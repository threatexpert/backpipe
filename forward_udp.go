package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// UDP has no accept/backpressure mechanism. Bound both sessions waiting for an
// agent and queued datagrams so an unavailable or slow agent cannot grow memory
// without limit. Limits apply independently to each forwarding listener.
const (
	udpForwardMaxPending     = 128
	udpForwardMaxSessions    = 1024
	udpForwardQueuePackets   = 16
	udpForwardMaxQueuedBytes = 8 * 1024 * 1024
)

type udpForwarder struct {
	udp     *net.UDPConn
	pool    *connPool
	target  string
	header  []byte
	options *proxyOptions
	ctx     context.Context
	writes  chan struct{} // serialize shared-socket writes and their deadlines

	mu          sync.Mutex
	sessions    map[string]*udpForwardSession
	pending     int
	queuedBytes int
	wg          sync.WaitGroup
}

type udpForwardSession struct {
	owner   *udpForwarder
	peer    *net.UDPAddr
	key     string
	packets chan []byte
	ctx     context.Context
	cancel  context.CancelFunc
	pending bool // protected by owner.mu

	connMu    sync.Mutex
	tunnel    net.Conn
	refreshMu sync.Mutex
}

// udpForwardHeader preserves a logical destination for agent-side redirect and
// DNS resolution; the server must never resolve this host itself.
func udpForwardHeader(target string) ([]byte, error) {
	address, err := normalizeRedirectAddress(target)
	if err != nil {
		return nil, err
	}
	host, portString, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portString)
	if ip := net.ParseIP(host); ip != nil {
		return appendSOCKSAddress([]byte{0, 0, 0}, &net.UDPAddr{IP: ip, Port: port}), nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("UDP target hostname exceeds 255 bytes")
	}
	header := append([]byte{0, 0, 0, 3, byte(len(host))}, host...)
	return append(header, byte(port>>8), byte(port)), nil
}

// serveUDPForward accepts ordinary datagrams, using one pool connection per
// client endpoint. The shared UDP socket has no read deadline: each session's
// tunnel owns its idle timeout and closing one session leaves others live.
func serveUDPForward(udp *net.UDPConn, pool *connPool, target string, options *proxyOptions) error {
	header, err := udpForwardHeader(target)
	if err != nil {
		return fmt.Errorf("[server] UDP forward target: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &udpForwarder{
		udp: udp, pool: pool, target: target, header: header, options: options,
		ctx: ctx, writes: make(chan struct{}, 1), sessions: make(map[string]*udpForwardSession),
	}
	defer func() {
		cancel()
		udp.Close()
		f.mu.Lock()
		remaining := make([]*udpForwardSession, 0, len(f.sessions))
		for _, s := range f.sessions {
			remaining = append(remaining, s)
		}
		f.mu.Unlock()
		for _, s := range remaining {
			s.stop()
		}
		f.wg.Wait()
	}()
	buf := make([]byte, 65535)
	for {
		n, peer, err := udp.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("[server] UDP listener %s stopped: %w", udp.LocalAddr(), err)
		}
		// The existing tunnel's 16-bit length includes the destination header.
		// Oversized datagrams are dropped without disturbing a live session.
		if n+len(header) > 65535 {
			continue
		}
		f.enqueue(peer, buf[:n])
	}
}

func (f *udpForwarder) enqueue(peer *net.UDPAddr, payload []byte) {
	key := peer.String()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queuedBytes+len(payload) > udpForwardMaxQueuedBytes {
		return
	}
	s := f.sessions[key]
	if s == nil {
		if f.pending >= udpForwardMaxPending || len(f.sessions) >= udpForwardMaxSessions {
			return
		}
		ctx, cancel := context.WithCancel(f.ctx)
		s = &udpForwardSession{
			owner: f, peer: peer, key: key, packets: make(chan []byte, udpForwardQueuePackets),
			ctx: ctx, cancel: cancel, pending: true,
		}
		f.sessions[key] = s
		f.pending++
		f.wg.Add(1)
		go s.run()
	}
	if s.ctx.Err() != nil || len(s.packets) == cap(s.packets) {
		return
	}
	packet := append([]byte(nil), payload...)
	f.queuedBytes += len(packet)
	s.packets <- packet
}

func (s *udpForwardSession) stop() {
	s.cancel()
	s.connMu.Lock()
	if s.tunnel != nil {
		s.tunnel.Close()
	}
	s.connMu.Unlock()
}

func (s *udpForwardSession) attach(tunnel net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.ctx.Err() != nil {
		tunnel.Close()
		return false
	}
	s.tunnel = tunnel
	return true
}

func (s *udpForwardSession) refresh() {
	// Compute and set under one lock so concurrent traffic cannot move an idle
	// deadline backwards. The listener's shared socket is deliberately untouched.
	s.refreshMu.Lock()
	s.tunnel.SetDeadline(time.Now().Add(s.owner.options.udpTimeout))
	s.refreshMu.Unlock()
}

func (s *udpForwardSession) writeReply(payload []byte) error {
	f := s.owner
	deadline := time.Now().Add(min(f.options.udpTimeout, 5*time.Second))
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	case f.writes <- struct{}{}:
	}
	defer func() { <-f.writes }()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	// A full OS send buffer must not keep a finished session alive forever.
	// Bound queueing and writing together: a tunnel deadline cannot wake a
	// goroutine waiting only on this channel. Only the token owner changes the
	// shared write deadline; reads and other sessions' timeouts stay independent.
	if err := f.udp.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := f.udp.WriteToUDP(payload, s.peer)
	return err
}

func (s *udpForwardSession) run() {
	f := s.owner
	defer f.wg.Done()
	defer func() {
		s.stop()
		f.mu.Lock()
		delete(f.sessions, s.key)
		if s.pending {
			f.pending--
		}
		for len(s.packets) > 0 {
			f.queuedBytes -= len(<-s.packets)
		}
		f.mu.Unlock()
	}()
	tunnel := pickUDPForwardTunnel(s.ctx, f.pool, f.options.poolWait)
	if tunnel == nil {
		if s.ctx.Err() == nil {
			log.Printf("[server] no agent connection available, dropping UDP forward: %s via %s", s.peer, f.udp.LocalAddr())
		}
		return
	}
	if !s.attach(tunnel) {
		return
	}
	atomic.AddInt64(&relayCount, 1)
	defer atomic.AddInt64(&relayCount, -1)
	tunnel.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeAll(tunnel, []byte("udp://0.0.0.0:0\n")); err != nil {
		return
	}
	response, err := netx.ReadString(tunnel, '\n', 1024)
	if err != nil || response != "OK\n" {
		log.Printf("[server] UDP forward tunnel setup failed: %s via %s", s.peer, f.udp.LocalAddr())
		return
	}
	f.mu.Lock()
	s.pending = false
	f.pending--
	f.mu.Unlock()
	s.refresh()
	var sent, received int64
	log.Printf("[server] UDP forward: %s via %s -> %s", s.peer, f.udp.LocalAddr(), f.target)
	runUDPLoops(s.stop, func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case payload := <-s.packets:
				f.mu.Lock()
				f.queuedBytes -= len(payload)
				f.mu.Unlock()
				packet := make([]byte, 0, len(f.header)+len(payload))
				packet = append(packet, f.header...)
				packet = append(packet, payload...)
				s.refresh()
				if err := writeUDPFrame(tunnel, packet); err != nil {
					return
				}
				sent++
			}
		}
	}, func() {
		buf := make([]byte, 65535)
		for {
			packet, err := readUDPFrame(tunnel, buf)
			if err != nil {
				return
			}
			_, _, payload, err := parseUDPPacket(packet)
			if err != nil {
				return
			}
			s.refresh()
			// The actual agent-side source stays in the internal frame. Raw UDP
			// clients receive only payload, from the original server listen port.
			if err := s.writeReply(payload); err != nil {
				return
			}
			received++
		}
	})
	log.Printf("[server] UDP forward ended: %s via %s (sent=%d received=%d packets)", s.peer, f.udp.LocalAddr(), sent, received)
}

// Unlike the TCP accept loop, one UDP reader serves every client. Pool waits
// happen in session goroutines and must end promptly when its listener closes.
func pickUDPForwardTunnel(ctx context.Context, pool *connPool, wait time.Duration) net.Conn {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if tunnel := pool.tryClaim(); tunnel != nil {
			if ctx.Err() != nil {
				tunnel.Close()
				return nil
			}
			return tunnel
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return nil
		case <-pool.avail:
		}
	}
}
