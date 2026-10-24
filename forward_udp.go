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
)

// UDP has no accept/backpressure mechanism. Bound both sessions waiting for an
// agent and queued datagrams so an unavailable or slow agent cannot grow memory
// without limit. Limits apply independently to each forwarding listener.
const (
	udpForwardMaxPending         = 128
	udpForwardMaxSessions        = 1024
	udpForwardQueuePackets       = 256
	udpForwardSessionQueuedBytes = 256 * 1024
	udpForwardMaxQueuedBytes     = 8 * 1024 * 1024
)

type udpForwarder struct {
	udp     *net.UDPConn
	pool    *connPool
	target  string
	header  []byte
	options *proxyOptions
	ctx     context.Context
	writes  chan struct{} // serialize shared-socket writes and their deadlines

	mu         sync.Mutex
	sessions   map[string]*udpForwardSession
	pending    int
	queueStats udpForwardQueueStats
	drops      udpForwardDrops
	lastReport udpForwardSnapshot
	wg         sync.WaitGroup
}

type udpForwardSession struct {
	owner          *udpForwarder
	peer           *net.UDPAddr
	key            string
	packets        chan []byte
	ctx            context.Context
	cancel         context.CancelFunc
	pending        bool                 // protected by owner.mu
	queueStats     udpForwardQueueStats // protected by owner.mu
	drops          udpForwardDrops      // protected by owner.mu
	sent, received int64                // one writer per direction; read after both loops end

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
	configureBusinessUDPReadBuffer(udp, "server")
	ctx, cancel := context.WithCancel(context.Background())
	f := &udpForwarder{
		udp: udp, pool: pool, target: target, header: header, options: options,
		ctx: ctx, writes: make(chan struct{}, 1), sessions: make(map[string]*udpForwardSession),
	}
	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		f.reportLoop()
	}()
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
		<-statsDone
		f.reportStats(true)
	}()
	buf := make([]byte, 65535)
	for {
		n, peer, err := udp.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("[server] UDP listener %s stopped: %w", udp.LocalAddr(), err)
		}
		f.enqueue(peer, buf[:n])
	}
}

func (f *udpForwarder) enqueue(peer *net.UDPAddr, payload []byte) {
	key := peer.String()
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[key]
	if f.ctx.Err() != nil || (s != nil && s.ctx.Err() != nil) {
		f.dropLocked(s, udpDropClosing, 1)
		return
	}
	// The tunnel's 16-bit length includes the logical destination header.
	if len(payload)+len(f.header) > 65535 {
		f.dropLocked(s, udpDropOversize, 1)
		return
	}
	if f.queueStats.bytes+len(payload) > udpForwardMaxQueuedBytes {
		f.dropLocked(s, udpDropListenerBytes, 1)
		return
	}
	if s == nil {
		if f.pending >= udpForwardMaxPending {
			f.dropLocked(nil, udpDropPendingLimit, 1)
			return
		}
		if len(f.sessions) >= udpForwardMaxSessions {
			f.dropLocked(nil, udpDropSessionLimit, 1)
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
	if s.queueStats.packets >= udpForwardQueuePackets {
		f.dropLocked(s, udpDropQueuePackets, 1)
		return
	}
	if s.queueStats.bytes+len(payload) > udpForwardSessionQueuedBytes {
		f.dropLocked(s, udpDropSessionBytes, 1)
		return
	}
	packet := append([]byte(nil), payload...)
	f.queueStats.add(len(packet))
	s.queueStats.add(len(packet))
	s.packets <- packet
}

func (s *udpForwardSession) dequeue(payload []byte) {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.releaseQueuedLocked(payload)
}

func (s *udpForwardSession) releaseQueuedLocked(payload []byte) {
	s.queueStats.packets--
	s.queueStats.bytes -= len(payload)
	s.owner.queueStats.packets--
	s.owner.queueStats.bytes -= len(payload)
}

// Called after the forwarding loops have joined. The waiting queue budget does
// not include the one in-flight datagram or its encoded tunnel frame.
func (s *udpForwardSession) cleanup() {
	s.stop()
	f := s.owner
	f.mu.Lock()
	delete(f.sessions, s.key)
	if s.pending {
		f.pending--
		s.pending = false
	}
	for len(s.packets) > 0 {
		payload := <-s.packets
		s.releaseQueuedLocked(payload)
		f.dropLocked(s, udpDropAbandoned, 1)
	}
	drops, queue := s.drops, s.queueStats
	f.mu.Unlock()
	log.Printf("[server] UDP forward ended: %s via %s (sent=%d received=%d packets dropped=%d queue_peak_packets=%d queue_peak_bytes=%d)", s.peer, f.udp.LocalAddr(), s.sent, s.received, drops.total(), queue.peakPackets, queue.peakBytes)
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
	defer s.cleanup()
	tunnel := selectUDPTunnel(s.ctx, f.pool, f.options)
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
	if err := openUDPTunnel(s.ctx, tunnel); err != nil {
		log.Printf("[server] UDP forward tunnel setup failed: %s via %s", s.peer, f.udp.LocalAddr())
		return
	}
	f.mu.Lock()
	s.pending = false
	f.pending--
	f.mu.Unlock()
	s.refresh()
	log.Printf("[server] UDP forward: %s via %s -> %s (transport=%s)", s.peer, f.udp.LocalAddr(), f.target, udpTransportName(tunnel))
	runUDPLoops(s.stop, func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case payload := <-s.packets:
				s.dequeue(payload)
				if s.ctx.Err() != nil {
					f.recordDrop(s, udpDropAbandoned)
					return
				}
				packet := make([]byte, 0, len(f.header)+len(payload))
				packet = append(packet, f.header...)
				packet = append(packet, payload...)
				s.refresh()
				if err := writeUDPFrame(tunnel, packet); err != nil {
					f.recordDrop(s, udpDropWriteError)
					return
				}
				s.sent++
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
				f.recordDrop(s, udpDropWriteError)
				return
			}
			s.received++
		}
	})
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
