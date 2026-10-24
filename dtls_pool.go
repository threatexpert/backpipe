package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/threatexpert/gonc/v2/secure"
)

const (
	dtlsHandshakeTimeout = 20 * time.Second
	dtlsMaxHandshakes    = 64
	dtlsMaxSessions      = 4096
)

// DTLS uses the same PSK-derived signing certificate and public-key check as
// gonc TLS. ECDHE provides fresh session keys and forward secrecy; this is not
// a TLS_PSK cipher suite. Disabling CA/hostname checks never disables our
// mandatory PSK public-key verification on either side.
func newDTLSPSKOptions(psk string, mtu int) ([]dtls.Option, error) {
	if psk == "" {
		return nil, fmt.Errorf("DTLS requires a nonempty PSK")
	}
	if mtu < minDatagramMTU || mtu > maxDatagramMTU {
		return nil, fmt.Errorf("DTLS MTU must be %d..%d", minDatagramMTU, maxDatagramMTU)
	}
	cert, err := secure.GenerateECDSACertificate("localhost", psk)
	if err != nil {
		return nil, fmt.Errorf("cannot create DTLS certificate")
	}
	return []dtls.Option{
		dtls.WithCertificates(*cert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(secure.VerifyPeerCertificateByPSK(psk)),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithMTU(mtu),
		dtls.WithReplayProtectionWindow(256),
	}, nil
}

func listenDTLSPool(ep endpoint, mtu int) (net.Listener, error) {
	opts, err := newDTLSPSKOptions(ep.psk, mtu)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", ep.address)
	if err != nil {
		return nil, err
	}
	serverOpts := make([]dtls.ServerOption, 0, len(opts)+1)
	for _, opt := range opts {
		serverOpts = append(serverOpts, opt)
	}
	serverOpts = append(serverOpts, dtls.WithClientAuth(dtls.RequireAnyClientCert))
	// Pion v3.1.10 implements DTLS 1.2. Keep its cookie exchange enabled and
	// connection IDs disabled: a NAT address change must establish a new session.
	packets, err := newDTLSPacketListener(addr)
	if err != nil {
		return nil, err
	}
	ln, err := dtls.NewListenerWithOptions(packets, serverOpts...)
	if err != nil {
		packets.Close()
		return nil, err
	}
	return &dtlsPoolListener{Listener: ln, packets: packets}, nil
}

// datagramPool only contains authenticated, bidirectionally ready sessions.
// Claiming removes a session from the idle queue; the caller performs OPEN.
// Claimed sessions are still owned here so shutdown also closes active traffic.
type datagramPool struct {
	mu      sync.Mutex
	entries []*datagramSession
	owned   map[*datagramSession]struct{}
	avail   chan struct{}
	done    chan struct{}
	closed  bool
}

func newDatagramPool() *datagramPool {
	return &datagramPool{
		owned: make(map[*datagramSession]struct{}),
		avail: make(chan struct{}, 1024),
		done:  make(chan struct{}),
	}
}

func (p *datagramPool) add(s *datagramSession) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		s.Close()
		return
	}
	if _, exists := p.owned[s]; exists {
		p.mu.Unlock()
		return
	}
	p.entries = append(p.entries, s)
	p.owned[s] = struct{}{}
	p.mu.Unlock()
	select {
	case p.avail <- struct{}{}:
	default:
	}
	go func() {
		<-s.Done()
		p.mu.Lock()
		delete(p.owned, s)
		for i, entry := range p.entries {
			if entry == s {
				copy(p.entries[i:], p.entries[i+1:])
				p.entries[len(p.entries)-1] = nil
				p.entries = p.entries[:len(p.entries)-1]
				break
			}
		}
		p.mu.Unlock()
	}()
}

func (p *datagramPool) tryClaim() *datagramSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	for !p.closed && len(p.entries) > 0 {
		s := p.entries[0]
		p.entries[0] = nil
		p.entries = p.entries[1:]
		select {
		case <-s.Done():
			continue
		default:
			return s
		}
	}
	return nil
}

func (p *datagramPool) pick(timeout time.Duration) *datagramSession {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if s := p.tryClaim(); s != nil {
			return s
		}
		select {
		case <-p.avail:
		case <-p.done:
			return nil
		case <-timer.C:
			return nil
		}
	}
}

func (p *datagramPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.entries {
		select {
		case <-s.Done():
		default:
			n++
		}
	}
	return n
}

func (p *datagramPool) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.done)
	sessions := make([]*datagramSession, 0, len(p.owned))
	for s := range p.owned {
		sessions = append(sessions, s)
	}
	p.entries = nil
	clear(p.owned)
	p.mu.Unlock()
	for _, s := range sessions {
		s.Close()
	}
}

// Track handshaking, idle and active sockets independently of the idle pool.
// register and closeAll serialize so cancellation cannot leak a late dial.
type dtlsConnSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func (s *dtlsConnSet) register(c net.Conn, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (limit > 0 && len(s.conns) >= limit) {
		return false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *dtlsConnSet) remove(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *dtlsConnSet) closeAll() {
	s.mu.Lock()
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	clear(s.conns)
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func acceptDTLSPoolConns(ctx context.Context, ln net.Listener, pool *datagramPool, whitelist map[string]bool, mtu int) error {
	if bounded, ok := ln.(*dtlsPoolListener); ok {
		bounded.packets.setWhitelist(whitelist)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var sockets dtlsConnSet
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() {
		ln.Close()
		sockets.closeAll()
	})
	defer func() {
		cancel()
		stop()
		ln.Close()
		sockets.closeAll()
		workers.Wait()
	}()
	sem := make(chan struct{}, dtlsMaxHandshakes)
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Pion Accept only creates a connection. No handshake or certificate
		// work has started, so apply the whitelist before doing that work.
		if !checkWhitelist(raw, whitelist) {
			raw.Close()
			continue
		}
		conn, ok := raw.(*dtls.Conn)
		if !ok {
			raw.Close()
			return fmt.Errorf("DTLS listener returned an unexpected connection")
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !sockets.register(conn, dtlsMaxSessions) {
			<-sem
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer sockets.remove(conn)
			defer conn.Close()
			hsCtx, hsCancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
			err := conn.HandshakeContext(hsCtx)
			hsCancel()
			if err != nil {
				<-sem
				if ctx.Err() == nil {
					log.Printf("[server] agent DTLS handshake failed: %s: %v", conn.RemoteAddr(), err)
				}
				return
			}
			session := newDatagramSession(conn, datagramSessionConfig{Server: true, MTU: mtu})
			defer session.Close()
			readyCtx, readyCancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
			err = session.WaitReady(readyCtx)
			readyCancel()
			<-sem
			if err != nil {
				return
			}
			pool.add(session)
			log.Printf("[server] UDP agent session pooled: %s (DTLS 1.2, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)", conn.RemoteAddr())
			select {
			case <-session.Done():
			case <-ctx.Done():
			}
		}()
	}
}

func dialDTLSPool(ctx context.Context, address string, options []dtls.Option) (*dtls.Conn, error) {
	// A connected UDP socket filters packets from other addresses. Each call
	// gets its own local port; sessions never migrate or share a UDP socket.
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	if udp, ok := raw.(*net.UDPConn); ok {
		_ = udp.SetReadBuffer(dtlsSocketReadBuffer)
	}
	clientOptions := make([]dtls.ClientOption, 0, len(options))
	for _, opt := range options {
		clientOptions = append(clientOptions, opt)
	}
	conn, err := dtls.ClientWithOptions(dtlsnet.PacketConnFromConn(raw), raw.RemoteAddr(), clientOptions...)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func dtlsRetryWait(ctx context.Context, attempt int) bool {
	// Full attempts grow exponentially, with jitter to avoid synchronized
	// reconnections when an entire idle pool loses its NAT mapping at once.
	if attempt > 5 {
		attempt = 5
	}
	delay := time.Second * time.Duration(1<<attempt)
	delay = time.Duration(float64(delay) * (0.75 + rand.Float64()*0.5))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func runDTLSAgent(ctx context.Context, ep endpoint, poolSize, mtu int, idle time.Duration, redirects redirectRules) error {
	if poolSize < 1 {
		return fmt.Errorf("UDP pool size must be positive")
	}
	opts, err := newDTLSPSKOptions(ep.psk, mtu)
	if err != nil {
		return err
	}
	var sockets dtlsConnSet
	var workers, sessions sync.WaitGroup
	stop := context.AfterFunc(ctx, sockets.closeAll)
	defer stop()
	for i := 0; i < poolSize; i++ {
		workers.Add(1)
		go func(slot int) {
			defer workers.Done()
			attempt := 0
			for ctx.Err() == nil {
				hsCtx, cancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
				conn, err := dialDTLSPool(hsCtx, ep.address, opts)
				cancel()
				if err != nil {
					if ctx.Err() == nil {
						log.Printf("[agent-udp-%d] DTLS connect failed: %v", slot, err)
					}
					if !dtlsRetryWait(ctx, attempt) {
						return
					}
					attempt++
					continue
				}
				if !sockets.register(conn, 0) {
					conn.Close()
					return
				}
				session := newDatagramSession(conn, datagramSessionConfig{
					MTU: mtu,
					Prepare: func(s *datagramSession) (func(), error) {
						udp, err := net.ListenUDP("udp", nil)
						if err != nil {
							return nil, err
						}
						configureBusinessUDPReadBuffer(udp, "agent")
						// Also covers a failed OPEN_ACK, when the prepared forwarder
						// is never started by the session state machine.
						go func() {
							<-s.Done()
							udp.Close()
						}()
						return func() {
							defer udp.Close()
							defer s.Close()
							serveUDPExit(s, udp, idle, redirects)
						}, nil
					},
				})
				sessions.Add(1)
				go func() {
					defer sessions.Done()
					<-session.Done()
					sockets.remove(conn)
					conn.Close()
				}()
				readyCtx, readyCancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
				err = session.WaitReady(readyCtx)
				readyCancel()
				if err != nil {
					session.Close()
					if !dtlsRetryWait(ctx, attempt) {
						return
					}
					attempt++
					continue
				}
				attempt = 0
				log.Printf("[agent-udp-%d] idle UDP session ready (DTLS 1.2, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)", slot)
				select {
				case <-session.Activated():
					// Replenish immediately. The activated session owns its exit
					// socket and continues forwarding independently of this slot.
					continue
				case <-session.Done():
					if !dtlsRetryWait(ctx, 0) {
						return
					}
				case <-ctx.Done():
					session.Close()
					return
				}
			}
		}(i + 1)
	}
	workers.Wait()
	sockets.closeAll()
	sessions.Wait()
	return nil
}
