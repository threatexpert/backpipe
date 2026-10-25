package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "v1.4.2"

func main() {
	if err := runCLI(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// parseWhitelist parses comma-separated IP whitelist
func parseWhitelist(s string) map[string]bool {
	m := make(map[string]bool)
	if s == "" {
		return m
	}
	for _, ip := range strings.Split(s, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			m[ip] = true
			log.Printf("[server] whitelisted IP: %s", ip)
		}
	}
	return m
}

// checkWhitelist returns true if conn IP is whitelisted or whitelist is empty
func checkWhitelist(c net.Conn, whitelist map[string]bool) bool {
	if len(whitelist) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	return whitelist[host]
}

// ======================== PROXY protocol v2 ========================

var proxyV2Magic = [12]byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
	0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

// writeProxyV2 writes a PROXY protocol v2 header to dst, carrying the
// client's real src address and the server's local dst address.
// The header is prepended to the relay stream so the final target can
// recover the original client IP/port.
func writeProxyV2(dst net.Conn, src, local net.Addr) error {
	srcTCP, ok1 := src.(*net.TCPAddr)
	localTCP, ok2 := local.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return fmt.Errorf("ppv2: non-TCP addresses")
	}

	var buf [16 + 36]byte // worst case: fixed header(16) + IPv6 addrs(36)
	copy(buf[:12], proxyV2Magic[:])
	buf[12] = 0x21 // version=2, command=PROXY

	srcIP4 := srcTCP.IP.To4()
	localIP4 := localTCP.IP.To4()

	var n int
	if srcIP4 != nil && localIP4 != nil {
		buf[13] = 0x11 // family=INET, proto=STREAM
		binary.BigEndian.PutUint16(buf[14:16], 12)
		copy(buf[16:20], srcIP4)
		copy(buf[20:24], localIP4)
		binary.BigEndian.PutUint16(buf[24:26], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(buf[26:28], uint16(localTCP.Port))
		n = 28
	} else {
		srcIP6 := srcTCP.IP.To16()
		localIP6 := localTCP.IP.To16()
		if srcIP6 == nil || localIP6 == nil {
			return fmt.Errorf("ppv2: cannot resolve IP to IPv6")
		}
		buf[13] = 0x21 // family=INET6, proto=STREAM
		binary.BigEndian.PutUint16(buf[14:16], 36)
		copy(buf[16:32], srcIP6)
		copy(buf[32:48], localIP6)
		binary.BigEndian.PutUint16(buf[48:50], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(buf[50:52], uint16(localTCP.Port))
		n = 52
	}

	_, err := dst.Write(buf[:n])
	return err
}

// ======================== server mode ========================

// poolEntry represents an idle agent connection in the pool
type poolEntry struct {
	conn   net.Conn
	dead   int32         // atomic: 1 = dead
	cancel chan struct{} // close to stop monitor and claim connection
	done   chan struct{} // monitor has stopped reading and reset its deadline
}

// connPool manages idle agent connections with liveness monitoring
type connPool struct {
	mu      sync.Mutex
	entries []*poolEntry
	avail   chan struct{} // signaled when a new connection is available
	closed  bool
}

func newConnPool() *connPool {
	return &connPool{
		avail: make(chan struct{}, 1024),
	}
}

func (p *connPool) add(c net.Conn) {
	e := &poolEntry{
		conn:   c,
		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		c.Close()
		return
	}
	p.entries = append(p.entries, e)
	p.mu.Unlock()

	go p.monitor(e)

	select {
	case p.avail <- struct{}{}:
	default:
	}
}

// monitor blocks on Read. Agent never sends data on idle connections,
// so Read only returns when the connection dies.
// When the connection is claimed (cancel closed), we interrupt the Read
// via SetReadDeadline, wait for it to exit, then reset the deadline.
func (p *connPool) monitor(e *poolEntry) {
	defer close(e.done)
	readDone := make(chan struct{})
	var readErr error
	var readN int
	go func() {
		buf := make([]byte, 1)
		readN, readErr = e.conn.Read(buf)
		close(readDone)
	}()

	select {
	case <-readDone:
		// connection died while idle
		atomic.StoreInt32(&e.dead, 1)
		log.Printf("[server] idle agent connection lost: %s", e.conn.RemoteAddr())
		e.conn.Close()
		p.removeEntry(e)
	case <-e.cancel:
		// claimed for relay — interrupt the blocking Read, then reset
		e.conn.SetReadDeadline(time.Now())
		<-readDone
		e.conn.SetReadDeadline(time.Time{})
		// Only the timeout used to interrupt the idle read is expected.
		// EOF, unsolicited bytes, and other errors make this connection unusable.
		if ne, ok := readErr.(net.Error); readN != 0 || !ok || !ne.Timeout() {
			atomic.StoreInt32(&e.dead, 1)
			e.conn.Close()
		}
	}
}

func (p *connPool) removeEntry(target *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e == target {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			return
		}
	}
}

// pick returns a live idle connection, waiting up to timeout.
func (p *connPool) pick(timeout time.Duration) net.Conn {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if c := p.tryClaim(); c != nil {
			return c
		}
		select {
		case <-p.avail:
		case <-deadline.C:
			return nil
		}
	}
}

// tryClaim finds the first live entry, removes it, and stops its monitor.
func (p *connPool) tryClaim() net.Conn {
	for {
		p.mu.Lock()
		var claimed *poolEntry
		for i, e := range p.entries {
			if atomic.LoadInt32(&e.dead) == 0 {
				p.entries = append(p.entries[:i], p.entries[i+1:]...)
				close(e.cancel)
				claimed = e
				break
			}
		}
		p.mu.Unlock()
		if claimed == nil {
			return nil
		}
		// Do not hold the pool lock: a concurrent disconnect may need it
		// to remove the entry before the monitor can finish.
		<-claimed.done
		if atomic.LoadInt32(&claimed.dead) == 0 {
			return claimed.conn
		}
	}
}

// size returns the number of live idle connections
func (p *connPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.entries {
		if atomic.LoadInt32(&e.dead) == 0 {
			n++
		}
	}
	return n
}

func (p *connPool) close() {
	p.mu.Lock()
	p.closed = true
	entries := p.entries
	p.entries = nil
	p.mu.Unlock()
	for _, e := range entries {
		e.conn.Close()
	}
}

var relayCount int64 // atomic: active relay sessions

// A client entry binds one transport; UDP has no Accept operation.
type serverListener struct {
	tcp net.Listener
	udp *net.UDPConn
}

func (ln serverListener) Addr() net.Addr {
	if ln.udp != nil {
		return ln.udp.LocalAddr()
	}
	return ln.tcp.Addr()
}

func (ln serverListener) Close() error {
	if ln.udp != nil {
		return ln.udp.Close()
	}
	return ln.tcp.Close()
}

// Bind every port before starting any accept loop. On failure, release all
// successfully bound ports so startup cannot leave a partially serving server.
func bindServerListeners(entries []entryConfig, poolAddr string) (net.Listener, []serverListener, error) {
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("at least one client entry is required")
	}
	poolLn, err := net.Listen("tcp", poolAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("agent pool listen on %s: %w", poolAddr, err)
	}
	listeners, err := bindClientListeners(entries)
	if err != nil {
		poolLn.Close()
		return nil, nil, err
	}
	return poolLn, listeners, nil
}

func bindClientListeners(entries []entryConfig) ([]serverListener, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one client entry is required")
	}
	var listeners []serverListener
	for i, entry := range entries {
		var ln serverListener
		var err error
		if entry.endpoint.scheme == "udp" {
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp", entry.endpoint.address)
			if err == nil {
				ln.udp, err = net.ListenUDP("udp", addr)
			}
		} else {
			ln.tcp, err = net.Listen("tcp", entry.endpoint.address)
		}
		if err != nil {
			for _, bound := range listeners {
				bound.Close()
			}
			return nil, fmt.Errorf("entry %d (%s) listen on %s: %w", i+1, entry.endpoint.scheme, entry.endpoint.address, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

func acceptUserConns(ln net.Listener, pool *connPool, ppv2 bool, entry entryConfig) error {
	for {
		uc, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("[server] client listener %s stopped: %w", ln.Addr(), err)
		}
		log.Printf("[server] user connected: %s via %s", uc.RemoteAddr(), ln.Addr())
		if entry.endpoint.target != "" {
			go serveTCPForward(uc, pool, entry.endpoint.target, entry.proxy)
		} else if entry.proxy != nil {
			go serveProxyClient(uc, pool, entry.proxy)
		} else {
			go handleUserConn(uc, pool, ppv2)
		}
	}
}

func acceptPoolConns(ln net.Listener, pool *connPool, whitelist map[string]bool, tlsConf *tlsPSKConfig) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[server] pool accept error: %v", err)
			continue
		}

		if !checkWhitelist(c, whitelist) {
			log.Printf("[server] rejected non-whitelisted IP: %s", c.RemoteAddr())
			c.Close()
			continue
		}

		setKeepalive(c)

		go func(raw net.Conn) {
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			var conn net.Conn = raw
			if tlsConf != nil {
				tlsConn, err := negotiateTLSPSK(tlsConf, raw)
				if err != nil {
					log.Printf("[server] TLS handshake failed from %s: %v", raw.RemoteAddr(), err)
					raw.Close()
					return
				}
				log.Printf("[server] agent TLS negotiated: %s (%s)", raw.RemoteAddr(), tlsConn.description())
				conn = tlsConn
			}
			conn.SetDeadline(time.Time{})
			log.Printf("[server] agent connection pooled: %s", conn.RemoteAddr())
			pool.add(conn)
		}(c)
	}
}

func handleUserConn(userConn net.Conn, pool *connPool, ppv2 bool) {
	clientAddr := userConn.RemoteAddr()

	agentConn := pool.pick(30 * time.Second)
	if agentConn == nil {
		log.Printf("[server] no agent connection available, dropping user: %s", clientAddr)
		userConn.Close()
		return
	}

	if ppv2 {
		if err := writeProxyV2(agentConn, userConn.RemoteAddr(), userConn.LocalAddr()); err != nil {
			log.Printf("[server] ppv2 write failed for %s: %v", clientAddr, err)
			userConn.Close()
			agentConn.Close()
			return
		}
	}

	atomic.AddInt64(&relayCount, 1)
	log.Printf("[server] relay started: %s <-> %s", clientAddr, agentConn.RemoteAddr())
	relay(userConn, agentConn)
	atomic.AddInt64(&relayCount, -1)
	log.Printf("[server] relay ended: %s", clientAddr)
}

// ======================== agent mode ========================

var agentConnID uint64
var agentConnIDMu sync.Mutex

func nextAgentConnID() uint64 {
	agentConnIDMu.Lock()
	defer agentConnIDMu.Unlock()
	agentConnID++
	return agentConnID
}

func runAgent(serverAddr, targetAddr string, poolSize int, proto, psk string, proxy *proxyOptions, redirects redirectRules) {
	var tlsConf *tlsPSKConfig
	if proto == "tls" {
		var err error
		tlsConf, err = newTLSPSKConfig(psk, true)
		if err != nil {
			log.Fatalf("[agent] failed to init TLS: %v", err)
		}
		log.Printf("[agent] TLS 1.2-1.3 enabled with PSK mutual authentication")
	}

	if proxy != nil {
		log.Printf("[agent] server: %s, mode: SOCKS5 TCP/UDP + HTTP + fixed TCP/UDP forwarding, idle pool: %d", serverAddr, poolSize)
	} else {
		log.Printf("[agent] server: %s, target: %s, idle pool: %d", serverAddr, targetAddr, poolSize)
	}

	// spawn channel: each signal means "create one more idle connection"
	spawn := make(chan struct{}, poolSize*2)

	// seed initial pool
	for i := 0; i < poolSize; i++ {
		spawn <- struct{}{}
	}

	for range spawn {
		go agentWorker(serverAddr, targetAddr, spawn, tlsConf, proxy, redirects)
	}
}

func agentWorker(serverAddr, targetAddr string, spawn chan<- struct{}, tlsConf *tlsPSKConfig, proxy *proxyOptions, redirects redirectRules) {
	id := nextAgentConnID()

	respawn := func(delay time.Duration) {
		if delay > 0 {
			time.Sleep(delay)
		}
		spawn <- struct{}{}
	}

	// pre-establish connection to server
	rawConn := dialRetry(serverAddr, id)
	rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	var serverConn net.Conn
	if tlsConf != nil {
		tlsConn, err := negotiateTLSPSK(tlsConf, rawConn)
		if err != nil {
			log.Printf("[agent-%d] TLS handshake failed: %v", id, err)
			rawConn.Close()
			go respawn(5 * time.Second)
			return
		}
		serverConn = tlsConn
		log.Printf("[agent-%d] idle connection ready (%s)", id, tlsConn.description())
	} else {
		serverConn = rawConn
		log.Printf("[agent-%d] idle connection ready", id)
	}
	serverConn.SetDeadline(time.Time{})

	// block until server sends data (user connected)
	buf := make([]byte, 32*1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		log.Printf("[agent-%d] idle connection lost: %v", id, err)
		serverConn.Close()
		go respawn(time.Second)
		return
	}

	// connection claimed — immediately replenish idle pool
	spawn <- struct{}{}
	if proxy != nil {
		// Replay the activation read: it may contain a partial request line,
		// a complete request, or request and payload in the same TCP segment.
		conn := &readerConn{Conn: serverConn, reader: io.MultiReader(bytes.NewReader(buf[:n]), serverConn)}
		serveProxyTunnel(conn, proxy, redirects)
		return
	}

	targetAddr = redirects.rewrite("tcp", targetAddr)
	log.Printf("[agent-%d] received %d bytes, connecting target: %s", id, n, targetAddr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[agent-%d] failed to connect target %s: %v", id, targetAddr, err)
		serverConn.Close()
		return
	}
	setKeepalive(targetConn)

	// write first chunk to target
	if _, err := targetConn.Write(buf[:n]); err != nil {
		log.Printf("[agent-%d] failed to write to target: %v", id, err)
		serverConn.Close()
		targetConn.Close()
		return
	}

	log.Printf("[agent-%d] relay started: server <-> %s", id, targetAddr)
	relay(serverConn, targetConn)
	log.Printf("[agent-%d] relay ended", id)
}

func dialRetry(addr string, id uint64) net.Conn {
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err == nil {
			setKeepalive(c)
			return c
		}
		log.Printf("[agent-%d] connect to server failed: %v, retry in %v", id, err, backoff)
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// ======================== common ========================

func relay(c1, c2 net.Conn) {
	done := make(chan struct{}, 2)

	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}

	go pipe(c1, c2)
	go pipe(c2, c1)

	<-done // first direction finished

	// give the other direction up to 30s to finish
	c1.SetReadDeadline(time.Now().Add(30 * time.Second))
	c2.SetReadDeadline(time.Now().Add(30 * time.Second))

	<-done // second direction finished

	c1.Close()
	c2.Close()
}

func setKeepalive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}
