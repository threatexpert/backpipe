package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/misc"
)

const Version = "v1.0.1"

func main() {
	showVersion := flag.Bool("version", false, "show version and exit")
	mode := flag.String("mode", "", "run mode: server or agent")
	left := flag.String("left", "", "server: user listen addr; agent: server addr to connect")
	right := flag.String("right", "", "server: agent pool listen addr; agent: target addr")
	pool := flag.Int("pool", 5, "agent: number of pre-established connections")
	allow := flag.String("allow", "", "server: agent IP whitelist, comma separated (e.g. 1.2.3.4,5.6.7.8)")
	proto := flag.String("proto", "plain", "tunnel protocol: plain or tls")
	psk := flag.String("psk", "", "pre-shared key for TLS mutual authentication (required when -proto tls)")
	flag.Parse()

	if *showVersion {
		fmt.Println("backpipe", Version)
		os.Exit(0)
	}

	if *proto == "tls" && *psk == "" {
		log.Fatal("-psk is required when -proto tls")
	}

	switch *mode {
	case "server":
		if *left == "" || *right == "" {
			log.Fatal("server mode requires -left and -right")
		}
		whitelist := parseWhitelist(*allow)
		runServer(*left, *right, whitelist, *proto, *psk)
	case "agent":
		if *left == "" || *right == "" {
			log.Fatal("agent mode requires -left and -right")
		}
		runAgent(*left, *right, *pool, *proto, *psk)
	default:
		fmt.Fprintf(os.Stderr, "backpipe - reverse TCP tunnel relay\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  server (relay server, accepts user connections and assigns to agent):\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode server -left 0.0.0.0:10888 -right 0.0.0.0:10086 -allow 1.2.3.4\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode server -left 0.0.0.0:10888 -right 0.0.0.0:10086 -proto tls -psk mysecret\n\n")
		fmt.Fprintf(os.Stderr, "  agent (reverse connector, pre-establishes connections to server):\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode agent -left server_host:10086 -right 127.0.0.1:22 -pool 5\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode agent -left server_host:10086 -right 127.0.0.1:22 -pool 5 -proto tls -psk mysecret\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode agent -left server_host:10086 -right \":s5s\" -pool 5\n")
		fmt.Fprintf(os.Stderr, "    backpipe -mode agent -left server_host:10086 -right \":s5s -auth user:pass -http\" -pool 5\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
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

// ======================== TLS with PSK ========================

// deriveECDSAKey derives a deterministic ECDSA private key (P-256) from a PSK
func deriveECDSAKey(psk string) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()

	h := hmac.New(sha256.New, []byte(psk))
	h.Write([]byte("backpipe-ecdsa-psk-derive"))
	digest := h.Sum(nil)

	d := new(big.Int).SetBytes(digest)
	n := curve.Params().N
	// ensure d is in [1, n-1]
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return priv, nil
}

// generateSelfSignedCert creates a self-signed certificate from the PSK-derived key
func generateSelfSignedCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// verifyPeerByPSK returns a verification function that checks the peer certificate
// was derived from the same PSK
func verifyPeerByPSK(psk string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate provided")
		}

		peerCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse peer certificate: %w", err)
		}

		expectedKey, err := deriveECDSAKey(psk)
		if err != nil {
			return fmt.Errorf("failed to derive key from PSK: %w", err)
		}

		if !reflect.DeepEqual(peerCert.PublicKey, &expectedKey.PublicKey) {
			return fmt.Errorf("PSK mismatch: peer certificate not derived from same PSK")
		}

		return nil
	}
}

// newServerTLSConfig creates TLS config for the server (pool listener) side
func newServerTLSConfig(psk string) (*tls.Config, error) {
	key, err := deriveECDSAKey(psk)
	if err != nil {
		return nil, err
	}
	cert, err := generateSelfSignedCert(key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPeerByPSK(psk),
		InsecureSkipVerify:    true,
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
	}, nil
}

// newAgentTLSConfig creates TLS config for the agent (dialer) side
func newAgentTLSConfig(psk string) (*tls.Config, error) {
	key, err := deriveECDSAKey(psk)
	if err != nil {
		return nil, err
	}
	cert, err := generateSelfSignedCert(key)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerByPSK(psk),
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
	}, nil
}

// ======================== server mode ========================

// poolEntry represents an idle agent connection in the pool
type poolEntry struct {
	conn   net.Conn
	dead   int32         // atomic: 1 = dead
	cancel chan struct{} // close to stop monitor and claim connection
}

// connPool manages idle agent connections with liveness monitoring
type connPool struct {
	mu      sync.Mutex
	entries []*poolEntry
	avail   chan struct{} // signaled when a new connection is available
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
	}

	p.mu.Lock()
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
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		e.conn.Read(buf)
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
	deadline := time.After(timeout)
	for {
		if c := p.tryClaim(); c != nil {
			return c
		}
		select {
		case <-p.avail:
		case <-deadline:
			return nil
		}
	}
}

// tryClaim finds the first live entry, removes it, and stops its monitor.
func (p *connPool) tryClaim() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, e := range p.entries {
		if atomic.LoadInt32(&e.dead) == 0 {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			close(e.cancel) // stop monitor, resets deadline internally
			return e.conn
		}
	}
	return nil
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

var relayCount int64 // atomic: active relay sessions

func runServer(userAddr, poolAddr string, whitelist map[string]bool, proto, psk string) {
	pool := newConnPool()

	var tlsConf *tls.Config
	if proto == "tls" {
		var err error
		tlsConf, err = newServerTLSConfig(psk)
		if err != nil {
			log.Fatalf("[server] failed to init TLS: %v", err)
		}
		log.Printf("[server] TLS 1.3 enabled with PSK mutual authentication")
	}

	// listen for agent pre-established connections (right side)
	poolLn, err := net.Listen("tcp", poolAddr)
	if err != nil {
		log.Fatalf("[server] failed to listen on pool port %s: %v", poolAddr, err)
	}
	log.Printf("[server] waiting for agent connections on %s", poolAddr)

	go acceptPoolConns(poolLn, pool, whitelist, tlsConf)
	go statusTicker(pool)

	// listen for user connections (left side)
	userLn, err := net.Listen("tcp", userAddr)
	if err != nil {
		log.Fatalf("[server] failed to listen on user port %s: %v", userAddr, err)
	}
	log.Printf("[server] waiting for user connections on %s", userAddr)

	for {
		uc, err := userLn.Accept()
		if err != nil {
			log.Printf("[server] user accept error: %v", err)
			continue
		}
		log.Printf("[server] user connected: %s", uc.RemoteAddr())
		go handleUserConn(uc, pool)
	}
}

func acceptPoolConns(ln net.Listener, pool *connPool, whitelist map[string]bool, tlsConf *tls.Config) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("[server] pool accept error: %v", err)
			continue
		}

		if !checkWhitelist(c, whitelist) {
			log.Printf("[server] rejected non-whitelisted IP: %s", c.RemoteAddr())
			c.Close()
			continue
		}

		setKeepalive(c)

		if tlsConf != nil {
			go func(raw net.Conn) {
				tlsConn := tls.Server(raw, tlsConf)
				if err := tlsConn.Handshake(); err != nil {
					log.Printf("[server] TLS handshake failed from %s: %v", raw.RemoteAddr(), err)
					raw.Close()
					return
				}
				log.Printf("[server] agent connection pooled (TLS): %s", raw.RemoteAddr())
				pool.add(tlsConn)
			}(c)
		} else {
			log.Printf("[server] agent connection pooled: %s", c.RemoteAddr())
			pool.add(c)
		}
	}
}

func statusTicker(pool *connPool) {
	_idleOld := -1
	_relaysOld := -1
	_idle := 0
	_relays := 0
	for {
		time.Sleep(1 * time.Second)
		_idle = pool.size()
		_relays = int(atomic.LoadInt64(&relayCount))
		if _idle != _idleOld || _relays != _relaysOld {
			log.Printf("[server] status: idle=%d relays=%d", _idle, _relays)
			_idleOld = _idle
			_relaysOld = _relays
		}
	}
}

func handleUserConn(userConn net.Conn, pool *connPool) {
	agentConn := pool.pick(30 * time.Second)
	if agentConn == nil {
		log.Printf("[server] no agent connection available, dropping user: %s", userConn.RemoteAddr())
		userConn.Close()
		return
	}

	atomic.AddInt64(&relayCount, 1)
	log.Printf("[server] relay started: %s <-> %s", userConn.RemoteAddr(), agentConn.RemoteAddr())
	relay(userConn, agentConn)
	atomic.AddInt64(&relayCount, -1)
	log.Printf("[server] relay ended: %s", userConn.RemoteAddr())
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

func runAgent(serverAddr, targetAddr string, poolSize int, proto, psk string) {
	var tlsConf *tls.Config
	if proto == "tls" {
		var err error
		tlsConf, err = newAgentTLSConfig(psk)
		if err != nil {
			log.Fatalf("[agent] failed to init TLS: %v", err)
		}
		log.Printf("[agent] TLS 1.3 enabled with PSK mutual authentication")
	}

	// parse :s5s mode
	var s5sConf *apps.AppS5SConfig
	if strings.HasPrefix(targetAddr, ":s5s") {
		s5sArgs := strings.Fields(targetAddr)[1:] // args after ":s5s"
		var err error
		s5sConf, err = apps.AppS5SConfigByArgs(os.Stderr, s5sArgs)
		if err != nil {
			log.Fatalf("[agent] failed to parse :s5s config: %v", err)
		}
		log.Printf("[agent] :s5s mode enabled (built-in SOCKS5 proxy)")
	}

	log.Printf("[agent] server: %s, target: %s, idle pool: %d", serverAddr, targetAddr, poolSize)

	// spawn channel: each signal means "create one more idle connection"
	spawn := make(chan struct{}, poolSize*2)

	// seed initial pool
	for i := 0; i < poolSize; i++ {
		spawn <- struct{}{}
	}

	for range spawn {
		go agentWorker(serverAddr, targetAddr, spawn, tlsConf, s5sConf)
	}
}

func agentWorker(serverAddr, targetAddr string, spawn chan<- struct{}, tlsConf *tls.Config, s5sConf *apps.AppS5SConfig) {
	id := nextAgentConnID()

	respawn := func(delay time.Duration) {
		if delay > 0 {
			time.Sleep(delay)
		}
		spawn <- struct{}{}
	}

	// pre-establish connection to server
	rawConn := dialRetry(serverAddr, id)

	var serverConn net.Conn
	if tlsConf != nil {
		tlsConn := tls.Client(rawConn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[agent-%d] TLS handshake failed: %v", id, err)
			rawConn.Close()
			go respawn(5 * time.Second)
			return
		}
		serverConn = tlsConn
		log.Printf("[agent-%d] idle connection ready (TLS)", id)
	} else {
		serverConn = rawConn
		log.Printf("[agent-%d] idle connection ready", id)
	}

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

	log.Printf("[agent-%d] received %d bytes, connecting target: %s", id, n, targetAddr)

	var targetConn net.Conn
	if s5sConf != nil {
		// built-in :s5s mode — use local TCP pair (supports CloseWrite for half-close)
		c1, c2, err := tcpPipe()
		if err != nil {
			log.Printf("[agent-%d] failed to create tcp pipe: %v", id, err)
			serverConn.Close()
			return
		}
		go apps.App_s5s_main_withconfig(c2, [32]byte{}, s5sConf, misc.NewProgressStats(), misc.NewProgressStats())
		targetConn = c1
	} else {
		// normal mode — dial target address
		var err error
		targetConn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[agent-%d] failed to connect target %s: %v", id, targetAddr, err)
			serverConn.Close()
			return
		}
		setKeepalive(targetConn)
	}

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

// tcpPipe creates a pair of connected TCP connections via loopback.
// Unlike net.Pipe(), these support CloseWrite for proper half-close signaling.
func tcpPipe() (net.Conn, net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	var c1 net.Conn
	go func() {
		var err error
		c1, err = ln.Accept()
		errCh <- err
	}()

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	if err := <-errCh; err != nil {
		c2.Close()
		return nil, nil, err
	}

	return c1, c2, nil
}

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
