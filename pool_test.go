package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type gatedReadConn struct {
	net.Conn
	returned chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (c *gatedReadConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.once.Do(func() {
		close(c.returned)
		<-c.release
	})
	return n, err
}

func TestPoolClaimWaitsForIdleReader(t *testing.T) {
	s, peer := net.Pipe()
	defer s.Close()
	defer peer.Close()
	c := &gatedReadConn{Conn: s, returned: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(c.release) }) }
	defer release()
	p := newConnPool()
	p.add(c)
	claimed := make(chan net.Conn, 1)
	go func() { claimed <- p.pick(time.Second) }()
	select {
	case <-c.returned:
	case <-time.After(time.Second):
		t.Fatal("idle read was not interrupted")
	}
	select {
	case <-claimed:
		t.Fatal("connection escaped before its idle reader exited")
	default:
	}
	release()
	var conn net.Conn
	select {
	case conn = <-claimed:
	case <-time.After(time.Second):
		t.Fatal("claim did not finish")
	}
	if conn == nil {
		t.Fatal("live connection was dropped")
	}
	go peer.Write([]byte("first-response"))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, len("first-response"))
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "first-response" {
		t.Fatalf("first response was consumed by idle monitor: %q, %v", b, err)
	}
}

func TestPoolWaitersAndDisconnectedEntries(t *testing.T) {
	p := newConnPool()
	s, peer := net.Pipe()
	p.add(s)
	peer.Close()
	await(t, func() bool { return p.size() == 0 }, func() string { return "dead entry still in pool" })
	const count = 12
	results := make(chan net.Conn, count)
	for i := 0; i < count; i++ {
		go func() { results <- p.pick(2 * time.Second) }()
	}
	for i := 0; i < count; i++ {
		s, peer := net.Pipe()
		t.Cleanup(func() { s.Close(); peer.Close() })
		p.add(s)
	}
	seen := make(map[net.Conn]bool)
	for i := 0; i < count; i++ {
		c := <-results
		if c == nil || seen[c] {
			t.Fatal("waiters did not get distinct live connections")
		}
		seen[c] = true
		c.Close()
	}
	if p.pick(20*time.Millisecond) != nil {
		t.Fatal("empty pool returned a connection")
	}
}

func TestUDPTunnelPartialFrameTimesOutAndReturns(t *testing.T) {
	s, peer, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer peer.Close()
	done := make(chan struct{})
	go func() { serveUDPTunnel(s, 100*time.Millisecond); close(done) }()
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	expectBytes(t, peer, []byte("OK\n"))
	peer.Write([]byte{0}) // Half a frame header; the other byte never arrives.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP tunnel leaked after partial frame timeout")
	}
}

func TestSOCKSRequestFailsWhenPoolIsEmpty(t *testing.T) {
	s, peer, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer peer.Close()
	opts, err := newProxyOptions("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	opts.poolWait = 30 * time.Millisecond
	done := make(chan struct{})
	go func() { serveProxyClient(s, newConnPool(), opts); close(done) }()
	peer.SetDeadline(time.Now().Add(time.Second))
	clientAuth(t, peer, "")
	clientRequest(t, peer, 3, "0.0.0.0:0", false)
	clientReply(t, peer, 1) // Never announce successful UDP association without an agent.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("empty pool request did not finish")
	}
}

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
