package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
)

// Run the real CLI in a child process so its listeners, reconnect workers and
// pool replenishment are exercised without leaving background goroutines here.
func TestBackpipeProcess(t *testing.T) {
	if os.Getenv("BACKPIPE_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

type processLog struct {
	sync.Mutex
	b bytes.Buffer
}

func (l *processLog) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.b.Write(p)
}
func (l *processLog) String() string {
	l.Lock()
	defer l.Unlock()
	return l.b.String()
}

type testProcess struct {
	cmd  *exec.Cmd
	logs processLog
	done chan struct{}
	once sync.Once
}

func startProcess(t *testing.T, args ...string) *testProcess {
	t.Helper()
	p := &testProcess{done: make(chan struct{})}
	p.cmd = exec.Command(os.Args[0], append([]string{"-test.run=^TestBackpipeProcess$", "--"}, args...)...)
	p.cmd.Env = append(os.Environ(), "BACKPIPE_TEST_PROCESS=1")
	p.cmd.Stdout, p.cmd.Stderr = &p.logs, &p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.stop()
		if strings.Contains(p.logs.String(), "WARNING: DATA RACE") {
			t.Errorf("child process race:\n%s", p.logs.String())
		}
		if t.Failed() {
			t.Logf("child %v:\n%s", args, p.logs.String())
		}
	})
	return p
}

func (p *testProcess) stop() {
	p.once.Do(func() { p.cmd.Process.Kill(); <-p.done })
}

func await(t *testing.T, condition func() bool, detail func() string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", detail())
}

func listenerAddress(t *testing.T, p *testProcess, kind string) string {
	t.Helper()
	re := regexp.MustCompile(`waiting for ` + kind + ` connections on (127\.0\.0\.1:\d+)`)
	var addr string
	await(t, func() bool {
		m := re.FindStringSubmatch(p.logs.String())
		if len(m) > 1 {
			addr = m[1]
		}
		return addr != ""
	}, p.logs.String)
	return addr
}

func tcpEcho(t *testing.T, afterEOF bool) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				if afterEOF {
					b, err := io.ReadAll(c)
					if err == nil {
						c.Write(append([]byte("reply:"), b...))
					}
				} else {
					io.Copy(c, c)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := u.ReadFromUDP(b)
			if err != nil {
				return
			}
			u.WriteToUDP(b[:n], addr)
		}
	}()
	return u.LocalAddr().(*net.UDPAddr)
}

func dialClient(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(8 * time.Second))
	return c.(*net.TCPConn)
}

func expectBytes(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func clientAuth(t *testing.T, c net.Conn, auth string) {
	t.Helper()
	if auth == "" {
		c.Write([]byte{5, 1, 0})
		expectBytes(t, c, []byte{5, 0})
		return
	}
	u, p, _ := strings.Cut(auth, ":")
	c.Write([]byte{5, 2, 0, 2})
	expectBytes(t, c, []byte{5, 2})
	req := append([]byte{1, byte(len(u))}, u...)
	req = append(req, byte(len(p)))
	req = append(req, p...)
	c.Write(req)
	expectBytes(t, c, []byte{1, 0})
}

func clientRequest(t *testing.T, c net.Conn, command byte, target string, domain bool) {
	t.Helper()
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	req := []byte{5, command, 0}
	if domain {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	} else {
		ip := net.ParseIP(host)
		if ip.To4() != nil {
			req = append(req, 1)
			req = append(req, ip.To4()...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	}
	req = append(req, byte(port>>8), byte(port))
	// Fragment requests to exercise stream parsing rather than packet reads.
	for _, b := range req {
		if _, err := c.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
}

func clientReply(t *testing.T, c net.Conn, code byte) *net.UDPAddr {
	t.Helper()
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatal(err)
	}
	if h[0] != 5 || h[1] != code || h[2] != 0 {
		t.Fatalf("SOCKS reply %x, want code %d", h, code)
	}
	n := 4
	if h[3] == 4 {
		n = 16
	} else if h[3] != 1 {
		t.Fatalf("unexpected reply address type %d", h[3])
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	return &net.UDPAddr{IP: net.IP(b[:n]), Port: int(binary.BigEndian.Uint16(b[n:]))}
}

func udpPacket(dst *net.UDPAddr, payload []byte, domain bool) []byte {
	p := []byte{0, 0, 0}
	if domain {
		host := dst.IP.String()
		p = append(p, 3, byte(len(host)))
		p = append(p, host...)
	} else {
		if ip := dst.IP.To4(); ip != nil {
			p = append(p, 1)
			p = append(p, ip...)
		} else {
			p = append(p, 4)
			p = append(p, dst.IP.To16()...)
		}
	}
	p = append(p, byte(dst.Port>>8), byte(dst.Port))
	return append(p, payload...)
}

// Check the address actually sent on the wire before applying the client's
// unspecified-address fallback, as gonc and ProxyLane do.
func defaultUDPRelay(t *testing.T, c net.Conn) *net.UDPAddr {
	t.Helper()
	relay := clientReply(t, c, 0)
	if !relay.IP.Equal(net.IPv4zero) || relay.IP.To4() == nil || relay.Port == 0 {
		t.Fatalf("expected default reply 0.0.0.0:<allocated port>, got %s", relay)
	}
	peer := c.RemoteAddr().(*net.TCPAddr)
	relay.IP, relay.Zone = peer.IP, peer.Zone
	return relay
}

func udpRoundTrip(t *testing.T, u *net.UDPConn, relay, target *net.UDPAddr, payload []byte, domain bool) {
	t.Helper()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.WriteToUDP(udpPacket(target, payload, domain), relay); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	n, src, err := u.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	want := udpPacket(target, payload, false)
	if !bytes.Equal(b[:n], want) || src.Port != relay.Port {
		t.Fatalf("unexpected UDP response: len=%d want=%d source=%s", n, len(want), src)
	}
}

func TestSOCKSProxyEndToEnd(t *testing.T) {
	for _, proto := range []string{"plain", "tls"} {
		t.Run(proto, func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if proto == "tls" {
				transport = func(addr string) string { return "tls://" + addr + "?psk=integration-pool-key" }
			}
			server := startProcess(t, "server", "-listen", "socks5://user:pass@127.0.0.1:0", "-accept", transport("127.0.0.1:0"), "-socks-server-ip", "127.0.0.1")
			poolAddr := listenerAddress(t, server, "agent")
			proxyAddr := listenerAddress(t, server, "user")
			agentArgs := []string{"agent", "-connect", transport(poolAddr), "-pool", "2"}
			agent := startProcess(t, agentArgs...)
			await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") >= 2 }, server.logs.String)

			// Wrong credentials and unsupported commands do not consume pool slots.
			bad := dialClient(t, proxyAddr)
			bad.Write([]byte{5, 1, 2})
			expectBytes(t, bad, []byte{5, 2})
			bad.Write([]byte{1, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'})
			expectBytes(t, bad, []byte{1, 1})
			bad.Close()
			unsupported := dialClient(t, proxyAddr)
			clientAuth(t, unsupported, "user:pass")
			unsupported.Write([]byte{5, 2, 0, 1})
			clientReply(t, unsupported, 7)
			unsupported.Close()
			emptyTarget := dialClient(t, proxyAddr)
			clientAuth(t, emptyTarget, "user:pass")
			clientRequest(t, emptyTarget, 1, ":0", true)
			clientReply(t, emptyTarget, 8)
			emptyTarget.Close()
			if n := strings.Count(server.logs.String(), "agent connection pooled:"); n != 2 {
				t.Fatalf("unauthenticated/unsupported request replenished pool: %d", n)
			}

			// More active connections than -pool, all held open: automatic
			// replenishment must happen at activation, not at session close.
			target := tcpEcho(t, false)
			var active []*net.TCPConn
			for i := 0; i < 6; i++ {
				c := dialClient(t, proxyAddr)
				clientAuth(t, c, "user:pass")
				clientRequest(t, c, 1, target, i%2 == 0)
				clientReply(t, c, 0)
				payload := []byte(fmt.Sprintf("tcp-session-%d", i))
				c.Write(payload)
				expectBytes(t, c, payload)
				active = append(active, c)
			}
			await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=2 relays=6") }, server.logs.String)
			for _, c := range active {
				c.Close()
			}

			// A target that only responds after EOF proves half-close survives
			// the activation prefix wrapper and both plain/TLS pool transports.
			c := dialClient(t, proxyAddr)
			clientAuth(t, c, "user:pass")
			clientRequest(t, c, 1, tcpEcho(t, true), false)
			clientReply(t, c, 0)
			c.Write([]byte("after-eof"))
			c.CloseWrite()
			expectBytes(t, c, []byte("reply:after-eof"))
			c.Close()

			// Two simultaneous associations from one IP, multiple destinations,
			// domain-form addressing, empty and large datagrams.
			udpTargets := []*net.UDPAddr{udpEcho(t), udpEcho(t)}
			var controls []*net.TCPConn
			for i := 0; i < 2; i++ {
				control := dialClient(t, proxyAddr)
				clientAuth(t, control, "user:pass")
				if i == 0 {
					clientRequest(t, control, 3, "0.0.0.0:0", false)
				} else {
					// Legacy gonc CreateSocks5UDPClient sends an empty domain.
					clientRequest(t, control, 3, ":0", true)
				}
				relay := clientReply(t, control, 0)
				if !relay.IP.Equal(net.IPv4(127, 0, 0, 1)) || relay.Port == 0 {
					t.Fatalf("invalid server relay address: %s", relay)
				}
				u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { u.Close() })
				for j, payload := range [][]byte{[]byte(fmt.Sprintf("udp-session-%d", i)), {}, bytes.Repeat([]byte("x"), 32000)} {
					udpRoundTrip(t, u, relay, udpTargets[j%2], payload, j%2 == 0)
				}
				controls = append(controls, control)
			}
			controls[0].Close()
			await(t, func() bool { return strings.Count(server.logs.String(), "UDP association ended:") >= 1 }, server.logs.String)
			// Losing the agent must close a live UDP control connection too.
			agent.stop()
			controls[1].SetReadDeadline(time.Now().Add(3 * time.Second))
			var b [1]byte
			if _, err := controls[1].Read(b[:]); err != io.EOF {
				t.Fatalf("agent loss did not close UDP control connection: %v", err)
			}
			pooled := strings.Count(server.logs.String(), "agent connection pooled:")
			startProcess(t, agentArgs...)
			await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") >= pooled+2 }, server.logs.String)
			c = dialClient(t, proxyAddr)
			clientAuth(t, c, "user:pass")
			clientRequest(t, c, 1, target, false)
			clientReply(t, c, 0)
			c.Write([]byte("reconnected"))
			expectBytes(t, c, []byte("reconnected"))
		})
	}
}

func TestSOCKSUDPAssociateEmptyDomain(t *testing.T) {
	for _, proto := range []string{"plain", "tls"} {
		t.Run(proto, func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if proto == "tls" {
				transport = func(addr string) string { return "tls://" + addr + "?psk=empty-domain-test" }
			}
			server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", transport("127.0.0.1:0"))
			poolAddr := listenerAddress(t, server, "agent")
			proxyAddr := listenerAddress(t, server, "user")
			startProcess(t, "agent", "-connect", transport(poolAddr), "-pool", "1")
			control := dialClient(t, proxyAddr)
			clientAuth(t, control, "")
			clientRequest(t, control, 3, ":0", true)
			if relay := clientReply(t, control, 0); relay.Port == 0 {
				t.Fatal("UDP ASSOCIATE returned a zero relay port")
			}
			control.Close()
			await(t, func() bool { return strings.Contains(server.logs.String(), "UDP association ended:") }, server.logs.String)
		})
	}
}

func TestUDPIdleCleanup(t *testing.T) {
	server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", "127.0.0.1:0", "-udp-timeout", "300ms")
	poolAddr := listenerAddress(t, server, "agent")
	proxyAddr := listenerAddress(t, server, "user")
	startProcess(t, "agent", "-connect", poolAddr, "-pool", "1", "-udp-timeout", "300ms")
	c := dialClient(t, proxyAddr)
	clientAuth(t, c, "")
	clientRequest(t, c, 3, "0.0.0.0:0", false)
	relay := defaultUDPRelay(t, c)
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	target := udpEcho(t)
	// Activity must extend the timeout in both directions.
	for i := 0; i < 8; i++ {
		udpRoundTrip(t, u, relay, target, []byte("keepalive"), false)
		time.Sleep(80 * time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err != io.EOF {
		t.Fatalf("idle association was not closed: %v", err)
	}
	await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=1 relays=0") }, server.logs.String)
}

func TestRawRelay(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", encrypted), func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if encrypted {
				transport = func(addr string) string { return "tls://" + addr + "?psk=raw-key" }
			}
			target := tcpEcho(t, false)
			server := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0", "-accept", transport("127.0.0.1:0"))
			poolAddr := listenerAddress(t, server, "agent")
			userAddr := listenerAddress(t, server, "user")
			startProcess(t, "agent", "-connect", transport(poolAddr), "-target", target, "-pool", "1")
			c := dialClient(t, userAddr)
			c.Write([]byte("fixed-target"))
			expectBytes(t, c, []byte("fixed-target"))
		})
	}
}

func TestSOCKSIPv6AndUDPSourcePinning(t *testing.T) {
	tcp, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 UDP unavailable: %v", err)
	}
	defer udp.Close()
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.Copy(c, c)
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, src, err := udp.ReadFromUDP(b)
			if err != nil {
				return
			}
			udp.WriteToUDP(b[:n], src)
		}
	}()
	server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", "127.0.0.1:0")
	poolAddr := listenerAddress(t, server, "agent")
	proxyAddr := listenerAddress(t, server, "user")
	startProcess(t, "agent", "-connect", poolAddr, "-pool", "1")
	c := dialClient(t, proxyAddr)
	clientAuth(t, c, "")
	clientRequest(t, c, 1, tcp.Addr().String(), false)
	clientReply(t, c, 0)
	c.Write([]byte("ipv6-tcp"))
	expectBytes(t, c, []byte("ipv6-tcp"))
	c.Close()
	control := dialClient(t, proxyAddr)
	clientAuth(t, control, "")
	clientRequest(t, control, 3, "[::]:0", false)
	relay := defaultUDPRelay(t, control)
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	target := udp.LocalAddr().(*net.UDPAddr)
	udpRoundTrip(t, u, relay, target, []byte("ipv6-udp"), false)
	// Another source port on the same IP cannot take over this association.
	rogue, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Close()
	rogue.SetDeadline(time.Now().Add(150 * time.Millisecond))
	rogue.WriteToUDP(udpPacket(target, []byte("wrong-source"), false), relay)
	var b [128]byte
	if _, _, err := rogue.ReadFromUDP(b[:]); err == nil {
		t.Fatal("unassociated UDP source received a response")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal(err)
	}
	udpRoundTrip(t, u, relay, target, []byte("still-associated"), false)
}

// Exercise the exact client used by gonc -x PROXY -u HOST PORT. Unlike the
// raw SOCKS clients above, it puts the destination in UDP ASSOCIATE and then
// opens an ephemeral UDP source port after receiving the relay address.
func TestGoncUDPClient(t *testing.T) {
	for _, proto := range []string{"plain", "tls"} {
		t.Run(proto, func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if proto == "tls" {
				transport = func(addr string) string { return "tls://" + addr + "?psk=gonc-udp-test-key" }
			}
			server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", transport("127.0.0.1:0"))
			poolAddr := listenerAddress(t, server, "agent")
			proxyAddr := listenerAddress(t, server, "user")
			startProcess(t, []string{"agent", "-connect", transport(poolAddr), "-pool", "2"}...)
			config, err := apps.ProxyClientConfigByCommandline(io.Discard, "socks5", "", proxyAddr)
			if err != nil {
				t.Fatal(err)
			}
			client := apps.NewSocks5Client(config)
			target := udpEcho(t)
			conn, err := client.DialTimeout("udp", target.String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("gonc-udp-through-backpipe")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, conn, payload)
		})
	}
}
