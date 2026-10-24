package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/secure"
)

func TestFixedEntriesShareProxyPool(t *testing.T) {
	// A server-first service must work without any bytes from the raw client.
	// Waiting for EOF before replying also checks half-close through the tunnel.
	banner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { banner.Close() })
	go func() {
		c, err := banner.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(15 * time.Second))
		if err := writeAll(c, []byte("service-ready\n")); err != nil {
			return
		}
		b, err := io.ReadAll(c)
		if err == nil {
			writeAll(c, append([]byte("reply:"), b...))
		}
	}()
	udpTarget, observations := forwardObservedUDPEcho(t)
	tcpTarget := tcpEcho(t, false)
	proxyUDPTarget := udpEcho(t)
	server := startProcess(t, "server",
		"-listen", "tcp://127.0.0.1:0?to=banner.invalid:500",
		"-listen", "udp://127.0.0.1:0?to=charon.invalid:500",
		"-listen", "socks5://127.0.0.1:0",
		"-listen", "socks5s://127.0.0.1:0?psk=fixed-entry-key",
		"-accept", "tls://127.0.0.1:0?psk=fixed-pool-key")
	entries := entryAddresses(t, server, 4)
	startProcess(t, "agent", "-connect", "tls://"+listenerAddress(t, server, "agent")+"?psk=fixed-pool-key", "-pool", "2",
		"-redirect", "tcp://banner.invalid:500="+banner.Addr().String(),
		"-redirect", "udp://charon.invalid:500="+udpTarget.String(),
		"-redirect", "tcp://proxy.invalid:80="+tcpTarget,
		"-redirect", "udp://proxy.invalid:80="+proxyUDPTarget.String())
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)

	rawTCP := dialClient(t, entries[0])
	expectBytes(t, rawTCP, []byte("service-ready\n"))
	relay, err := net.ResolveUDPAddr("udp4", entries[1])
	if err != nil {
		t.Fatal(err)
	}
	rawUDP := []*net.UDPConn{forwardUDPClient(t), forwardUDPClient(t)}
	var sources [2]string
	for round := 0; round < 3; round++ {
		for i, c := range rawUDP {
			payload := []byte(fmt.Sprintf("raw-client-%d-packet-%d", i, round))
			if i == 0 && round == 0 {
				payload = nil // Even the first, empty UDP datagram creates a session.
			}
			forwardUDPRoundTrip(t, c, relay, payload)
			select {
			case observed := <-observations:
				if !bytes.Equal(observed.payload, payload) {
					t.Fatalf("raw UDP payload changed: %x, want %x", observed.payload, payload)
				}
				if round == 0 {
					sources[i] = observed.source
				} else if sources[i] != observed.source {
					t.Fatalf("client %d did not reuse its agent UDP socket: %s -> %s", i, sources[i], observed.source)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("missing agent UDP source observation")
			}
		}
	}
	if sources[0] == sources[1] {
		t.Fatal("different UDP clients shared the same agent UDP socket")
	}

	// Keep both fixed forwards alive while opening SOCKS TCP, SOCKS UDP and
	// HTTP CONNECT through each proxy entry. All nine sessions share two idle
	// connections; a separate fixed-forward pool would stall here.
	var active []net.Conn
	for i, entry := range entries[2:] {
		proxyURL := "socks5://" + entry
		if i == 1 {
			proxyURL = "socks5s://" + entry + "?psk=fixed-entry-key"
		}
		cfg, err := apps.ParseProxyURL(io.Discard, proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, network := range []string{"tcp", "udp"} {
			c, err := apps.NewSocks5Client(cfg).DialTimeout(network, "proxy.invalid:80", 3*time.Second)
			if err != nil {
				t.Fatalf("proxy entry %d %s: %v", i, network, err)
			}
			t.Cleanup(func() { c.Close() })
			active = append(active, c)
		}
		var c net.Conn = dialClient(t, entry)
		if i == 1 {
			n, err := secure.DoNegotiation(goncTLSForTest(t, "fixed-entry-key", true), c, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			c = n
			t.Cleanup(func() { c.Close() })
		}
		if err := writeAll(c, []byte("CONNECT proxy.invalid:80 HTTP/1.1\r\nHost: proxy.invalid:80\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(c)
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP CONNECT status: %s", resp.Status)
		}
		active = append(active, &readerConn{Conn: c, reader: r})
	}
	for i, c := range active {
		c.SetDeadline(time.Now().Add(4 * time.Second))
		payload := []byte(fmt.Sprintf("mixed-session-%d", i))
		if err := writeAll(c, payload); err != nil {
			t.Fatal(err)
		}
		expectBytes(t, c, payload)
	}
	await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=2 relays=9") }, server.logs.String)
	if got := strings.Count(server.logs.String(), "agent connection pooled:"); got != 11 {
		t.Fatalf("packets consumed extra pool connections: got %d pooled, want 2 initial + 9 sessions", got)
	}
	if err := writeAll(rawTCP, []byte("raw-half-close")); err != nil {
		t.Fatal(err)
	}
	if err := rawTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, rawTCP, []byte("reply:raw-half-close"))
	for _, c := range active {
		c.Close()
	}
	forwardUDPRoundTrip(t, rawUDP[1], relay, []byte("fixed-udp-still-active"))
}

func TestFixedUDPExplicitTCPWithoutDTLS(t *testing.T) {
	for _, scheme := range []string{"tcp", "tls"} {
		t.Run(scheme, func(t *testing.T) {
			targets := []*net.UDPAddr{udpEcho(t), udpEcho(t)}
			poolEndpoint := scheme + "://127.0.0.1:0"
			if scheme == "tls" {
				poolEndpoint += "?psk=fixed-udp-tcp-regression"
			}
			server := startProcess(t, "server",
				"-listen", "udp://127.0.0.1:0?to=charon:500",
				"-listen", "udp://127.0.0.1:0?to=charon:4500",
				"-accept", poolEndpoint, "-udp-transport", "tcp")
			entries := entryAddresses(t, server, 2)
			connect := scheme + "://" + listenerAddress(t, server, "agent")
			if scheme == "tls" {
				connect += "?psk=fixed-udp-tcp-regression"
			}
			agent := startProcess(t, "agent", "-connect", connect, "-pool", "1",
				"-redirect", "udp://charon:500="+targets[0].String(),
				"-redirect", "udp://charon:4500="+targets[1].String())
			clients := []*net.UDPConn{forwardUDPClient(t), forwardUDPClient(t)}
			// Keep both sessions active while the single idle pool replenishes.
			// Preserve empty datagrams, NAT keepalives, binary payloads, and
			// frames larger than a TLS record through the old stream carrier.
			payloads := [][]byte{nil, {0xff}, make([]byte, 28),
				append([]byte{0, 0, 0, 0}, bytes.Repeat([]byte{0x20}, 1300)...),
				bytes.Repeat([]byte{0xa5}, 60000)}
			for _, payload := range payloads {
				for i, client := range clients {
					relay, err := net.ResolveUDPAddr("udp4", entries[i])
					if err != nil {
						t.Fatal(err)
					}
					forwardUDPRoundTrip(t, client, relay, payload)
				}
			}
			await(t, func() bool {
				return strings.Count(server.logs.String(), "agent connection pooled:") == 3
			}, server.logs.String)
			if strings.Count(server.logs.String(), "(transport=tcp)") != 2 ||
				strings.Count(agent.logs.String(), "(transport=tcp)") != 2 ||
				strings.Contains(server.logs.String(), "UDP agent") {
				t.Fatalf("unexpected UDP carrier:\nserver:\n%s\nagent:\n%s", server.logs.String(), agent.logs.String())
			}
		})
	}
}

func TestFixedUDPIdleAndAgentRecovery(t *testing.T) {
	target := udpEcho(t)
	server := startProcess(t, "server", "-listen", "udp://127.0.0.1:0?to=charon.invalid:500", "-accept", "127.0.0.1:0", "-udp-timeout", "300ms")
	entries := entryAddresses(t, server, 1)
	relay, err := net.ResolveUDPAddr("udp4", entries[0])
	if err != nil {
		t.Fatal(err)
	}
	agentArgs := []string{"agent", "-connect", listenerAddress(t, server, "agent"), "-pool", "1", "-udp-timeout", "300ms", "-redirect", "udp://charon.invalid:500=" + target.String()}
	agent := startProcess(t, agentArgs...)
	c := forwardUDPClient(t)
	for i := 0; i < 8; i++ {
		forwardUDPRoundTrip(t, c, relay, []byte("refresh-idle-timeout"))
		time.Sleep(80 * time.Millisecond)
	}
	if got := strings.Count(server.logs.String(), "UDP forward:"); got != 1 {
		t.Fatalf("active traffic did not preserve one session: got %d", got)
	}
	await(t, func() bool { return strings.Count(server.logs.String(), "UDP forward ended:") == 1 }, server.logs.String)
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)

	// The same client address must establish a fresh tunnel after expiry.
	forwardUDPRoundTrip(t, c, relay, []byte("after-idle"))
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 3 }, server.logs.String)
	agent.stop()
	await(t, func() bool { return strings.Count(server.logs.String(), "UDP forward ended:") == 2 }, server.logs.String)

	// A dead active session must also be evicted, so one packet is sufficient
	// to use the replacement agent rather than disappearing in a stale tunnel.
	startProcess(t, agentArgs...)
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 4 }, server.logs.String)
	forwardUDPRoundTrip(t, c, relay, []byte("after-agent-restart"))
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 5 }, server.logs.String)
}

func TestFixedTCPFailureClosesWithoutTunnelReply(t *testing.T) {
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedTarget := reserved.Addr().String()
	reserved.Close()
	server := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0?to=closed.invalid:80", "-accept", "127.0.0.1:0")
	startProcess(t, "agent", "-connect", listenerAddress(t, server, "agent"), "-pool", "1", "-redirect", "closed.invalid:80="+closedTarget)
	c := dialClient(t, listenerAddress(t, server, "user"))
	var b [128]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil {
		t.Fatalf("failed target leaked an internal tunnel reply: %q, %v", b[:n], err)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("failed target did not close the client")
	}
}

type forwardUDPObservation struct {
	source  string
	payload []byte
}

func forwardObservedUDPEcho(t *testing.T) (*net.UDPAddr, <-chan forwardUDPObservation) {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	observations := make(chan forwardUDPObservation, 32)
	go func() {
		b := make([]byte, 65535)
		for {
			n, src, err := u.ReadFromUDP(b)
			if err != nil {
				return
			}
			observations <- forwardUDPObservation{source: src.String(), payload: append([]byte(nil), b[:n]...)}
			u.WriteToUDP(b[:n], src)
		}
	}()
	return u.LocalAddr().(*net.UDPAddr), observations
}

func forwardUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

func forwardUDPRoundTrip(t *testing.T, c *net.UDPConn, relay *net.UDPAddr, payload []byte) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.WriteToUDP(payload, relay); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, source, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !source.IP.Equal(relay.IP) || source.Port != relay.Port {
		t.Fatalf("reply source %s differs from fixed listener %s", source, relay)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("raw UDP response %x, want %x", buf[:n], payload)
	}
}
