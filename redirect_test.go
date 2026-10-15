package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

func TestRedirectRules(t *testing.T) {
	c, err := parseCommand("agent", []string{"-connect", "server:10086",
		"-redirect", "Priv-Domain.:0500=1.2.3.4:600",
		"-redirect", "tcp://split:53=localhost:1053",
		"-redirect", "udp://split:53=[::1]:2053",
		"-redirect", "[2001:db8::1]:443=[2001:db8::2]:8443",
		"-redirect", "1.2.3.4:600=other:700",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ network, from, want string }{
		{"tcp", "PRIV-DOMAIN:500", "1.2.3.4:600"},
		{"udp", "priv-domain.:500", "1.2.3.4:600"},
		{"tcp", "split:53", "localhost:1053"},
		{"udp", "split:53", "[::1]:2053"},
		{"tcp", "[2001:0db8:0:0::1]:443", "[2001:db8::2]:8443"},
		{"udp", "[::ffff:1.2.3.4]:600", "other:700"},
		{"tcp", "priv-domain:501", "priv-domain:501"},
		{"udp", "unmatched:500", "unmatched:500"},
	} {
		if got := c.redirects.rewrite(tc.network, tc.from); got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.network, tc.from, got, tc.want)
		}
	}
	for _, rules := range [][]string{
		{"a:1=b:2", "tcp://A.:01=c:3"},
		{"udp://a:1=b:2", "a:1=c:3"},
		{"tcp://a:1=b:2", "tcp://a:1=b:2"},
		{"[::ffff:127.0.0.1]:80=b:2", "127.0.0.1:80=c:3"},
		{"a:1"}, {"a:1=b:2=c:3"}, {"a:1="}, {"=b:2"},
		{"tls://a:1=b:2"}, {"a:1=tcp://b:2"}, {"*.example:1=b:2"},
		{"a:0=b:2"}, {"a:1=b:65536"}, {"a:1=b:-1"}, {"a:1=b:+2"},
		{"a:1=b:http"}, {"a:1=:2"}, {"a:1=b:2?psk=secret"},
		{"a:1=user@b:2"}, {"a:1=bad host:2"}, {"a..b:1=c:2"},
		{"a:1=[fe80::1%bad\nzone]:2"},
	} {
		args := []string{"-connect", "server:10086"}
		for _, rule := range rules {
			args = append(args, "-redirect", rule)
		}
		if _, err := parseCommand("agent", args, io.Discard); err == nil {
			t.Errorf("invalid rules accepted: %q", rules)
		}
	}
	if _, err := parseCommand("server", []string{"-listen", "socks5://:1080", "-accept", ":10086", "-redirect", "a:1=b:2"}, io.Discard); err == nil {
		t.Fatal("server accepted agent-only redirect flag")
	}
}

func TestRedirectProxyEndToEnd(t *testing.T) {
	tcpTarget := tcpEcho(t, true)
	udpTarget := udpEcho(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Host, r.URL.RequestURI())
	}))
	defer origin.Close()
	server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-listen", "socks5s://127.0.0.1:0?psk=redirect-entry", "-accept", "tls://127.0.0.1:0?psk=redirect-pool")
	entries := entryAddresses(t, server, 2)
	agent := startProcess(t, "agent", "-connect", "tls://"+listenerAddress(t, server, "agent")+"?psk=redirect-pool", "-pool", "2",
		"-redirect", "tcp://priv-domain.invalid:500="+tcpTarget,
		"-redirect", "udp://priv-domain.invalid:500="+udpTarget.String(),
		"-redirect", "another.invalid:500="+udpTarget.String(),
		"-redirect", "web.invalid:18080="+strings.TrimPrefix(origin.URL, "http://"))
	for entry := range entries {
		t.Run(fmt.Sprintf("encrypted=%v", entry == 1), func(t *testing.T) {
			dial := func() (net.Conn, [32]byte) {
				t.Helper()
				var c net.Conn = dialClient(t, entries[entry])
				var key [32]byte
				if entry == 1 {
					n, err := secure.DoNegotiation(goncTLSForTest(t, "redirect-entry", true), c, io.Discard)
					if err != nil {
						t.Fatal(err)
					}
					c, key = n, n.KeyingMaterial
					t.Cleanup(func() { c.Close() })
				}
				return c, key
			}
			// Unresolvable original domain proves matching precedes DNS. Half-close
			// exercises both the original buffered connection and the rewritten line.
			c, _ := dial()
			clientAuth(t, c, "")
			clientRequest(t, c, 1, "PRIV-DOMAIN.INVALID.:500", true)
			clientReply(t, c, 0)
			if _, err := c.Write([]byte("redirect-socks")); err != nil {
				t.Fatal(err)
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, c, []byte("reply:redirect-socks"))
			c.Close()

			c, _ = dial()
			if err := writeAll(c, []byte("CONNECT priv-domain.invalid:500 HTTP/1.1\r\nHost: priv-domain.invalid:500\r\n\r\nearly-data")); err != nil {
				t.Fatal(err)
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(c)
			resp, err := http.ReadResponse(r, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("CONNECT status %d", resp.StatusCode)
			}
			expectBytes(t, r, []byte("reply:early-data"))
			c.Close()

			c, _ = dial()
			if err := writeAll(c, []byte("GET http://web.invalid:18080/path?q=1 HTTP/1.1\r\nHost: web.invalid:18080\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			resp, err = http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "web.invalid:18080 /path?q=1" {
				t.Fatalf("HTTP Host/path changed: %q, %v", body, err)
			}

			control, key := dial()
			clientAuth(t, control, "")
			clientRequest(t, control, 3, "0.0.0.0:0", false)
			relayAddr := defaultUDPRelay(t, control)
			u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			var packets net.PacketConn = u
			if entry == 1 {
				packets, err = secure.NewSecureUDPConn(u, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, host := range []string{"priv-domain.invalid", "another.invalid", "priv-domain.invalid"} {
				payload := []byte("reply-for-" + host)
				packet := append([]byte{0, 0, 0, 3, byte(len(host))}, []byte(host)...)
				packet = append(packet, 1, 244) // Original port 500, different from exit.
				packet = append(packet, payload...)
				u.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := packets.WriteTo(packet, relayAddr); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65535)
				n, _, err := packets.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], udpPacket(udpTarget, payload, false)) {
					t.Fatal("UDP reply did not retain actual exit IP and port")
				}
			}
			// The same association must also forward unmatched destinations.
			payload := []byte("unmatched")
			packet := udpPacket(udpTarget, payload, false)
			u.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := packets.WriteTo(packet, relayAddr); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 65535)
			n, _, err := packets.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:n], packet) {
				t.Fatalf("unmatched UDP failed: %v", err)
			}
			control.Close()
		})
	}
	await(t, func() bool {
		return strings.Contains(agent.logs.String(), "redirect tcp:") && strings.Contains(agent.logs.String(), "redirect udp:")
	}, agent.logs.String)
}

func TestRedirectFixedTargetAndNoFallback(t *testing.T) {
	target := tcpEcho(t, false)
	server := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0", "-accept", "127.0.0.1:0")
	startProcess(t, "agent", "-connect", listenerAddress(t, server, "agent"), "-target", "fixed.invalid:500", "-redirect", "fixed.invalid:500="+target, "-redirect", target+"=must-not-chain.invalid:600", "-pool", "1")
	c := dialClient(t, listenerAddress(t, server, "user"))
	if _, err := c.Write([]byte("fixed-target")); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, c, []byte("fixed-target"))

	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	proxy := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", "127.0.0.1:0")
	startProcess(t, "agent", "-connect", listenerAddress(t, proxy, "agent"), "-redirect", target+"="+closedAddr, "-pool", "1")
	p := dialClient(t, listenerAddress(t, proxy, "user"))
	clientAuth(t, p, "")
	clientRequest(t, p, 1, target, false)
	// A reachable original must not be used after the redirected dial fails.
	var reply [4]byte
	if _, err := io.ReadFull(p, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] == 0 {
		t.Fatalf("unexpected fallback reply: %x", reply)
	}
}

func TestRedirectPreservesBufferedTunnelPayload(t *testing.T) {
	rules, err := parseRedirectRules([]string{"buffer.invalid:500=" + tcpEcho(t, true)})
	if err != nil {
		t.Fatal(err)
	}
	options, err := newProxyOptions("", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s, peer, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer peer.Close()
	done := make(chan struct{})
	go func() { defer close(done); serveProxyTunnel(s, options, rules) }()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(peer, []byte("tcp://buffer.invalid:500\ncoalesced-payload")); err != nil {
		t.Fatal(err)
	}
	if err := peer.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, peer, []byte("OK\nreply:coalesced-payload"))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not close")
	}
}
