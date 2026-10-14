package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

func expectIdleWithoutApplicationData(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	var buf [64]byte
	n, err := c.Read(buf[:])
	if n != 0 {
		t.Fatalf("idle connection sent application data: %x", buf[:n])
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("idle connection did not stay open: %v", err)
	}
	c.SetReadDeadline(time.Time{})
}

func TestPoolHasNoApplicationRegistration(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", encrypted), func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if encrypted {
				transport = func(addr string) string { return "tls://" + addr + "?psk=idle-pool-key" }
			}
			// A silent peer enters a real server's SOCKS pool immediately and
			// receives no application ACK, in either plain or TLS mode.
			server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-accept", transport("127.0.0.1:0"))
			var peer net.Conn = dialClient(t, listenerAddress(t, server, "agent"))
			if encrypted {
				conn, err := secure.DoNegotiation(goncTLSForTest(t, "idle-pool-key", true), peer, io.Discard)
				if err != nil {
					t.Fatal(err)
				}
				peer = conn
			}
			defer peer.Close()
			await(t, func() bool { return strings.Contains(server.logs.String(), "agent connection pooled:") }, server.logs.String)
			expectIdleWithoutApplicationData(t, peer)

			// A real proxy-mode agent must also stay silent, then accept the
			// first UDP tunnel request directly without waiting for an ACK.
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			startProcess(t, "agent", "-connect", transport(ln.Addr().String()), "-pool", "1")
			accept := func() net.Conn {
				t.Helper()
				ln.SetDeadline(time.Now().Add(3 * time.Second))
				raw, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { raw.Close() })
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				var conn net.Conn = raw
				if encrypted {
					conn, err = secure.DoNegotiation(goncTLSForTest(t, "idle-pool-key", false), raw, io.Discard)
					if err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			conn := accept()
			expectIdleWithoutApplicationData(t, conn)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := writeAll(conn, []byte("udp://0.0.0.0:0\n")); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, conn, []byte("OK\n"))
			packet := udpPacket(udpEcho(t), []byte("first-business-request"), false)
			if err := writeUDPFrame(conn, packet); err != nil {
				t.Fatal(err)
			}
			got, err := readUDPFrame(conn, make([]byte, 65535))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, packet) {
				t.Fatalf("unexpected UDP reply: %x", got)
			}
			// Replenish before the active session closes, with no registration
			// on the replacement connection either.
			expectIdleWithoutApplicationData(t, accept())
		})
	}
}
