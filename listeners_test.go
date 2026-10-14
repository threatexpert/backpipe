package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
)

func entryAddresses(t *testing.T, server *testProcess, count int) []string {
	t.Helper()
	re := regexp.MustCompile(`waiting for user connections on (\S+)`)
	var addresses []string
	await(t, func() bool {
		matches := re.FindAllStringSubmatch(server.logs.String(), -1)
		if len(matches) != count {
			return false
		}
		addresses = nil
		for _, match := range matches {
			host, port, err := net.SplitHostPort(match[1])
			if err != nil {
				t.Fatal(err)
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
				host = "127.0.0.1"
			}
			addresses = append(addresses, net.JoinHostPort(host, port))
		}
		return true
	}, server.logs.String)
	return addresses
}

func TestMultipleSOCKSEntriesSharePool(t *testing.T) {
	for _, encryptedPool := range []bool{false, true} {
		t.Run(fmt.Sprintf("poolTLS=%v", encryptedPool), func(t *testing.T) {
			transport := func(addr string) string { return addr }
			if encryptedPool {
				transport = func(addr string) string { return "tls://" + addr + "?psk=shared-pool-key" }
			}
			server := startProcess(t, "server",
				"-listen", "socks5s://public:public-pass@:0?psk=public-key",
				"-listen", "socks5://127.0.0.1:0",
				"-listen", "socks5s://other:other-pass@127.0.0.1:0?psk=other-key",
				"-accept", transport("127.0.0.1:0"))
			entries := entryAddresses(t, server, 3)
			startProcess(t, "agent", "-connect", transport(listenerAddress(t, server, "agent")), "-pool", "2")
			await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)
			target := tcpEcho(t, false)
			// A different entry's PSK or password must not authenticate here.
			for _, raw := range []string{
				"socks5s://public:public-pass@" + entries[0] + "?psk=other-key",
				"socks5s://other:other-pass@" + entries[0] + "?psk=public-key",
			} {
				cfg, err := apps.ParseProxyURL(io.Discard, raw)
				if err != nil {
					t.Fatal(err)
				}
				c, err := apps.NewSocks5Client(cfg).DialTimeout("tcp", target, 2*time.Second)
				if c != nil {
					c.Close()
				}
				if err == nil {
					t.Fatal("credentials leaked across entries")
				}
			}
			if strings.Count(server.logs.String(), "agent connection pooled:") != 2 {
				t.Fatal("rejected clients consumed pool slots")
			}
			urls := []string{
				"socks5s://public:public-pass@" + entries[0] + "?psk=public-key",
				"socks5://" + entries[1],
				"socks5s://other:other-pass@" + entries[2] + "?psk=other-key",
			}
			var active []net.Conn
			for _, raw := range urls {
				cfg, err := apps.ParseProxyURL(io.Discard, raw)
				if err != nil {
					t.Fatal(err)
				}
				client := apps.NewSocks5Client(cfg)
				for _, network := range []string{"tcp", "udp"} {
					dst := target
					if network == "udp" {
						dst = udpEcho(t).String()
					}
					c, err := client.DialTimeout(network, dst, 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.Close() })
					active = append(active, c)
				}
			}
			// All entries transfer at once, with six active sessions sharing a
			// single two-slot idle pool. A separate pool per entry would stall.
			results := make(chan error, len(active))
			for i, c := range active {
				go func() {
					c.SetDeadline(time.Now().Add(4 * time.Second))
					payload := []byte(fmt.Sprintf("entry-session-%d", i))
					if _, err := c.Write(payload); err != nil {
						results <- err
						return
					}
					got := make([]byte, len(payload))
					_, err := io.ReadFull(c, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = fmt.Errorf("session %d received another session's payload", i)
					}
					results <- err
				}()
			}
			for range active {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=2 relays=6") }, server.logs.String)
			active[1].Close()
			await(t, func() bool { return strings.Contains(server.logs.String(), "UDP association ended:") }, server.logs.String)
			// Closing the public UDP association must leave the local one alive.
			active[3].SetDeadline(time.Now().Add(3 * time.Second))
			active[3].Write([]byte("local-still-alive"))
			expectBytes(t, active[3], []byte("local-still-alive"))
			for _, c := range active {
				c.Close()
			}
			await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=2 relays=0") }, server.logs.String)
		})
	}
}

func TestListenerBindFailureReleasesEarlierPorts(t *testing.T) {
	// Reserve distinct ports, then force the second client entry to collide
	// with the first. The binder must release both the first entry and pool.
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	pool, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	entryAddr, poolAddr := first.Addr().String(), pool.Addr().String()
	first.Close()
	pool.Close()
	entries := []entryConfig{
		{endpoint: endpoint{scheme: "socks5", address: entryAddr}},
		{endpoint: endpoint{scheme: "socks5s", address: entryAddr}},
	}
	p, listeners, err := bindServerListeners(entries, poolAddr)
	if err == nil {
		p.Close()
		for _, ln := range listeners {
			ln.Close()
		}
		t.Fatal("duplicate address did not fail")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Fatal(err)
	}
	for _, addr := range []string{entryAddr, poolAddr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("startup failure left %s bound: %v", addr, err)
		}
		ln.Close()
	}
	server := startProcess(t, "server", "-listen", "socks5://"+entryAddr, "-listen", "socks5s://"+entryAddr+"?psk=hidden-key", "-accept", poolAddr)
	select {
	case <-server.done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after bind failure")
	}
	if server.cmd.ProcessState.ExitCode() == 0 {
		t.Fatal("bind failure reported success")
	}
	logs := server.logs.String()
	if !strings.Contains(logs, "entry 2") || strings.Contains(logs, "waiting for") || strings.Contains(logs, "hidden-key") {
		t.Fatalf("incorrect startup diagnostics: %s", logs)
	}
}
