package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestKCPDTLSPoolAndCoexistence(t *testing.T) {
	for _, mode := range []string{"kcp-only", "native-udp", "forced-stream", "fec-only", "fec-native-udp"} {
		t.Run(mode, func(t *testing.T) {
			native := mode == "native-udp" || mode == "forced-stream" || mode == "fec-native-udp"
			fec := strings.HasPrefix(mode, "fec-")
			key := "kcp-integration-key"
			target := tcpEcho(t, false)
			udpTarget := udpEcho(t)
			args := []string{"server", "-listen", "socks5://127.0.0.1:0", "-listen", "tcp://127.0.0.1:0?to=" + target,
				"-listen", "udp://127.0.0.1:0?to=" + udpTarget.String(), "-accept", "kcp+dtls://127.0.0.1:0?psk=" + key,
				"-kcp-heartbeat", "100ms", "-kcp-timeout", "1s"}
			if mode == "kcp-only" {
				args = append(args, "-kcp-sndwnd", "1024", "-kcp-rcvwnd", "1024")
			}
			if fec {
				args = append(args, "-kcp-fec", "10:3")
			}
			if native {
				args = append(args, "-accept", "dtls://127.0.0.1:0?psk="+key)
			}
			if mode == "forced-stream" {
				args = append(args, "-udp-transport", "stream")
			}
			server := startProcess(t, args...)
			entries := entryAddresses(t, server, 3)
			agentArgs := []string{"agent", "-connect", "kcp+dtls://" + listenerAddress(t, server, "agent") + "?psk=" + key,
				"-pool", "1", "-kcp-heartbeat", "100ms", "-kcp-timeout", "1s"}
			if mode == "kcp-only" {
				agentArgs = append(agentArgs, "-kcp-sndwnd", "1024", "-kcp-rcvwnd", "1024")
			}
			if fec {
				agentArgs = append(agentArgs, "-kcp-fec", "10:3")
			}
			if native {
				agentArgs = append(agentArgs, "-connect", "dtls://"+listenerAddress(t, server, "UDP agent")+"?psk="+key, "-udp-pool", "1")
			}
			agent := startProcess(t, agentArgs...)
			await(t, func() bool { return strings.Contains(server.logs.String(), "agent connection pooled:") }, server.logs.String)
			// SOCKS CONNECT and a target that responds only after receiving EOF.
			control := dialClient(t, entries[0])
			clientAuth(t, control, "")
			clientRequest(t, control, 1, tcpEcho(t, true), false)
			clientReply(t, control, 0)
			payload := bytes.Repeat([]byte("half-close"), 10000)
			if err := writeAll(control, payload); err != nil {
				t.Fatal(err)
			}
			control.CloseWrite()
			expectBytes(t, control, append([]byte("reply:"), payload...))
			control.Close()
			// HTTP CONNECT keeps its existing request/response protocol.
			http := dialClient(t, entries[0])
			http.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
			r := bufio.NewReader(http)
			line, err := r.ReadString('\n')
			if err != nil || !strings.Contains(line, "200") {
				t.Fatalf("HTTP CONNECT: %q %v", line, err)
			}
			for {
				line, err = r.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				if line == "\r\n" {
					break
				}
			}
			http.Write([]byte("http-over-kcp"))
			expectBytes(t, r, []byte("http-over-kcp"))
			http.Close()
			// Fixed TCP forwarding uses the same KCP pool.
			fixed := dialClient(t, entries[1])
			fixed.Write([]byte("fixed"))
			expectBytes(t, fixed, []byte("fixed"))
			fixed.Close()
			udpControl := dialClient(t, entries[0])
			clientAuth(t, udpControl, "")
			clientRequest(t, udpControl, 3, ":0", true)
			relay := clientReply(t, udpControl, 0)
			relay.IP = net.IPv4(127, 0, 0, 1)
			u := forwardUDPClient(t)
			for _, data := range [][]byte{nil, []byte("udp-over-kcp"), bytes.Repeat([]byte("large"), 12000)} {
				udpRoundTrip(t, u, relay, udpTarget, data, true)
			}
			udpControl.Close()
			fixedUDP, err := net.ResolveUDPAddr("udp", entries[2])
			if err != nil {
				t.Fatal(err)
			}
			forwardUDPRoundTrip(t, u, fixedUDP, []byte("fixed-udp"))
			want := "transport=kcp+dtls"
			if mode == "native-udp" || mode == "fec-native-udp" {
				want = "transport=dtls"
			}
			if !strings.Contains(server.logs.String(), want) {
				t.Fatalf("missing %s", want)
			}
			// Kill the agent with a live stream: timeout must reach the client,
			// and a replacement agent must replenish the original pool.
			live := dialClient(t, entries[1])
			live.Write([]byte("before-loss"))
			expectBytes(t, live, []byte("before-loss"))
			agent.stop()
			live.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := live.Read(make([]byte, 1)); err == nil {
				t.Fatal("agent death left stream usable")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("agent death did not close client")
			}
			pooled := strings.Count(server.logs.String(), "agent connection pooled:")
			startProcess(t, agentArgs...)
			await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") > pooled }, server.logs.String)
			recovered := dialClient(t, entries[1])
			recovered.Write([]byte("recovered"))
			expectBytes(t, recovered, []byte("recovered"))
			recovered.Close()
		})
	}
}

func TestKCPPoolCancellationAndAuthentication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := defaultKCPSettings()
	cfg.Heartbeat = 50 * time.Millisecond
	cfg.Timeout = time.Second
	ln, err := listenDTLSPool(endpoint{address: "127.0.0.1:0", psk: "kcp-key"}, cfg.MTU)
	if err != nil {
		t.Fatal(err)
	}
	pool := newConnPool()
	defer pool.close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- acceptKCPPoolConns(ctx, ln, pool, nil, cfg) }()
	badCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	bad, err := dialDTLSPool(badCtx, ln.Addr().String(), testDTLSOptions(t, "wrong-key"))
	stop()
	if bad != nil {
		bad.Close()
	}
	if err == nil || pool.size() != 0 {
		t.Fatal("wrong PSK reached pool")
	}
	opts, _ := newProxyOptions("", time.Second)
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- runKCPAgent(ctx, endpoint{address: ln.Addr().String(), psk: "kcp-key"}, 1, cfg, "", opts, nil)
	}()
	claimed := pool.pick(5 * time.Second)
	if claimed == nil {
		t.Fatal("no KCP pool connection")
	}
	if err := openTCPTunnel(claimed, tcpEcho(t, false)); err != nil {
		t.Fatal(err)
	}
	claimed.Write([]byte("active"))
	expectBytes(t, claimed, []byte("active"))
	await(t, func() bool { return pool.size() == 1 }, func() string { return "active session did not replenish pool" })
	cancel()
	for _, ch := range []<-chan error{serverDone, agentDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation leaked a session")
		}
	}
	claimed.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(claimed, make([]byte, 1)); err == nil {
		t.Fatal("active session survived cancellation")
	}
}

func TestKCPServerRestartAndBareTarget(t *testing.T) {
	target := tcpEcho(t, true)
	server := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0", "-accept", "kcp+dtls://127.0.0.1:0?psk=restart-key",
		"-kcp-heartbeat", "100ms", "-kcp-timeout", "1s")
	poolAddr := listenerAddress(t, server, "agent")
	entry := listenerAddress(t, server, "user")
	agent := startProcess(t, "agent", "-connect", "kcp+dtls://"+poolAddr+"?psk=restart-key", "-target", target,
		"-pool", "2", "-kcp-heartbeat", "100ms", "-kcp-timeout", "1s")
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)
	// Leave one active stream and one idle stream when the server dies.
	live := dialClient(t, entry)
	live.Write([]byte("incomplete"))
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") >= 3 }, server.logs.String)
	server.stop()
	await(t, func() bool { return strings.Contains(agent.logs.String(), "idle connection lost:") }, agent.logs.String)
	restarted := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0", "-accept", "kcp+dtls://"+poolAddr+"?psk=restart-key",
		"-kcp-heartbeat", "100ms", "-kcp-timeout", "1s")
	await(t, func() bool { return strings.Count(restarted.logs.String(), "agent connection pooled:") == 2 }, func() string {
		return restarted.logs.String() + agent.logs.String()
	})
	recovered := dialClient(t, listenerAddress(t, restarted, "user"))
	recovered.Write([]byte("after-restart"))
	recovered.CloseWrite()
	expectBytes(t, recovered, []byte("reply:after-restart"))
	recovered.Close()
	live.Close()
}
