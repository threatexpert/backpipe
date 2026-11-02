package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSharedDTLSCLI(t *testing.T) {
	for _, role := range []string{"server", "agent"} {
		base, option := []string{"-listen", "socks5://:1080"}, "-accept"
		if role == "agent" {
			base, option = nil, "-connect"
		}
		args := append(append([]string{}, base...), option, "kcp+dtls://127.0.0.1:10087?psk=key", "-kcp-native-udp", "-udp-mtu", "900")
		if role == "agent" {
			args = append(args, "-udp-pool", "3")
		}
		cfg, err := parseCommand(role, args, io.Discard)
		if err != nil {
			t.Fatal(role, err)
		}
		if !cfg.sharedDTLS || len(cfg.tunnels) != 2 || cfg.udpTransport != "udp" || cfg.udpMTU != 900 {
			t.Fatalf("%s did not enable shared native pool", role)
		}
		if cfg.tunnels[1].scheme != "dtls" || cfg.tunnels[1].address != cfg.tunnel.address || cfg.tunnels[1].psk != cfg.tunnel.psk {
			t.Fatal("implicit native endpoint did not inherit address and PSK")
		}
		if _, err := parseCommand(role, append(args, option, "dtls://127.0.0.1:10088?psk=key"), io.Discard); err == nil {
			t.Fatal("shared mode accepted a second native endpoint")
		}
		for _, endpoint := range []string{"tcp://127.0.0.1:10087", "tls://127.0.0.1:10087?psk=key", "dtls://127.0.0.1:10087?psk=key"} {
			for _, flag := range []string{"-kcp-native-udp", "-kcp-native-udp=false"} {
				if _, err := parseCommand(role, append(append([]string{}, base...), option, endpoint, flag), io.Discard); err == nil {
					t.Fatal("shared mode accepted without KCP", role, endpoint)
				}
			}
		}
	}
}

func TestSharedDTLSRecordClassification(t *testing.T) {
	for _, magic := range [][]byte{kcpMagic, datagramMagic[:]} {
		t.Run(string(magic[:3]), func(t *testing.T) {
			raw, peer := newTestRecordPipe()
			defer raw.Close()
			defer peer.Close()
			first := append(bytes.Clone(magic), 1, 2, 3, 4)
			second := append(bytes.Clone(magic), 9, 8, 7, 6)
			peer.Write(first)
			peer.Write(second)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, native, err := classifyDTLSCarrier(ctx, raw)
			if err != nil || native != bytes.Equal(magic, datagramMagic[:]) {
				t.Fatalf("classification: %t %v", native, err)
			}
			if _, err := conn.Read(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal("short buffer consumed the first record", err)
			}
			for _, want := range [][]byte{first, second} {
				buf := make([]byte, 100)
				n, err := conn.Read(buf)
				if err != nil || !bytes.Equal(buf[:n], want) {
					t.Fatalf("record boundaries changed: %x %v", buf[:n], err)
				}
			}
		})
	}
	for _, record := range [][]byte{nil, []byte("BPK"), []byte("BPK\x02x"), []byte("unknown")} {
		raw, peer := newTestRecordPipe()
		peer.Write(record)
		_, _, err := classifyDTLSCarrier(context.Background(), raw)
		raw.Close()
		peer.Close()
		if err == nil {
			t.Fatalf("accepted unknown/truncated record: %x", record)
		}
	}
}

func TestSharedDTLSClassificationTimeout(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		raw, peer := newTestRecordPipe()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		if canceled {
			cancel()
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if _, _, err := classifyDTLSCarrier(ctx, raw); err == nil {
				t.Error("silent peer was accepted")
			}
		}()
		waitKCPTestDone(t, done)
		cancel()
		raw.Close()
		peer.Close()
	}
}

func TestSharedDTLSBindRollback(t *testing.T) {
	reserved, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.LocalAddr().String()
	reserved.Close()
	cfg, err := parseCommand("server", []string{"-listen", "socks5://127.0.0.1:0", "-accept", "kcp+dtls://" + address + "?psk=key", "-kcp-native-udp"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg.entries[0].endpoint.address = "127.0.0.1:-1"
	if err := runConfiguredServer(cfg); err == nil || !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("expected entry bind failure: %v", err)
	}
	rebound, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal("shared pool left bound after startup failure", err)
	}
	rebound.Close()
}

func TestSharedDTLSAuthenticationAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := listenDTLSPool(endpoint{address: "127.0.0.1:0", psk: "shared-key"}, defaultDatagramMTU)
	if err != nil {
		t.Fatal(err)
	}
	streams, datagrams := newConnPool(), newDatagramPool()
	defer streams.close()
	defer datagrams.close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := acceptSharedDTLSPoolConns(ctx, ln, streams, datagrams, nil, defaultKCPSettings(), defaultDatagramMTU); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { cancel(); ln.Close(); waitKCPTestDone(t, done) })
	badCtx, stop := context.WithTimeout(ctx, time.Second)
	bad, err := dialDTLSPool(badCtx, ln.Addr().String(), testDTLSOptions(t, "wrong-key"))
	stop()
	if bad != nil {
		bad.Close()
	}
	if err == nil {
		t.Fatal("shared listener accepted wrong PSK")
	}

	for _, prefix := range []string{"unknown", "BPK\x02\x01", "BPD", "BPK\x01\xff", "BPD\x01\xff\x00"} {
		dialCtx, stop := context.WithTimeout(ctx, time.Second)
		conn, err := dialDTLSPool(dialCtx, ln.Addr().String(), testDTLSOptions(t, "shared-key"))
		stop()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte(prefix)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		// A recognized protocol may send its own READY/hello concurrently
		// with rejecting the malformed peer record. Drain that preface and
		// require prompt closure, rather than assuming the first read is EOF.
		for err == nil {
			_, err = conn.Read(make([]byte, maxDatagramMTU))
		}
		conn.Close()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("unknown protocol was not promptly closed")
		}
	}
	if streams.size() != 0 || datagrams.size() != 0 {
		t.Fatal("invalid peer entered a pool")
	}

	// An authenticated peer that never sends its first record must not hold
	// shutdown hostage, nor share a reader with a prematurely started protocol.
	dialCtx, stop := context.WithTimeout(ctx, time.Second)
	silent, err := dialDTLSPool(dialCtx, ln.Addr().String(), testDTLSOptions(t, "shared-key"))
	stop()
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	cancel()
	waitKCPTestDone(t, done)
}

func TestSharedDTLSLegacyAgents(t *testing.T) {
	nativeBinary := os.Getenv("BACKPIPE_LEGACY_BINARY")
	if nativeBinary == "" {
		t.Skip("set BACKPIPE_LEGACY_BINARY to a v1.4.2 executable")
	}
	startLegacy := func(t *testing.T, binary string, args ...string) {
		t.Helper()
		p := &testProcess{done: make(chan struct{})}
		p.cmd = exec.Command(binary, args...)
		p.cmd.Stdout, p.cmd.Stderr = &p.logs, &p.logs
		if err := p.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { p.cmd.Wait(); close(p.done) }()
		t.Cleanup(func() {
			p.stop()
			if t.Failed() {
				t.Log(p.logs.String())
			}
		})
	}
	for _, fec := range []bool{false, true} {
		name, env := "kcp-v1.5", "BACKPIPE_LEGACY_KCP_BINARY"
		if fec {
			name, env = "fec-v1.6", "BACKPIPE_LEGACY_KCP_FEC_BINARY"
		}
		t.Run(name, func(t *testing.T) {
			binary := os.Getenv(env)
			if binary == "" {
				t.Skip("set " + env + " to the matching old executable")
			}
			target, udpTarget := tcpEcho(t, true), udpEcho(t)
			args := []string{"server", "-listen", "tcp://127.0.0.1:0?to=" + target,
				"-listen", "udp://127.0.0.1:0?to=" + udpTarget.String(), "-accept", "kcp+dtls://127.0.0.1:0?psk=shared-compat", "-kcp-native-udp"}
			if fec {
				args = append(args, "-kcp-fec", "10:3")
			}
			server := startProcess(t, args...)
			address := listenerAddress(t, server, "agent")
			if address != listenerAddress(t, server, "UDP agent") {
				t.Fatal("shared listener opened two ports")
			}
			kcpArgs := []string{"agent", "-connect", "kcp+dtls://" + address + "?psk=shared-compat", "-pool", "1"}
			if fec {
				kcpArgs = append(kcpArgs, "-kcp-fec", "10:3")
			}
			// Old peers use their existing protocol independently at the same
			// destination; they do not know the new CLI convenience switch.
			startLegacy(t, binary, kcpArgs...)
			startLegacy(t, nativeBinary, "agent", "-connect", "dtls://"+address+"?psk=shared-compat", "-udp-pool", "1")
			entries := entryAddresses(t, server, 2)
			client := dialClient(t, entries[0])
			payload := bytes.Repeat([]byte("shared-old-agent"), 10000)
			if err := writeAll(client, payload); err != nil {
				t.Fatal(err)
			}
			client.CloseWrite()
			expectBytes(t, client, append([]byte("reply:"), payload...))
			client.Close()
			udp, err := net.ResolveUDPAddr("udp", entries[1])
			if err != nil {
				t.Fatal(err)
			}
			forwardUDPRoundTrip(t, forwardUDPClient(t), udp, bytes.Repeat([]byte("native"), 9000))
		})
	}
}
