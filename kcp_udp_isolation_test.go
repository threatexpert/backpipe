package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"golang.org/x/net/dns/dnsmessage"
)

// Exercise the real SOCKS association, native DTLS pool, UDP exit and DNS wire
// exchange while four KCP streams cannot deliver data. Only the KCP carriers
// are simulated, to inject a deterministic blackhole without OS traffic rules.
// This verifies transport isolation, not bandwidth isolation on a shared WAN.
func TestKCPNativeDNSIndependentOfStalledStreams(t *testing.T) {
	var stalled []*kcpStreamConn
	var writers []<-chan struct{}
	for i := 0; i < 4; i++ {
		var blackhole atomic.Bool
		var dropped atomic.Int64
		a, _, _, _ := testKCPPair(t, func(record []byte) [][]byte {
			if blackhole.Load() && record[4] == kcpPacketFECData {
				dropped.Add(1)
				return nil
			}
			return [][]byte{record}
		}, nil, func(cfg *kcpSettings) {
			cfg.SendWindow, cfg.ReceiveWindow = 1500, 1500
			cfg.FECData, cfg.FECParity = 10, 3
			cfg.Heartbeat, cfg.Timeout = 100*time.Millisecond, 5*time.Second
		})
		blackhole.Store(true)
		written := make(chan struct{})
		stalled = append(stalled, a)
		writers = append(writers, written)
		go func() { a.Write(make([]byte, 8<<20)); close(written) }()
		t.Cleanup(func() { a.abort(net.ErrClosed); waitKCPTestDone(t, written) })
		await(t, func() bool { return dropped.Load() > 0 }, func() string { return "KCP stream did not start transmitting" })
		select {
		case <-written:
			t.Fatal("KCP stream did not stall")
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	native := newDatagramPool()
	t.Cleanup(native.close)
	stream := newConnPool()
	t.Cleanup(stream.close)
	ep := endpoint{address: "127.0.0.1:0", psk: "dns-isolation-key"}
	ln, err := listenDTLSPool(ep, defaultDatagramMTU)
	if err != nil {
		t.Fatal(err)
	}
	serverDone, agentDone, kcpAgentDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	kcpCfg := defaultKCPSettings()
	go func() {
		defer close(serverDone)
		if err := acceptSharedDTLSPoolConns(ctx, ln, stream, native, nil, kcpCfg, defaultDatagramMTU); err != nil {
			t.Error(err)
		}
	}()
	ep.address = ln.Addr().String()
	go func() {
		defer close(kcpAgentDone)
		proxyOptions, _ := newProxyOptions("", 10*time.Second)
		if err := runKCPAgent(ctx, ep, 1, kcpCfg, "", proxyOptions, nil); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer close(agentDone)
		if err := runDTLSAgent(ctx, ep, 1, defaultDatagramMTU, time.Second*10, nil); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		native.close()
		waitKCPTestDone(t, serverDone)
		waitKCPTestDone(t, agentDone)
		waitKCPTestDone(t, kcpAgentDone)
	})
	await(t, func() bool { return native.size() == 1 && stream.size() == 1 }, func() string { return "shared pools not ready" })

	options, err := newProxyOptions("", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	options.udpTransport, options.udpPool, options.poolWait = "udp", native, time.Second
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		acceptUserConns(proxy, stream, false, entryConfig{proxy: options})
	}()
	t.Cleanup(func() { proxy.Close(); waitKCPTestDone(t, proxyDone) })
	dnsAddress := kcpTestDNSServer(t)
	proxyConfig, err := apps.ParseProxyURL(io.Discard, "socks5://"+proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for association := 0; association < 2; association++ {
		client, err := apps.NewSocks5Client(proxyConfig).DialTimeout("udp", dnsAddress, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		for id := uint16(1); id <= 10; id++ {
			name := dnsmessage.MustNewName("isolation.test.")
			query := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
				Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			}
			wire, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			client.SetDeadline(time.Now().Add(time.Second))
			if _, err := client.Write(wire); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			n, err := client.Read(buf)
			if err != nil {
				t.Fatalf("DNS blocked behind KCP: %v", err)
			}
			var reply dnsmessage.Message
			if err := reply.Unpack(buf[:n]); err != nil || !reply.Response || reply.ID != id || len(reply.Answers) != 1 {
				t.Fatalf("invalid DNS response: %+v, %v", reply, err)
			}
			answer, ok := reply.Answers[0].Body.(*dnsmessage.AResource)
			if !ok || !bytes.Equal(answer.A[:], []byte{192, 0, 2, 1}) {
				t.Fatal("incorrect DNS answer")
			}
		}
		client.Close()
		await(t, func() bool { return native.size() == 1 }, func() string { return "native pool did not replenish" })
	}
	for i, connection := range stalled {
		select {
		case <-connection.done:
			t.Fatal("KCP session died instead of remaining stalled")
		case <-writers[i]:
			t.Fatal("KCP write completed instead of remaining stalled")
		default:
		}
	}
	if stream.size() != 1 {
		t.Fatal("native DNS consumed the KCP pool")
	}
}

func kcpTestDNSServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { conn.Close(); waitKCPTestDone(t, done) })
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(buf[:n]) != nil || len(message.Questions) != 1 {
				continue
			}
			message.Response = true
			message.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
			}}
			wire, err := message.Pack()
			if err == nil {
				conn.WriteToUDP(wire, source)
			}
		}
	}()
	return conn.LocalAddr().String()
}
