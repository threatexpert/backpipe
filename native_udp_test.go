package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
)

func TestNativeUDPMixedEntries(t *testing.T) {
	udpTarget := udpEcho(t)
	tcpTarget := tcpEcho(t, false)
	server := startProcess(t, "server",
		"-listen", "udp://127.0.0.1:0?to=charon.invalid:4500",
		"-listen", "socks5://127.0.0.1:0",
		"-listen", "socks5s://127.0.0.1:0?psk=native-entry-key",
		"-accept", "tls://127.0.0.1:0?psk=native-pool-key",
		"-accept", "dtls://127.0.0.1:0?psk=native-pool-key")
	entries := entryAddresses(t, server, 3)
	agent := startProcess(t, "agent",
		"-connect", "tls://"+listenerAddress(t, server, "agent")+"?psk=native-pool-key",
		"-connect", "dtls://"+listenerAddress(t, server, "UDP agent")+"?psk=native-pool-key",
		"-pool", "1", "-udp-pool", "1", "-udp-mtu", "900",
		"-redirect", "udp://charon.invalid:4500="+udpTarget.String())
	await(t, func() bool { return strings.Contains(server.logs.String(), "UDP agent session pooled:") }, server.logs.String)
	relay, err := net.ResolveUDPAddr("udp4", entries[0])
	if err != nil {
		t.Fatal(err)
	}
	raw := forwardUDPClient(t)
	for _, payload := range [][]byte{nil, []byte("native-UDP"), bytes.Repeat([]byte("x"), 1300), bytes.Repeat([]byte("z"), 60000)} {
		forwardUDPRoundTrip(t, raw, relay, payload)
	}
	for i, address := range entries[1:] {
		proxyURL := "socks5://" + address
		if i == 1 {
			proxyURL = "socks5s://" + address + "?psk=native-entry-key"
		}
		cfg, err := apps.ParseProxyURL(io.Discard, proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		for _, network := range []string{"udp", "tcp"} {
			target := tcpTarget
			if network == "udp" {
				target = udpTarget.String()
			}
			c, err := apps.NewSocks5Client(cfg).DialTimeout(network, target, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte(network), 6000)
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, c, payload)
		}
	}
	await(t, func() bool {
		return strings.Count(server.logs.String(), "UDP agent session pooled:") >= 4 &&
			strings.Count(server.logs.String(), "agent connection pooled:") >= 3
	}, server.logs.String)
	if !strings.Contains(server.logs.String(), "transport=dtls") || !strings.Contains(agent.logs.String(), "transport=dtls") {
		t.Fatal("UDP transport not reported as DTLS")
	}
	if strings.Contains(server.logs.String(), "transport=tcp") {
		t.Fatal("UDP unexpectedly used TCP despite configured DTLS")
	}
}

func TestNativeUDPOnlyFixedPortsAndTimeout(t *testing.T) {
	target, observations := forwardObservedUDPEcho(t)
	server := startProcess(t, "server",
		"-listen", "udp://127.0.0.1:0?to=charon.invalid:500",
		"-listen", "udp://127.0.0.1:0?to=charon.invalid:4500",
		"-accept", "dtls://127.0.0.1:0?psk=udp-only-key", "-udp-timeout", "1s")
	entries := entryAddresses(t, server, 2)
	startProcess(t, "agent", "-connect", "dtls://"+listenerAddress(t, server, "UDP agent")+"?psk=udp-only-key",
		"-udp-pool", "1", "-udp-timeout", "1s",
		"-redirect", "udp://charon.invalid:500="+target.String(),
		"-redirect", "udp://charon.invalid:4500="+target.String())
	client := forwardUDPClient(t)
	var sources []string
	for _, entry := range entries {
		relay, err := net.ResolveUDPAddr("udp4", entry)
		if err != nil {
			t.Fatal(err)
		}
		forwardUDPRoundTrip(t, client, relay, []byte("same-client-distinct-entry"))
		select {
		case observation := <-observations:
			sources = append(sources, observation.source)
		case <-time.After(3 * time.Second):
			t.Fatal("missing UDP exit observation")
		}
	}
	if sources[0] == sources[1] {
		t.Fatal("distinct fixed ports shared one exit association")
	}
	await(t, func() bool { return strings.Count(server.logs.String(), "UDP forward ended:") >= 2 }, server.logs.String)
	await(t, func() bool { return strings.Contains(server.logs.String(), "relays=0 udp-idle=1") }, server.logs.String)
}

func TestUDPTransportDoesNotFallBackWhenPoolUnavailable(t *testing.T) {
	tcp := newConnPool()
	defer tcp.close()
	server, peer := net.Pipe()
	defer peer.Close()
	tcp.add(server)
	udp := newDatagramPool()
	defer udp.close()
	options, _ := newProxyOptions("", time.Second)
	options.udpTransport, options.udpPool = "udp", udp
	options.poolWait = 50 * time.Millisecond
	if c := selectUDPTunnel(context.Background(), tcp, options); c != nil {
		c.Close()
		t.Fatal("UDP pool exhaustion silently selected another transport")
	}
	if tcp.size() != 1 {
		t.Fatal("UDP pool exhaustion consumed a TCP connection")
	}
	options.poolWait = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c := selectUDPTunnel(ctx, tcp, options); c != nil {
		c.Close()
		t.Fatal("canceled UDP wait selected a session")
	}
}

func TestExplicitTCPUDPTransportWithDTLSConfigured(t *testing.T) {
	target := udpEcho(t)
	server := startProcess(t, "server", "-listen", "udp://127.0.0.1:0?to="+target.String(),
		"-accept", "127.0.0.1:0", "-accept", "dtls://127.0.0.1:0?psk=unused-udp-key", "-udp-transport", "tcp")
	startProcess(t, "agent", "-connect", listenerAddress(t, server, "agent"), "-pool", "1")
	relay, err := net.ResolveUDPAddr("udp4", listenerAddress(t, server, "user"))
	if err != nil {
		t.Fatal(err)
	}
	forwardUDPRoundTrip(t, forwardUDPClient(t), relay, []byte("explicit-old-transport"))
	if !strings.Contains(server.logs.String(), "transport=tcp") {
		t.Fatal("explicit TCP carrier was not used")
	}
}

func TestUDPTransportDoesNotFallBackAfterActivationFailure(t *testing.T) {
	tcp := newConnPool()
	defer tcp.close()
	stream, peer := net.Pipe()
	defer peer.Close()
	tcp.add(stream)
	udp := newDatagramPool()
	defer udp.close()
	session, _, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{
		Prepare: func(*datagramSession) (func(), error) {
			return nil, errors.New("UDP exit cannot be opened")
		},
	}, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := session.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	udp.add(session)
	options, _ := newProxyOptions("", time.Second)
	options.udpTransport, options.udpPool = "udp", udp
	options.poolWait = time.Second
	if c := selectUDPTunnel(ctx, tcp, options); c != nil {
		c.Close()
		t.Fatal("failed UDP activation silently selected another transport")
	}
	if tcp.size() != 1 {
		t.Fatal("failed UDP activation consumed a TCP connection")
	}
	select {
	case <-session.Done():
	default:
		t.Fatal("failed UDP session was not closed")
	}
}

func TestConfiguredServerBindFailureReleasesBothPools(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	reserved.Close()
	config := &commandConfig{
		tunnels: []endpoint{
			{scheme: "tcp", address: address},
			{scheme: "dtls", address: address, psk: "rollback-test-key"},
		},
		udpMTU:  defaultDatagramMTU,
		entries: []entryConfig{{endpoint: endpoint{scheme: "udp", address: "127.0.0.1:-1"}}},
	}
	if err := runConfiguredServer(config); err == nil || !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("startup should fail at client entry: %v", err)
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TCP pool left bound after failed startup: %v", err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("DTLS pool left bound after failed startup: %v", err)
	}
	udp.Close()
}
