package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/secure"
)

// Configure the peer using gonc's public API independently of backpipe's helper.
func goncTLSForTest(t *testing.T, key string, client bool) *secure.NegotiationConfig {
	t.Helper()
	cert, err := secure.GenerateECDSACertificate("localhost", key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := secure.NewNegotiationConfig()
	cfg.IsClient, cfg.SecureLayer, cfg.KeyType, cfg.Key = client, "tls13", "PSK", key
	cfg.Certs, cfg.ErrorOnFailKeyingMaterial = []tls.Certificate{*cert}, true
	return cfg
}

func TestGoncPoolAndEntryInteroperability(t *testing.T) {
	const key = "same-gonc-key"
	server := startProcess(t, "server", "-listen", "socks5s://127.0.0.1:0?psk="+key, "-accept", "tls://127.0.0.1:0?psk="+key)
	poolAddr := listenerAddress(t, server, "agent")
	entryAddr := listenerAddress(t, server, "user")

	// Verify server-side mutual authentication: this client trusts the correct
	// server key but presents a certificate derived from a different key.
	bad := goncTLSForTest(t, key, true)
	bad.Certs = goncTLSForTest(t, "wrong-client-certificate", true).Certs
	c, err := secure.DoNegotiation(bad, dialClient(t, poolAddr), io.Discard)
	if err == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("pool accepted a client with the wrong certificate")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("pool did not reject the wrong client certificate")
		}
	}
	if strings.Contains(server.logs.String(), "agent connection pooled:") {
		t.Fatal("unauthenticated connection entered pool")
	}

	// A gonc TLS client enters the pool without application registration, then uses
	// gonc's handler. The user also connects through gonc's encrypted SOCKS API.
	poolConn, err := secure.DoNegotiation(goncTLSForTest(t, key, true), dialClient(t, poolAddr), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer poolConn.Close()
	await(t, func() bool { return strings.Contains(server.logs.String(), "agent connection pooled:") }, server.logs.String)
	done := make(chan struct{})
	go func() {
		defer close(done)
		apps.ServeTunnelConn(&apps.Socks5uConfig{Logger: log.New(io.Discard, "", 0)}, poolConn)
	}()
	t.Cleanup(func() {
		poolConn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("gonc tunnel handler did not close")
		}
	})
	config, err := apps.ParseProxyURL(io.Discard, "socks5s://"+entryAddr+"?psk="+key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := apps.NewSocks5Client(config).DialTimeout("tcp", tcpEcho(t, false), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("gonc-entry-and-pool")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, client, payload)
}

func TestAgentConnectsToGoncTLSServer(t *testing.T) {
	const key = "gonc-server-key"
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	startProcess(t, "agent", "-connect", "tls://"+ln.Addr().String()+"?psk="+key, "-target", tcpEcho(t, false), "-pool", "1")
	cfg := goncTLSForTest(t, key, false)
	accept := func() *secure.NegotiatedConn {
		t.Helper()
		ln.SetDeadline(time.Now().Add(5 * time.Second))
		raw, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { raw.Close() })
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, err := secure.DoNegotiation(cfg, raw, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	c := accept()
	payload := []byte("gonc-server-to-agent")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, c, payload)
	// Activation must replenish the pool while the first session remains open.
	second := accept()
	if _, err := second.Write(payload); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, second, payload)
}
