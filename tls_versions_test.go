package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

func TestTLSVersionsAndCipherSuites(t *testing.T) {
	const key = "tls-version-test"
	cert, err := secure.GenerateECDSACertificate("localhost", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []bool{false, true} {
		role := "server"
		if client {
			role = "agent"
		}
		for _, tc := range []struct {
			name                     string
			min, max, version, suite uint16
			badCert                  bool
			reject                   bool
		}{
			{name: "prefer13", min: tls.VersionTLS12, max: tls.VersionTLS13, version: tls.VersionTLS13},
			{name: "aes128", min: tls.VersionTLS12, max: tls.VersionTLS12, version: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			{name: "aes256", min: tls.VersionTLS12, max: tls.VersionTLS12, version: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			{name: "chacha", min: tls.VersionTLS12, max: tls.VersionTLS12, version: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
			{name: "reject10", min: tls.VersionTLS10, max: tls.VersionTLS10, reject: true},
			{name: "reject11", min: tls.VersionTLS11, max: tls.VersionTLS11, reject: true},
			{name: "rejectCBC", min: tls.VersionTLS12, max: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, reject: true},
			{name: "rejectWrongPSK12", min: tls.VersionTLS12, max: tls.VersionTLS12, badCert: true, reject: true},
		} {
			t.Run(role+"/"+tc.name, func(t *testing.T) {
				cfg, err := newTLSPSKConfig(key, client)
				if err != nil {
					t.Fatal(err)
				}
				// Independent peer configuration, including a peer restricted to one suite.
				peerCfg := &tls.Config{
					Certificates:          []tls.Certificate{*cert},
					InsecureSkipVerify:    true,
					VerifyPeerCertificate: secure.VerifyPeerCertificateByPSK(key),
					MinVersion:            tc.min, MaxVersion: tc.max,
				}
				if tc.suite != 0 {
					peerCfg.CipherSuites = []uint16{tc.suite}
				}
				if tc.badCert {
					wrong, err := secure.GenerateECDSACertificate("localhost", "wrong-key")
					if err != nil {
						t.Fatal(err)
					}
					peerCfg.Certificates = []tls.Certificate{*wrong}
				}
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				raw, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				other, err := ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				other.SetDeadline(time.Now().Add(3 * time.Second))
				var peer *tls.Conn
				if client {
					peerCfg.ClientAuth = tls.RequireAnyClientCert
					peer = tls.Server(other, peerCfg)
				} else {
					peer = tls.Client(other, peerCfg)
				}
				done := make(chan error, 1)
				go func() { done <- peer.Handshake() }()
				conn, err := negotiateTLSPSK(cfg, raw)
				peerErr := <-done
				if tc.reject {
					if err == nil {
						t.Fatal("backpipe accepted an incompatible or unauthenticated peer")
					}
					return
				}
				if err != nil || peerErr != nil {
					t.Fatalf("backpipe=%v peer=%v", err, peerErr)
				}
				state := conn.ConnectionState()
				if state.Version != tc.version || (tc.suite != 0 && state.CipherSuite != tc.suite) {
					t.Fatalf("unexpected negotiation: %s", conn.description())
				}
				peerState := peer.ConnectionState()
				exported, err := peerState.ExportKeyingMaterial("EXPERIMENTAL-SERVER-KEY", nil, 32)
				if err != nil || !bytes.Equal(exported, conn.KeyingMaterial[:]) {
					t.Fatalf("UDP exporter mismatch: %v", err)
				}
				t.Log(conn.description())
			})
		}
	}
}

func TestBackpipePoolNegotiatesTLS13(t *testing.T) {
	server := startProcess(t, "server", "-listen", "tcp://127.0.0.1:0", "-accept", "tls://127.0.0.1:0?psk=pool-version-key")
	poolAddr := listenerAddress(t, server, "agent")
	entryAddr := listenerAddress(t, server, "user")
	agent := startProcess(t, "agent", "-connect", "tls://"+poolAddr+"?psk=pool-version-key", "-target", tcpEcho(t, false), "-pool", "1")
	await(t, func() bool { return strings.Contains(agent.logs.String(), "idle connection ready (TLS 1.3,") }, agent.logs.String)
	for range 2 {
		c := dialClient(t, entryAddr)
		defer c.Close()
		payload := []byte("TLS13 pool replenishment")
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		expectBytes(t, c, payload)
	}
	await(t, func() bool { return strings.Count(server.logs.String(), "(TLS 1.3,") >= 3 }, server.logs.String)
}
