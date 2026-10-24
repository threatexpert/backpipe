package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/threatexpert/gonc/v2/secure"
)

func testDTLSOptions(t *testing.T, key string) []dtls.Option {
	t.Helper()
	opts, err := newDTLSPSKOptions(key, defaultDatagramMTU)
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestDTLSMutualPSKAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(server, client []dtls.Option) ([]dtls.Option, []dtls.Option)
		valid  bool
	}{
		{name: "matching keys", valid: true},
		{name: "wrong server key", modify: func(server, client []dtls.Option) ([]dtls.Option, []dtls.Option) {
			server = testDTLSOptions(t, "wrong-server")
			// The server would accept the client. Only the client's mandatory
			// public-key check prevents connecting to this incorrect server.
			server = append(server, dtls.WithVerifyPeerCertificate(secure.VerifyPeerCertificateByPSK("pool-key")))
			return server, client
		}},
		{name: "wrong client key", modify: func(server, client []dtls.Option) ([]dtls.Option, []dtls.Option) {
			client = testDTLSOptions(t, "wrong-client")
			client = append(client, dtls.WithVerifyPeerCertificate(secure.VerifyPeerCertificateByPSK("pool-key")))
			return server, client
		}},
		{name: "missing client certificate", modify: func(server, client []dtls.Option) ([]dtls.Option, []dtls.Option) {
			client = append(client, dtls.WithGetClientCertificate(func(*dtls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &tls.Certificate{}, nil
			}))
			return server, client
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := testDTLSOptions(t, "pool-key"), testDTLSOptions(t, "pool-key")
			if tc.modify != nil {
				server, client = tc.modify(server, client)
			}
			serverOpts := []dtls.ServerOption{dtls.WithClientAuth(dtls.RequireAnyClientCert)}
			for _, opt := range server {
				serverOpts = append(serverOpts, opt)
			}
			ln, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, serverOpts...)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type result struct {
				conn *dtls.Conn
				err  error
			}
			serverDone := make(chan result, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					serverDone <- result{err: err}
					return
				}
				conn := raw.(*dtls.Conn)
				serverDone <- result{conn, conn.HandshakeContext(ctx)}
			}()
			clientConn, clientErr := dialDTLSPool(ctx, ln.Addr().String(), client)
			if clientConn != nil {
				defer clientConn.Close()
			}
			serverResult := <-serverDone
			if serverResult.conn != nil {
				defer serverResult.conn.Close()
			}
			if !tc.valid {
				if clientErr == nil || serverResult.err == nil {
					t.Fatalf("invalid peer authenticated: client=%v server=%v", clientErr, serverResult.err)
				}
				return
			}
			if clientErr != nil || serverResult.err != nil {
				t.Fatalf("handshake failed: client=%v server=%v", clientErr, serverResult.err)
			}
			for _, c := range []*dtls.Conn{clientConn, serverResult.conn} {
				state, ok := c.ConnectionState()
				if !ok || state.CipherSuiteID != dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || len(state.PeerCertificates) == 0 {
					t.Fatalf("missing mutually authenticated ECDHE/GCM: ok=%v cipher=%v certificates=%d", ok, state.CipherSuiteID, len(state.PeerCertificates))
				}
			}
		})
	}
	if _, err := newDTLSPSKOptions("", defaultDatagramMTU); err == nil {
		t.Fatal("accepted empty PSK")
	}
}

func TestDTLSPoolWhitelistBeforeHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := listenDTLSPool(endpoint{address: "127.0.0.1:0", psk: "pool-key"}, defaultDatagramMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pool := newDatagramPool()
	defer pool.close()
	done := make(chan error, 1)
	go func() {
		done <- acceptDTLSPoolConns(ctx, ln, pool, map[string]bool{"192.0.2.1": true}, defaultDatagramMTU)
	}()
	dialCtx, dialCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	conn, err := dialDTLSPool(dialCtx, ln.Addr().String(), testDTLSOptions(t, "pool-key"))
	dialCancel()
	if conn != nil {
		conn.Close()
	}
	if err == nil || pool.size() != 0 {
		t.Fatal("non-whitelisted peer completed handshake or entered pool")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DTLS listener did not stop")
	}
}

func TestDTLSPoolRefillsAndClosesActiveSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := listenDTLSPool(endpoint{address: "127.0.0.1:0", psk: "pool-key"}, defaultDatagramMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pool := newDatagramPool()
	defer pool.close()
	serverDone, agentDone := make(chan error, 1), make(chan error, 1)
	go func() { serverDone <- acceptDTLSPoolConns(ctx, ln, pool, nil, defaultDatagramMTU) }()
	target := udpEcho(t)
	rules := redirectRules{{network: "udp", address: "charon:500"}: target.String()}
	go func() {
		// Different MTUs must agree on the smaller value for both directions.
		agentDone <- runDTLSAgent(ctx, endpoint{address: ln.Addr().String(), psk: "pool-key"}, 2, defaultDatagramMTU+200, 5*time.Second, rules)
	}()
	waitPool := func(want int) {
		t.Helper()
		await(t, func() bool { return pool.size() == want }, func() string { return fmt.Sprintf("pool=%d want=%d", pool.size(), want) })
	}
	waitPool(2)
	lost := pool.tryClaim()
	if lost == nil {
		t.Fatal("missing idle session")
	}
	lost.Close() // A lost idle session must replenish without any OPEN.
	waitPool(2)
	active := pool.tryClaim()
	if active == nil {
		t.Fatal("missing active session")
	}
	defer active.Close()
	openCtx, openCancel := context.WithTimeout(ctx, 3*time.Second)
	err = active.Open(openCtx)
	openCancel()
	if err != nil {
		t.Fatal(err)
	}
	waitPool(2) // Activation must replenish while the first business stays open.
	select {
	case <-active.Done():
		t.Fatal("active session ended during pool refill")
	default:
	}
	other := pool.tryClaim()
	if other == nil {
		t.Fatal("missing replenished session")
	}
	defer other.Close()
	if active.RemoteAddr().String() == other.RemoteAddr().String() {
		t.Fatal("independent UDP sessions reused a local port")
	}
	header, err := udpForwardHeader("charon:500")
	if err != nil {
		t.Fatal(err)
	}
	// Exercise real UDP, destination redirects, and multi-fragment data through
	// the active session while an independent pool is maintained.
	payload := bytes.Repeat([]byte("native-udp"), 500)
	if err := active.WritePacket(append(header, payload...)); err != nil {
		t.Fatal(err)
	}
	active.SetReadDeadline(time.Now().Add(3 * time.Second))
	packet, err := active.ReadPacket(make([]byte, 65535))
	if err != nil {
		t.Fatal(err)
	}
	host, port, reply, err := parseUDPPacket(packet)
	if err != nil || !bytes.Equal(reply, payload) || host != target.IP.String() || port != target.Port {
		t.Fatalf("UDP redirect reply mismatch: source=%s:%d length=%d err=%v", host, port, len(reply), err)
	}
	pool.close()
	select {
	case <-active.Done():
	case <-time.After(time.Second):
		t.Fatal("closing pool left claimed business open")
	}
	if pool.pick(time.Hour) != nil {
		t.Fatal("closed pool returned a session")
	}
	cancel()
	for _, done := range []<-chan error{serverDone, agentDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("DTLS worker did not stop after cancellation")
		}
	}
}
