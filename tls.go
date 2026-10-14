package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

// Both the pool and SOCKS entry use gonc's certificate derivation and mutual
// authentication. Only the application protocol after the TLS handshake differs.
type tlsPSKConfig struct {
	config *tls.Config
	client bool
}

type tlsPSKConn struct {
	*tls.Conn
	KeyingMaterial [32]byte
}

func newTLSPSKConfig(psk string, client bool) (*tlsPSKConfig, error) {
	if psk == "" {
		return nil, fmt.Errorf("TLS requires a nonempty PSK")
	}
	cert, err := secure.GenerateECDSACertificate("localhost", psk)
	if err != nil {
		return nil, fmt.Errorf("cannot create TLS certificate")
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		// gonc authenticates the PSK-derived public key instead of a CA or hostname.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: secure.VerifyPeerCertificateByPSK(psk),
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
		// TLS 1.2 uses ephemeral key exchange and authenticated encryption only.
		// TLS 1.3 cipher selection is managed by crypto/tls independently.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if !client {
		cfg.ClientAuth = tls.RequireAnyClientCert
	}
	return &tlsPSKConfig{config: cfg, client: client}, nil
}

func negotiateTLSPSK(cfg *tlsPSKConfig, raw net.Conn) (*tlsPSKConn, error) {
	setKeepalive(raw)
	var conn *tls.Conn
	if cfg.client {
		conn = tls.Client(raw, cfg.config)
	} else {
		conn = tls.Server(raw, cfg.config)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	state := conn.ConnectionState()
	key, err := state.ExportKeyingMaterial("EXPERIMENTAL-SERVER-KEY", nil, 32)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to export keying material: %w", err)
	}
	result := &tlsPSKConn{Conn: conn}
	copy(result.KeyingMaterial[:], key)
	return result, nil
}

func (c *tlsPSKConn) description() string {
	state := c.ConnectionState()
	return tls.VersionName(state.Version) + ", " + tls.CipherSuiteName(state.CipherSuite)
}
