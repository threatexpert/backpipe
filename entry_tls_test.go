package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/secure"
)

func TestGoncEncryptedEntry(t *testing.T) {
	for _, poolTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("poolTLS=%v", poolTLS), func(t *testing.T) {
			keyfile := filepath.Join(t.TempDir(), "entry key.txt")
			if err := os.WriteFile(keyfile, []byte("client-entry-key\n"), 0600); err != nil {
				t.Fatal(err)
			}
			transport := func(addr string) string { return addr }
			if poolTLS {
				poolfile := filepath.Join(t.TempDir(), "pool key.txt")
				if err := os.WriteFile(poolfile, []byte("different-pool-key\n"), 0600); err != nil {
					t.Fatal(err)
				}
				transport = func(addr string) string { return "tls://" + addr + "?psk=" + url.QueryEscape("@"+poolfile) }
			}
			server := startProcess(t, "server", "-listen", "socks5s://user:pass@127.0.0.1:0?psk="+url.QueryEscape("@"+keyfile), "-accept", transport("127.0.0.1:0"))
			poolAddr := listenerAddress(t, server, "agent")
			proxyAddr := listenerAddress(t, server, "user")
			if poolTLS {
				badAgent := startProcess(t, "agent", "-connect", "tls://"+poolAddr+"?psk=wrong-pool-key", "-pool", "1")
				await(t, func() bool { return strings.Contains(badAgent.logs.String(), "TLS handshake failed") }, badAgent.logs.String)
				badAgent.stop()
				if strings.Contains(server.logs.String(), "agent connection pooled:") {
					t.Fatal("wrong pool PSK accepted")
				}
			}
			startProcess(t, "agent", "-connect", transport(poolAddr), "-pool", "2")
			await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)
			target := tcpEcho(t, false)
			for _, badKey := range []string{"wrong-entry-key", "different-pool-key"} {
				cfg, err := apps.ParseProxyURL(io.Discard, "socks5s://user:pass@"+proxyAddr+"?psk="+badKey)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := apps.NewSocks5Client(cfg).DialTimeout("tcp", target, 2*time.Second)
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("wrong entry PSK accepted")
				}
			}
			if n := strings.Count(server.logs.String(), "agent connection pooled:"); n != 2 {
				t.Fatal("TLS rejection consumed pool connections")
			}
			cfg, err := apps.ParseProxyURL(io.Discard, "socks5s://user:pass@"+proxyAddr+"?psk=client-entry-key")
			if err != nil {
				t.Fatal(err)
			}
			client := apps.NewSocks5Client(cfg)
			// Hold multiple TCP and UDP sessions open to exercise distinct TLS
			// exporter keys and replenishment with more sessions than idle slots.
			for i, network := range []string{"tcp", "udp", "udp", "tcp"} {
				dst := target
				if network == "udp" {
					dst = udpEcho(t).String()
				}
				conn, err := client.DialTimeout(network, dst, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				for _, payload := range [][]byte{[]byte(fmt.Sprintf("encrypted-%s-%d", network, i)), bytes.Repeat([]byte("x"), 32000)} {
					if _, err := conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					expectBytes(t, conn, payload)
				}
			}
			await(t, func() bool { return strings.Contains(server.logs.String(), "status: idle=2 relays=4") }, server.logs.String)
			conn, err := client.DialTimeout("tcp", tcpEcho(t, true), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte("tls-eof"))
			cw, ok := conn.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("gonc TLS connection lacks CloseWrite")
			}
			if err := cw.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, conn, []byte("reply:tls-eof"))
			for _, secret := range []string{"client-entry-key", "different-pool-key", "user:pass"} {
				if strings.Contains(server.logs.String(), secret) {
					t.Fatal("server log exposed credentials")
				}
			}
		})
	}
}

func TestEncryptedUDPWireAndSessionKeys(t *testing.T) {
	for _, layer := range []string{"tls12", "tls13"} {
		t.Run(layer, func(t *testing.T) { testEncryptedUDPWireAndSessionKeys(t, layer) })
	}
}

func testEncryptedUDPWireAndSessionKeys(t *testing.T, layer string) {
	server := startProcess(t, "server", "-listen", "socks5s://127.0.0.1:0?psk=wire-test-key", "-accept", "127.0.0.1:0")
	poolAddr := listenerAddress(t, server, "agent")
	proxyAddr := listenerAddress(t, server, "user")
	startProcess(t, "agent", "-connect", poolAddr, "-pool", "2")
	cert, err := secure.GenerateECDSACertificate("localhost", "wire-test-key")
	if err != nil {
		t.Fatal(err)
	}
	cfg := secure.NewNegotiationConfig()
	cfg.IsClient, cfg.SecureLayer, cfg.KeyType, cfg.Key = true, layer, "PSK", "wire-test-key"
	cfg.Certs, cfg.ErrorOnFailKeyingMaterial = []tls.Certificate{*cert}, true
	var keys [][32]byte
	var relays []*net.UDPAddr
	for i := 0; i < 2; i++ {
		c, err := secure.DoNegotiation(cfg, dialClient(t, proxyAddr), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		clientAuth(t, c, "")
		clientRequest(t, c, 3, "0.0.0.0:0", false)
		relays = append(relays, defaultUDPRelay(t, c))
		keys = append(keys, c.KeyingMaterial)
	}
	if keys[0] == keys[1] {
		t.Fatal("UDP sessions share an exporter key")
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	packet := udpPacket(udpEcho(t), []byte("wire-encryption-payload"), false)
	enc, err := secure.NewSecureUDPConn(u, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	// Neither ordinary SOCKS UDP nor a packet encrypted for another TLS
	// session should forward. Follow with a valid packet to verify recovery.
	for _, send := range []func() error{
		func() error { _, err := u.WriteToUDP(packet, relays[0]); return err },
		func() error { _, err := enc.WriteTo(packet, relays[1]); return err },
	} {
		u.SetDeadline(time.Now().Add(150 * time.Millisecond))
		if err := send(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := u.ReadFromUDP(buf); err == nil {
			t.Fatal("invalid encryption was forwarded")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatal(err)
		}
	}
	u.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := enc.WriteTo(packet, relays[0]); err != nil {
		t.Fatal(err)
	}
	n, _, err := u.ReadFromUDP(buf) // Read the actual ciphertext on the socket.
	if err != nil {
		t.Fatal(err)
	}
	if n != 16+len(packet) || bytes.Contains(buf[:n], []byte("wire-encryption-payload")) {
		t.Fatal("UDP reply is not encrypted in gonc wire format")
	}
	block, err := aes.NewCipher(keys[0][:])
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, n-16)
	cipher.NewCTR(block, buf[:16]).XORKeyStream(plain, buf[16:n])
	if !bytes.Equal(plain, packet) {
		t.Fatal("UDP reply cannot be decrypted with the control session's key")
	}
}
