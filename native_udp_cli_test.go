package main

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNativeUDPDualPoolCLI(t *testing.T) {
	for _, role := range []string{"server", "agent"} {
		for _, datagramFirst := range []bool{false, true} {
			option, address := "-accept", ":10086"
			args := []string{"-listen", "socks5://:1080", "-listen", "udp://:500?to=charon:500"}
			if role == "agent" {
				option, address = "-connect", "server.example:10086"
				args = []string{"-pool", "7", "-udp-pool", "9", "-redirect", "udp://charon:500=10.1.2.3:500"}
			}
			stream, datagram := "tls://"+address+"?psk=stream-key", "dtls://"+address+"?psk=udp-key"
			first, second := stream, datagram
			if datagramFirst {
				first, second = datagram, stream
			}
			args = append(args, option, first, option, second, "-udp-mtu", "1400")
			c, err := parseCommand(role, args, io.Discard)
			if err != nil {
				t.Fatalf("%s, datagram first %v: %v", role, datagramFirst, err)
			}
			if len(c.tunnels) != 2 || c.tunnel.scheme != "tls" || c.tunnel.psk != "stream-key" || c.udpTransport != "udp" || c.udpMTU != 1400 {
				t.Fatal("dual pool configuration parsed incorrectly")
			}
			if role == "agent" && (c.pool != 7 || c.udpPool != 9 || c.proxy == nil) {
				t.Fatal("agent pool sizes or routed mode parsed incorrectly")
			}
		}
	}
}

func TestNativeUDPOnlyAndTransportCLI(t *testing.T) {
	for _, transport := range []string{"", "udp"} {
		args := []string{"-listen", "udp://:500?to=charon:500", "-accept", "dtls://:10086?psk=key"}
		if transport != "" {
			args = append(args, "-udp-transport", transport)
		}
		c, err := parseCommand("server", args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.tunnels) != 1 || c.tunnel.scheme != "" || c.udpTransport != "udp" || c.entries[0].proxy == nil {
			t.Fatal("DTLS-only server parsed incorrectly")
		}
	}
	c, err := parseCommand("agent", []string{"-connect", "dtls://host:10086?psk=key"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.tunnel.scheme != "" || c.pool != 5 || c.udpPool != 20 || c.udpMTU != defaultDatagramMTU || c.proxy == nil {
		t.Fatal("DTLS-only agent defaults parsed incorrectly")
	}
	for _, transport := range []string{"", "tcp"} {
		args := []string{"-listen", "socks5://:1080", "-accept", ":10086"}
		if transport != "" {
			args = append(args, "-udp-transport", transport)
		}
		c, err := parseCommand("server", args, io.Discard)
		if err != nil || c.udpTransport != "tcp" || len(c.tunnels) != 1 || c.tunnel.scheme != "tcp" {
			t.Fatalf("legacy TCP pool transport %s: %v", transport, err)
		}
	}
	for _, transport := range []string{"tcp", "udp"} {
		c, err := parseCommand("server", []string{
			"-listen", "socks5://:1080", "-accept", "tls://:10086?psk=key",
			"-accept", "dtls://:10086?psk=key", "-udp-transport", transport,
		}, io.Discard)
		if err != nil || c.udpTransport != transport {
			t.Fatalf("explicit dual-pool transport %s: %v", transport, err)
		}
	}
}

func TestNativeUDPEndpointKeyFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp key.txt")
	if err := os.WriteFile(path, []byte("  datagram-key  \nunused"), 0600); err != nil {
		t.Fatal(err)
	}
	value := "dtls://[::1]:10086?psk=" + url.QueryEscape("@"+path)
	for _, option := range []string{"accept", "connect"} {
		ep, err := parseEndpoint(value, option)
		if err != nil || ep.psk != "datagram-key" || ep.scheme != "dtls" || ep.address != "[::1]:10086" {
			t.Fatalf("DTLS PSK file for %s: %v", option, err)
		}
	}
	for _, option := range []string{"listen", "target"} {
		if _, err := parseEndpoint(value, option); err == nil {
			t.Fatalf("DTLS unexpectedly accepted as %s", option)
		}
	}
}

func TestNativeUDPMTUBounds(t *testing.T) {
	for _, mtu := range []int{minDatagramMTU, maxDatagramMTU} {
		c, err := parseCommand("agent", []string{"-connect", "dtls://host:10086?psk=key", "-udp-mtu", strconv.Itoa(mtu)}, io.Discard)
		if err != nil || c.udpMTU != mtu {
			t.Fatalf("MTU bound %d: %v", mtu, err)
		}
	}
	for _, mtu := range []int{minDatagramMTU - 1, maxDatagramMTU + 1} {
		if _, err := parseCommand("agent", []string{"-connect", "dtls://host:10086?psk=key", "-udp-mtu", strconv.Itoa(mtu)}, io.Discard); err == nil {
			t.Fatalf("invalid MTU %d accepted", mtu)
		}
	}
}

func TestRejectInvalidNativeUDPCLI(t *testing.T) {
	for _, args := range [][]string{
		{"server", "-listen", "udp://:500?to=charon:500", "-accept", "dtls://:10086"},
		{"server", "-listen", "udp://:500?to=charon:500", "-accept", "dtls://:10086?psk="},
		{"server", "-listen", "udp://:500?to=charon:500", "-accept", "dtls://user:pass@:10086?psk=key"},
		{"server", "-listen", "udp://:500?to=charon:500", "-accept", "dtls://:10086?psk=key", "-udp-transport", "tcp"},
		{"server", "-listen", "socks5://:1080", "-accept", "dtls://:10086?psk=key"},
		{"server", "-listen", "tcp://:8080?to=web:80", "-accept", "dtls://:10086?psk=key"},
		{"server", "-listen", "tcp://:8080", "-accept", ":10086", "-accept", "dtls://:10086?psk=key"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-accept", "tls://:10087?psk=key"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-transport", "udp"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-transport", "invalid"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-transport", "auto"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-accept", "dtls://:10086?psk=key", "-udp-transport", "auto"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-transport", ""},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-mtu", "1200"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-udp-pool", "20"},
		{"agent", "-connect", "host:10086", "-connect", "host:10087"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-connect", "dtls://host:10087?psk=key"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-target", "127.0.0.1:80"},
		{"agent", "-connect", "host:10086", "-udp-pool", "20"},
		{"agent", "-connect", "host:10086", "-udp-mtu", "1200"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-udp-pool", "0"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-udp-mtu", "575"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-udp-mtu", "8193"},
		{"agent", "-connect", "dtls://host:10086?psk=key", "-udp-transport", "udp"},
	} {
		if _, err := parseCommand(args[0], args[1:], io.Discard); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestNativeUDPDiagnosticsHideSecrets(t *testing.T) {
	const secret = "PRIVATE_DTLS_CREDENTIAL"
	for _, args := range [][]string{
		{"agent", "-connect", "dtls://host:10086?psk=" + secret, "-help"},
		{"agent", "-connect", "dtls://host:10086?psk=" + secret + "%GG"},
		{"agent", "-connect", "dtls://host:10086?psk=@" + secret},
		{"agent", "-connect", "dtls://host:10086?psk=" + secret, "-connect", "dtls://host:10087?psk=" + secret},
		{"agent", "-connect", "dtls://host:10086?psk=" + secret, "-udp-pool", secret},
		{"agent", "-connect", "dtls://host:10086?psk=" + secret, "-udp-mtu", secret},
		{"server", "-listen", "udp://:500?to=charon:500", "-accept", "dtls://:10086?psk=" + secret, "-udp-transport", secret},
	} {
		var out bytes.Buffer
		err := runCLI(args, &out)
		result := out.String()
		if err != nil {
			result += err.Error()
		}
		if strings.Contains(result, secret) {
			t.Fatal("DTLS diagnostic exposed secret")
		}
	}
}
