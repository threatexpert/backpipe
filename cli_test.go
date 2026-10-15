package main

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointCredentialsAndKeyFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key with spaces.txt")
	if err := os.WriteFile(path, []byte("  file-key  \nignored second line"), 0600); err != nil {
		t.Fatal(err)
	}
	value := "socks5s://user%3Aname:p%40ss%3Aword@[::1]:1080?psk=" + url.QueryEscape("@"+path)
	c, err := parseCommand("server", []string{"-listen", value, "-accept", "tls://:10086?psk=pool%2Bkey%26value"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.entries[0].proxy.config.Username != "user:name" || c.entries[0].proxy.config.Password != "p@ss:word" || c.entries[0].proxy.entryTLS == nil || c.entries[0].endpoint.psk != "file-key" || c.tunnel.psk != "pool+key&value" || c.entries[0].endpoint.address != "[::1]:1080" {
		t.Fatal("credentials, IPv6 address or separate keys parsed incorrectly")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseEndpoint(value, "listen"); err == nil {
		t.Fatal("empty PSK file accepted")
	}
}

func TestRejectAmbiguousOrInvalidCLI(t *testing.T) {
	for _, value := range []string{
		"socks5://:1080?psk=secret", "socks5s://:1080", "socks5s://:1080?psk=",
		"socks5s://:1080?psk=one&psk=two", "socks5s://:1080?psk=key&unknown=value",
		"socks5://user@:1080", "tcp://user:pass@:1080", "socks5://:1080/path",
		"socks5://:1080#fragment", "socks5://:99999", "socks5://:abc", ":1080",
		"socks5s://:1080?psk=%GG", "socks5://bad%ZZ:pass@:1080",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseEndpoint(value, "listen"); err == nil {
				t.Fatal("invalid listener accepted")
			}
		})
	}
	for _, args := range [][]string{
		{"server", "-accept", ":10086"},
		{"server", "-listen", "tcp://:1080", "-listen", "socks5://:3180", "-accept", ":10086"},
		{"server", "-listen", "socks5://:1080", "-listen", "tcp://:3180", "-accept", ":10086"},
		{"server", "-listen", "socks5s://:1080?psk=key", "-listen", "", "-accept", ":10086"},
		{"-mode", "server", "-left", ":1080", "-right", ":10086"},
		{"server", "-listen", "socks5://:1080", "-accept", ":10086", "-ppv2"},
		{"server", "-listen", "tcp://:1080", "-accept", ":10086", "-socks-server-ip", "127.0.0.1"},
		{"server", "-listen", "tcp://:1080", "-accept", ":10086", "-udp-timeout", "1s"},
		{"agent", "-connect", "host:10086", "-pool", "0"},
		{"agent", "-connect", ":10086"},
		{"agent", "-connect", "host:0"},
		{"agent", "-connect", "host:10086", "-target", ":s5s"},
		{"agent", "-connect", "host:10086", "-target", "udp://host:53"},
		{"agent", "-connect", "host:10086", "-socks5"},
		{"agent", "-connect", "host:10086", "-udp-timeout", "0s"},
		{"agent", "-connect", "host:10086", "extra"},
	} {
		if _, err := parseCommand(args[0], args[1:], io.Discard); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestCLIHelpAndErrorsDoNotExposeSecrets(t *testing.T) {
	secret := "SENSITIVE_VALUE"
	for _, args := range [][]string{
		{"server", "-listen", "socks5s://:1080?psk=" + secret, "-listen", "socks5://user:" + secret + "@127.0.0.1:3180", "-help"},
		{"server", "-listen", "socks5://user:" + secret + "@:1080", "-accept", "tls://:10086?psk=" + secret, "-help"},
		{"server", "-listen", "socks5s://:1080?psk=" + secret + "%GG", "-accept", ":10086"},
		{"agent", "-connect", "host:10086", "-pool", secret},
		{"agent", "-connect", "host:10086", "-" + secret},
	} {
		var out bytes.Buffer
		err := runCLI(args, &out)
		result := out.String()
		if err != nil {
			result += err.Error()
		}
		if strings.Contains(result, secret) {
			t.Fatal("diagnostic exposed secret")
		}
	}
	var out bytes.Buffer
	if err := runCLI([]string{"-help"}, &out); err != nil || !strings.Contains(out.String(), "socks5s://") {
		t.Fatal("missing modern usage")
	}
	if err := runCLI([]string{"-version"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestFixedTargetListenersShareRoutedMode(t *testing.T) {
	c, err := parseCommand("server", []string{
		"-listen", "udp://:500?to=Charon.:00500",
		"-listen", "tcp://127.0.0.1:8080?to=%5B2001:db8::1%5D:80",
		"-listen", "socks5://user:pass@127.0.0.1:3180",
		"-listen", "socks5s://:1080?psk=client-key",
		"-accept", "tls://:10086?psk=pool-key",
		"-socks-server-ip", "192.0.2.1",
		"-udp-timeout", "5m",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.entries) != 4 || c.entries[0].endpoint.target != "charon:500" || c.entries[1].endpoint.target != "[2001:db8::1]:80" {
		t.Fatalf("fixed targets not parsed: %+v", c.entries)
	}
	for i, entry := range c.entries {
		if entry.proxy == nil || entry.proxy.udpTimeout != 5*time.Minute {
			t.Fatalf("entry %d not configured for shared routed mode", i)
		}
		wantServerIP := ""
		if i >= 2 {
			wantServerIP = "192.0.2.1"
		}
		if entry.proxy.config.ServerIP != wantServerIP {
			t.Fatalf("entry %d got SOCKS relay IP %q, want %q", i, entry.proxy.config.ServerIP, wantServerIP)
		}
		if (entry.proxy.entryTLS != nil) != (i == 3) {
			t.Fatalf("entry %d has incorrect entry encryption", i)
		}
	}
	for _, listen := range []string{"udp://:500?to=charon:500", "tcp://:8080?to=web:80"} {
		c, err := parseCommand("server", []string{"-listen", listen, "-accept", ":10086"}, io.Discard)
		if err != nil || c.entries[0].proxy == nil {
			t.Fatalf("standalone fixed listener %q: %v", listen, err)
		}
	}
	c, err = parseCommand("server", []string{"-listen", "tcp://:8080", "-listen", "tcp://:8081", "-accept", ":10086", "-ppv2"}, io.Discard)
	if err != nil || c.entries[0].proxy != nil || c.entries[1].proxy != nil || !c.ppv2 {
		t.Fatalf("bare TCP mode changed: %v", err)
	}
}

func TestRejectInvalidFixedTargetListeners(t *testing.T) {
	for _, value := range []string{
		"udp://:500", "udp://:500?to=", "tcp://:8080?to=", "udp://:500?to=:500",
		"udp://:500?to=charon:0", "udp://:500?to=charon:65536", "tcp://:8080?to=web:abc",
		"udp://:500?to=charon:500&to=charon:501", "tcp://:8080?to=tcp://web:80",
		"udp://:500?to=charon:500&psk=key", "tcp://:8080?to=web:80&unknown=value",
		"socks5://:1080?to=web:80", "socks5s://:1080?psk=key&to=web:80",
		"udp://user:pass@:500?to=charon:500", "udp://:500?to=charon:500%0Atcp://other:80",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := parseEndpoint(value, "listen"); err == nil {
				t.Fatal("invalid fixed-target listener accepted")
			}
		})
	}
	for _, option := range []string{"accept", "connect", "target"} {
		if _, err := parseEndpoint("tcp://127.0.0.1:10086?to=web:80", option); err == nil {
			t.Fatalf("to accepted on -%s", option)
		}
	}
	for _, args := range [][]string{
		{"-listen", "tcp://:8080", "-listen", "udp://:500?to=charon:500", "-accept", ":10086"},
		{"-listen", "tcp://:8080?to=web:80", "-listen", "tcp://:8081", "-accept", ":10086"},
		{"-listen", "tcp://:8080?to=web:80", "-accept", ":10086", "-ppv2"},
		{"-listen", "udp://:500?to=charon:500", "-accept", ":10086", "-ppv2"},
		{"-listen", "udp://:500?to=charon:500", "-accept", ":10086", "-socks-server-ip", "127.0.0.1"},
		{"-listen", "tcp://:8080?to=web:80", "-accept", ":10086", "-socks-server-ip", "127.0.0.1"},
	} {
		if _, err := parseCommand("server", args, io.Discard); err == nil {
			t.Fatalf("invalid fixed listener mode accepted: %v", args)
		}
	}
}
