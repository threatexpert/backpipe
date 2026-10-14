package main

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
