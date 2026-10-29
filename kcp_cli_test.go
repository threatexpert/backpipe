package main

import (
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestKCPCLICongestionAndFEC(t *testing.T) {
	for _, role := range []string{"server", "agent"} {
		base, option := []string{"-listen", "socks5://:1080"}, "-accept"
		if role == "agent" {
			base, option = nil, "-connect"
		}
		args := append(append([]string{}, base...), option, "kcp+dtls://127.0.0.1:10086?psk=key")
		cfg, err := parseCommand(role, args, io.Discard)
		if err != nil || !cfg.kcp.NoCongestion || cfg.kcp.fecProfile() != "off" {
			t.Fatalf("%s defaults: %v", role, err)
		}
		for _, profile := range []string{"off", "10:3", "4:2", "1:1", "32:32"} {
			cfg, err := parseCommand(role, append(args, "-kcp-nocwnd=false", "-kcp-fec", profile), io.Discard)
			if err != nil || cfg.kcp.NoCongestion || cfg.kcp.fecProfile() != profile {
				t.Fatalf("%s profile %s: %v", role, profile, err)
			}
		}
		for _, profile := range []string{"", "10", "10+3", "0:0", "0:3", "10:0", "-1:3", "33:3", "10:33", "10:3:1", "x:y", "999999999999999999999:3"} {
			if _, err := parseCommand(role, append(args, "-kcp-fec", profile), io.Discard); err == nil {
				t.Fatalf("%s accepted invalid FEC %q", role, profile)
			}
		}
		for _, extra := range [][]string{{"-kcp-nocwnd=false"}, {"-kcp-nocwnd=true"}, {"-kcp-fec", "off"}, {"-kcp-fec", "10:3"}} {
			legacy := append(append([]string{}, base...), option, "tcp://127.0.0.1:10086")
			if _, err := parseCommand(role, append(legacy, extra...), io.Discard); err == nil {
				t.Fatalf("%s accepted KCP options without KCP: %v", role, extra)
			}
		}
	}
}

func TestKCPCLIWindows(t *testing.T) {
	for _, role := range []string{"server", "agent"} {
		base, option := []string{"-listen", "socks5://:1080"}, "-accept"
		if role == "agent" {
			base, option = nil, "-connect"
		}
		args := append(append([]string{}, base...), option, "kcp+dtls://127.0.0.1:10086?psk=key")
		cfg, err := parseCommand(role, args, io.Discard)
		if err != nil || cfg.kcp.SendWindow != 128 || cfg.kcp.ReceiveWindow != 128 {
			t.Fatalf("%s changed window defaults: %v", role, err)
		}
		for _, size := range []int{128, 1024, 4096} {
			cfg, err := parseCommand(role, append(args, "-kcp-sndwnd", strconv.Itoa(size), "-kcp-rcvwnd", "512"), io.Discard)
			if err != nil || cfg.kcp.SendWindow != size || cfg.kcp.ReceiveWindow != 512 {
				t.Fatalf("%s independent windows %d/512: %v", role, size, err)
			}
		}
		for _, flag := range []string{"-kcp-sndwnd", "-kcp-rcvwnd"} {
			for _, size := range []string{"-1", "0", "127", "4097", "2147483647"} {
				if _, err := parseCommand(role, append(args, flag, size), io.Discard); err == nil {
					t.Fatalf("%s accepted %s=%s", role, flag, size)
				}
			}
			legacy := append(append([]string{}, base...), option, "tcp://127.0.0.1:10086", flag, "128")
			if _, err := parseCommand(role, legacy, io.Discard); err == nil {
				t.Fatalf("%s accepted %s without KCP", role, flag)
			}
		}
	}
}

func TestKCPCLICombinations(t *testing.T) {
	for _, role := range []string{"server", "agent"} {
		base, option := []string{"-listen", "socks5://:1080"}, "-accept"
		if role == "agent" {
			base, option = nil, "-connect"
		}
		for _, native := range []bool{false, true} {
			args := append(append([]string{}, base...), option, "kcp+dtls://127.0.0.1:10086?psk=key")
			if native {
				args = append(args, option, "dtls://127.0.0.1:10087?psk=key")
			}
			c, err := parseCommand(role, args, io.Discard)
			if err != nil {
				t.Fatal(role, args, err)
			}
			want := "tcp"
			if native {
				want = "udp"
			}
			if c.tunnel.scheme != "kcp+dtls" || c.udpTransport != want {
				t.Fatalf("unexpected configuration: %+v", c)
			}
			if role == "server" {
				c, err = parseCommand(role, append(args, "-udp-transport", "stream"), io.Discard)
				if err != nil || c.udpTransport != "tcp" {
					t.Fatalf("stream selection: %v", err)
				}
			}
		}
		for _, extra := range [][]string{
			{option, "tls://127.0.0.1:10088?psk=key"},
			{option, "tcp://127.0.0.1:10088"},
			{option, "kcp+dtls://127.0.0.1:10088?psk=key"},
			{option, "dtls://127.0.0.1:10086?psk=key"},
			{option, "dtls://127.0.0.1:010086?psk=key"},
			{"-kcp-mtu", "1401"}, {"-kcp-mtu", "575"},
			{"-kcp-heartbeat", "0s"}, {"-kcp-timeout", "1s"},
		} {
			args := append(append([]string{}, base...), option, "kcp+dtls://127.0.0.1:10086?psk=key")
			if _, err := parseCommand(role, append(args, extra...), io.Discard); err == nil {
				t.Fatal("accepted invalid KCP combination", role, extra)
			}
		}
	}
	for _, value := range []string{"kcp+dtls://host:10086", "kcp+dtls://user:pass@host:10086?psk=secret", "kcp+dtls://host:10086?psk=secret&unknown=yes"} {
		_, err := parseEndpoint(value, "connect")
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("bad endpoint diagnostic: %v", err)
		}
	}
	if _, err := parseCommand("agent", []string{"-connect", "host:10086", "-kcp-mtu", "1200"}, io.Discard); err == nil {
		t.Fatal("KCP options accepted without KCP")
	}
	if _, err := parseCommand("agent", []string{"-connect", "kcp+dtls://host:10086?psk=key", "-target", "127.0.0.1:80"}, io.Discard); err != nil {
		t.Fatal("bare target rejected", err)
	}
}
