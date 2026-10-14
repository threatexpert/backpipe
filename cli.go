package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

const usage = `backpipe - reverse tunnel with independent pooled TCP connections

Usage:
  backpipe server -listen socks5://:1080 -accept :10086
  backpipe agent -connect server_host:10086 -pool 20

  backpipe server -listen "socks5s://:1080?psk=client-key" -accept "tls://:10086?psk=tunnel-key"
  backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20

  backpipe server -listen "socks5s://:1080?psk=client-key" -listen socks5://127.0.0.1:3180 -accept :10086

  backpipe server -listen tcp://:8080 -accept :10086
  backpipe agent -connect server_host:10086 -target 127.0.0.1:80

Use backpipe server -help or backpipe agent -help for options.
Use backpipe -version for the version. Old -mode/-left/-right syntax is removed.
`

type endpoint struct {
	scheme, address, username, password, psk string
}

// Never return URL parser errors: they can contain credentials or the PSK.
func parseEndpoint(value, option string) (endpoint, error) {
	var ep endpoint
	fail := func(reason string) (endpoint, error) {
		return endpoint{}, fmt.Errorf("-%s: %s", option, reason)
	}
	if value == "" {
		return fail("address is required")
	}
	if !strings.Contains(value, "://") {
		if option == "listen" {
			return fail("use tcp://, socks5:// or socks5s://")
		}
		value = "tcp://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.Path != "" || u.Fragment != "" || strings.Contains(value, "#") {
		return fail("invalid endpoint URL; paths and fragments are not supported")
	}
	ep.scheme, ep.address = u.Scheme, u.Host
	allowed := ep.scheme == "tcp"
	switch option {
	case "listen":
		allowed = allowed || ep.scheme == "socks5" || ep.scheme == "socks5s"
	case "accept", "connect":
		allowed = allowed || ep.scheme == "tls"
	case "target":
	default:
		return fail("unknown endpoint option")
	}
	if !allowed {
		return fail("unsupported protocol")
	}
	host, port, err := net.SplitHostPort(ep.address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 0 || n > 65535 || strings.ContainsAny(host, " \t\r\n") {
		return fail("expected host:port (use brackets for IPv6), port 0..65535")
	}
	if (option == "connect" || option == "target") && (host == "" || n == 0) {
		return fail("host and nonzero port are required")
	}
	if u.User != nil {
		if ep.scheme != "socks5" && ep.scheme != "socks5s" {
			return fail("username/password are only supported on SOCKS5 listeners")
		}
		ep.username = u.User.Username()
		ep.password, _ = u.User.Password()
		if len(ep.username) < 1 || len(ep.username) > 255 || len(ep.password) < 1 || len(ep.password) > 255 {
			return fail("username and password must each contain 1..255 bytes")
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail("invalid query encoding")
	}
	encrypted := ep.scheme == "tls" || ep.scheme == "socks5s"
	for key, values := range query {
		if key != "psk" || len(values) != 1 || !encrypted {
			return fail("only one psk query parameter is allowed, and only for TLS")
		}
	}
	if encrypted {
		ep.psk, err = secure.ReadPSKFile(query.Get("psk"))
		if err != nil {
			return fail("cannot read PSK file")
		}
		if ep.psk == "" {
			return fail("TLS requires a nonempty psk (literal value or @file)")
		}
	}
	return ep, nil
}

type entryConfig struct {
	endpoint endpoint
	proxy    *proxyOptions
}

type commandConfig struct {
	role           string
	entries        []entryConfig
	tunnel, target endpoint
	pool           int
	allow          string
	ppv2           bool
	proxy          *proxyOptions
}

func parseCommand(role string, args []string, output io.Writer) (*commandConfig, error) {
	if role != "server" && role != "agent" {
		return nil, fmt.Errorf("expected server or agent subcommand; use backpipe -help")
	}
	c := &commandConfig{role: role}
	fs := flag.NewFlagSet(role, flag.ContinueOnError)
	// flag.Parse includes offending values in its errors; suppress those so
	// malformed URLs and misplaced options cannot expose keys in diagnostics.
	fs.SetOutput(io.Discard)
	var listens []string
	var accept, connect, target, serverIP string
	var idle time.Duration
	if role == "server" {
		fs.Func("listen", "client entry (repeatable; SOCKS5 entries also accept HTTP): tcp://addr, socks5://[user:pass@]addr, socks5s://[user:pass@]addr?psk=key", func(value string) error {
			listens = append(listens, value)
			return nil
		})
		fs.StringVar(&accept, "accept", "", "agent pool listener: host:port or tls://host:port?psk=key")
		fs.StringVar(&c.allow, "allow", "", "comma-separated agent IP whitelist")
		fs.StringVar(&serverIP, "socks-server-ip", "", "advertised UDP relay IP (default: 0.0.0.0; clients use the TCP peer IP)")
		fs.BoolVar(&c.ppv2, "ppv2", false, "inject PROXY v2 header (tcp listener only)")
	} else {
		fs.StringVar(&connect, "connect", "", "server pool address: host:port or tls://host:port?psk=key")
		fs.StringVar(&target, "target", "", "fixed TCP target host:port; omit for SOCKS5 TCP/UDP and HTTP proxy exit")
		fs.IntVar(&c.pool, "pool", 5, "desired idle connections; active sessions are additional")
	}
	fs.DurationVar(&idle, "udp-timeout", 2*time.Minute, "SOCKS5 UDP idle timeout; set on both peers")
	fs.Usage = func() {
		fmt.Fprintf(output, "backpipe %s options:\n", role)
		fs.SetOutput(output)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
		fmt.Fprintln(output, "Quote URLs containing & or credentials; URL-encode special characters. psk=@file reads the first line.")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, flag.ErrHelp
		}
		return nil, fmt.Errorf("invalid %s options; use backpipe %s -help", role, role)
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional arguments; use backpipe %s -help", role)
	}
	var err error
	proxyMode := false
	if role == "server" {
		if len(listens) == 0 {
			return nil, fmt.Errorf("at least one -listen is required")
		}
		for i, listen := range listens {
			ep, err := parseEndpoint(listen, "listen")
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i+1, err)
			}
			isProxy := ep.scheme != "tcp"
			if i > 0 && isProxy != proxyMode {
				return nil, fmt.Errorf("tcp:// and SOCKS5 listeners cannot share a pool; use separate server processes")
			}
			proxyMode = isProxy
			c.entries = append(c.entries, entryConfig{endpoint: ep})
		}
		if c.tunnel, err = parseEndpoint(accept, "accept"); err != nil {
			return nil, err
		}
		if proxyMode && c.ppv2 {
			return nil, fmt.Errorf("-ppv2 requires a tcp:// listener")
		}
		if !proxyMode && serverIP != "" {
			return nil, fmt.Errorf("-socks-server-ip requires a SOCKS5 listener")
		}
	} else {
		if c.pool < 1 {
			return nil, fmt.Errorf("-pool must be at least 1")
		}
		if c.tunnel, err = parseEndpoint(connect, "connect"); err != nil {
			return nil, err
		}
		proxyMode = target == ""
		if !proxyMode {
			if c.target, err = parseEndpoint(target, "target"); err != nil {
				return nil, err
			}
		}
	}
	if idle <= 0 {
		return nil, fmt.Errorf("-udp-timeout must be positive")
	}
	if !proxyMode {
		var specified bool
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "udp-timeout" {
				specified = true
			}
		})
		if specified {
			return nil, fmt.Errorf("-udp-timeout requires SOCKS5 mode")
		}
	} else if role == "agent" {
		c.proxy, err = newProxyOptions("", idle)
		if err != nil {
			return nil, err
		}
	} else {
		for i := range c.entries {
			entry := &c.entries[i]
			entry.proxy, err = newProxyOptions(serverIP, idle)
			if err != nil {
				return nil, err
			}
			entry.proxy.config.Username, entry.proxy.config.Password = entry.endpoint.username, entry.endpoint.password
			if entry.endpoint.scheme == "socks5s" {
				entry.proxy.entryTLS, err = newTLSPSKConfig(entry.endpoint.psk, false)
				if err != nil {
					return nil, fmt.Errorf("cannot initialize SOCKS5 TLS for entry %d: %w", i+1, err)
				}
			}
		}
	}
	return c, nil
}

func runCLI(args []string, output io.Writer) error {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "-help" || args[0] == "--help" || args[0] == "-h")) {
		fmt.Fprint(output, usage)
		return nil
	}
	if len(args) == 1 && args[0] == "-version" {
		fmt.Fprintln(output, "backpipe", Version)
		return nil
	}
	c, err := parseCommand(args[0], args[1:], output)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	proto := "plain"
	if c.tunnel.scheme == "tls" {
		proto = "tls"
	}
	if c.role == "server" {
		return runServer(c.entries, c.tunnel.address, parseWhitelist(c.allow), proto, c.tunnel.psk, c.ppv2)
	} else {
		runAgent(c.tunnel.address, c.target.address, c.pool, proto, c.tunnel.psk, c.proxy)
	}
	return nil
}
