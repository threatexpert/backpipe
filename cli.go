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

const usage = `backpipe - reverse tunnel with TCP/TLS or KCP/DTLS streams and optional native DTLS sessions

Usage:
  backpipe server -listen socks5://:1080 -accept :10086
  backpipe agent -connect server_host:10086 -pool 20

  backpipe server -listen "socks5s://:1080?psk=client-key" -accept "tls://:10086?psk=tunnel-key"
  backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20

  backpipe server -listen "socks5s://:1080?psk=client-key" -listen socks5://127.0.0.1:3180 -accept :10086

  backpipe server -listen "udp://:500?to=charon:500" -listen "tcp://:8080?to=web:80" -listen socks5://:1080 -accept :10086
  backpipe agent -connect server_host:10086 -pool 20 -redirect "udp://charon:500=10.1.2.3:500"

  backpipe server -listen "udp://:500?to=charon:500" -accept "dtls://:10086?psk=tunnel-key"
  backpipe agent -connect "dtls://server_host:10086?psk=tunnel-key" -udp-pool 20

  backpipe server -listen socks5://:1080 -accept "kcp+dtls://:10086?psk=tunnel-key"
  backpipe agent -connect "kcp+dtls://server_host:10086?psk=tunnel-key" -pool 20

  backpipe server -listen socks5://:1080 -accept "kcp+dtls://:10086?psk=tunnel-key" -accept "dtls://:10087?psk=tunnel-key"
  backpipe agent -connect "kcp+dtls://server_host:10086?psk=tunnel-key" -connect "dtls://server_host:10087?psk=tunnel-key" -pool 20 -udp-pool 20

  backpipe server -listen tcp://:8080 -accept :10086
  backpipe agent -connect server_host:10086 -target 127.0.0.1:80

Use backpipe server -help or backpipe agent -help for options.
Use backpipe -version for the version. Old -mode/-left/-right syntax is removed.
`

type endpoint struct {
	scheme, address, username, password, psk, target string
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
			return fail("use tcp://, udp://, socks5:// or socks5s://")
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
		allowed = allowed || ep.scheme == "udp" || ep.scheme == "socks5" || ep.scheme == "socks5s"
	case "accept", "connect":
		allowed = allowed || ep.scheme == "tls" || ep.scheme == "dtls" || ep.scheme == "kcp+dtls"
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
	encrypted := ep.scheme == "tls" || ep.scheme == "dtls" || ep.scheme == "socks5s" || ep.scheme == "kcp+dtls"
	for key, values := range query {
		if len(values) != 1 {
			return fail("query parameters must not be repeated")
		}
		switch key {
		case "psk":
			if !encrypted {
				return fail("psk is only supported for TLS or DTLS")
			}
		case "to":
			if option != "listen" || (ep.scheme != "tcp" && ep.scheme != "udp") {
				return fail("to is only supported on TCP/UDP listeners")
			}
			ep.target, err = normalizeRedirectAddress(values[0])
			if err != nil {
				return fail("invalid to target: " + err.Error())
			}
		default:
			return fail("unsupported query parameter")
		}
	}
	if ep.scheme == "udp" && ep.target == "" {
		return fail("UDP listeners require to=host:port")
	}
	if encrypted {
		ep.psk, err = secure.ReadPSKFile(query.Get("psk"))
		if err != nil {
			return fail("cannot read PSK file")
		}
		if ep.psk == "" {
			return fail("TLS/DTLS requires a nonempty psk (literal value or @file)")
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
	tunnels        []endpoint
	pool           int
	udpPool        int
	udpTransport   string
	udpMTU         int
	kcp            kcpSettings
	allow          string
	ppv2           bool
	proxy          *proxyOptions
	redirects      redirectRules
}

func parseCommand(role string, args []string, output io.Writer) (*commandConfig, error) {
	if role != "server" && role != "agent" {
		return nil, fmt.Errorf("expected server or agent subcommand; use backpipe -help")
	}
	c := &commandConfig{role: role, udpPool: 20, udpMTU: defaultDatagramMTU, kcp: defaultKCPSettings()}
	fs := flag.NewFlagSet(role, flag.ContinueOnError)
	// flag.Parse includes offending values in its errors; suppress those so
	// malformed URLs and misplaced options cannot expose keys in diagnostics.
	fs.SetOutput(io.Discard)
	var listens []string
	var redirects []string
	var tunnels []string
	var target, serverIP string
	var idle time.Duration
	if role == "server" {
		fs.Func("listen", "client entry (repeatable): tcp://addr?to=host:port, udp://addr?to=host:port, socks5://[user:pass@]addr, socks5s://[user:pass@]addr?psk=key; SOCKS5 also accepts HTTP; bare tcp://addr requires agent -target", func(value string) error {
			listens = append(listens, value)
			return nil
		})
		fs.Func("accept", "agent pool listener (repeatable, one stream and one native DTLS): host:port, tls://host:port?psk=key, kcp+dtls://host:port?psk=key, dtls://host:port?psk=key; TCP/TLS and KCP/DTLS are mutually exclusive", func(value string) error {
			tunnels = append(tunnels, value)
			return nil
		})
		fs.StringVar(&c.udpTransport, "udp-transport", "", "UDP tunnel transport: stream (tcp is a legacy alias) or udp; defaults to udp with a native DTLS pool, otherwise stream; no automatic fallback")
		fs.StringVar(&c.allow, "allow", "", "comma-separated agent IP whitelist")
		fs.StringVar(&serverIP, "socks-server-ip", "", "advertised UDP relay IP (default: 0.0.0.0; clients use the TCP peer IP)")
		fs.BoolVar(&c.ppv2, "ppv2", false, "inject PROXY v2 header (bare tcp:// listener with agent -target only)")
	} else {
		fs.Func("connect", "server pool address (repeatable, one stream and one native DTLS): host:port, tls://host:port?psk=key, kcp+dtls://host:port?psk=key, dtls://host:port?psk=key; TCP/TLS and KCP/DTLS are mutually exclusive", func(value string) error {
			tunnels = append(tunnels, value)
			return nil
		})
		fs.StringVar(&target, "target", "", "fixed TCP target for bare tcp:// listeners; omit for SOCKS5/HTTP and listeners with ?to=host:port")
		fs.IntVar(&c.pool, "pool", 5, "desired idle TCP/TLS or KCP/DTLS streams; active sessions are additional")
		fs.IntVar(&c.udpPool, "udp-pool", 20, "desired idle DTLS sessions; requires dtls://; active sessions are additional")
		fs.Func("redirect", "outbound target rewrite (repeatable): [tcp://|udp://]host:port=host:port; no protocol matches both", func(value string) error {
			redirects = append(redirects, value)
			return nil
		})
	}
	fs.DurationVar(&idle, "udp-timeout", 2*time.Minute, "UDP idle timeout for SOCKS5 and fixed forwarding; set on both peers")
	fs.IntVar(&c.udpMTU, "udp-mtu", defaultDatagramMTU, fmt.Sprintf("maximum outer UDP payload in bytes (%d..%d); requires dtls://; set on both peers", minDatagramMTU, maxDatagramMTU))
	fs.IntVar(&c.kcp.MTU, "kcp-mtu", c.kcp.MTU, "maximum outer KCP/DTLS UDP payload (576..1400 bytes); requires kcp+dtls://")
	fs.IntVar(&c.kcp.SendWindow, "kcp-sndwnd", c.kcp.SendWindow, "KCP send window (128..4096 segments); requires kcp+dtls://")
	fs.IntVar(&c.kcp.ReceiveWindow, "kcp-rcvwnd", c.kcp.ReceiveWindow, "KCP receive window (128..4096 segments); requires kcp+dtls://")
	fs.DurationVar(&c.kcp.Heartbeat, "kcp-heartbeat", c.kcp.Heartbeat, "KCP/DTLS heartbeat interval; requires kcp+dtls://")
	fs.DurationVar(&c.kcp.Timeout, "kcp-timeout", c.kcp.Timeout, "KCP/DTLS peer response timeout (at least 3 heartbeat intervals); requires kcp+dtls://")
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
	specified := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { specified[f.Name] = true })
	tunnelOption := "accept"
	if role == "agent" {
		tunnelOption = "connect"
	}
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("at least one -%s is required", tunnelOption)
	}
	hasDTLS := false
	for i, value := range tunnels {
		ep, err := parseEndpoint(value, tunnelOption)
		if err != nil {
			return nil, fmt.Errorf("pool endpoint %d: %w", i+1, err)
		}
		if ep.scheme == "dtls" {
			if hasDTLS {
				return nil, fmt.Errorf("-%s accepts at most one DTLS endpoint", tunnelOption)
			}
			hasDTLS = true
		} else {
			if c.tunnel.scheme != "" {
				return nil, fmt.Errorf("-%s accepts at most one stream endpoint; TCP/TLS and KCP/DTLS are mutually exclusive", tunnelOption)
			}
			c.tunnel = ep
		}
		c.tunnels = append(c.tunnels, ep)
	}
	if c.tunnel.scheme != "kcp+dtls" && (specified["kcp-mtu"] || specified["kcp-sndwnd"] || specified["kcp-rcvwnd"] || specified["kcp-heartbeat"] || specified["kcp-timeout"]) {
		return nil, fmt.Errorf("KCP options require a kcp+dtls:// pool endpoint")
	}
	if !validKCPWindow(c.kcp.SendWindow) || !validKCPWindow(c.kcp.ReceiveWindow) {
		return nil, fmt.Errorf("-kcp-sndwnd and -kcp-rcvwnd must be between 128 and 4096 segments")
	}
	if c.kcp.MTU < 576 || c.kcp.MTU > 1400 || c.kcp.Heartbeat < 50*time.Millisecond || c.kcp.Heartbeat > time.Hour || c.kcp.Timeout < 3*c.kcp.Heartbeat || c.kcp.Timeout > 24*time.Hour {
		return nil, fmt.Errorf("KCP requires MTU 576..1400, heartbeat 50ms..1h, timeout at least 3 heartbeats and at most 24h")
	}
	if c.tunnel.scheme == "kcp+dtls" && hasDTLS {
		for _, ep := range c.tunnels {
			if ep.scheme == "dtls" {
				_, kp, _ := net.SplitHostPort(c.tunnel.address)
				_, dp, _ := net.SplitHostPort(ep.address)
				kn, _ := strconv.Atoi(kp)
				dn, _ := strconv.Atoi(dp)
				if kn == dn && kn != 0 {
					return nil, fmt.Errorf("KCP/DTLS and native DTLS require different UDP ports")
				}
			}
		}
	}
	if !hasDTLS && (specified["udp-pool"] || specified["udp-mtu"]) {
		return nil, fmt.Errorf("-udp-pool and -udp-mtu require a DTLS pool endpoint")
	}
	if c.udpPool < 1 {
		return nil, fmt.Errorf("-udp-pool must be at least 1")
	}
	if c.udpMTU < minDatagramMTU || c.udpMTU > maxDatagramMTU {
		return nil, fmt.Errorf("-udp-mtu must be between %d and %d", minDatagramMTU, maxDatagramMTU)
	}
	if !specified["udp-transport"] {
		c.udpTransport = "tcp"
		if hasDTLS {
			c.udpTransport = "udp"
		}
	}
	if c.udpTransport == "stream" {
		c.udpTransport = "tcp"
	} // preserve legacy internal selection
	if c.udpTransport != "tcp" && c.udpTransport != "udp" {
		return nil, fmt.Errorf("-udp-transport must be stream, tcp (legacy alias), or udp")
	}
	if c.udpTransport == "udp" && !hasDTLS {
		return nil, fmt.Errorf("-udp-transport udp requires a DTLS pool endpoint")
	}
	var err error
	if c.redirects, err = parseRedirectRules(redirects); err != nil {
		return nil, err
	}
	proxyMode := false
	hasSOCKS := false
	if role == "server" {
		if len(listens) == 0 {
			return nil, fmt.Errorf("at least one -listen is required")
		}
		for i, listen := range listens {
			ep, err := parseEndpoint(listen, "listen")
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", i+1, err)
			}
			isProxy := ep.scheme != "tcp" || ep.target != ""
			if i > 0 && isProxy != proxyMode {
				return nil, fmt.Errorf("bare tcp:// listeners require agent -target and cannot share a pool with SOCKS5 or listeners using to; use separate server processes")
			}
			proxyMode = isProxy
			hasSOCKS = hasSOCKS || ep.scheme == "socks5" || ep.scheme == "socks5s"
			if c.tunnel.scheme == "" && (ep.scheme != "udp" || c.udpTransport == "tcp") {
				return nil, fmt.Errorf("SOCKS5/HTTP, TCP listeners and UDP over streams require a TCP/TLS or KCP/DTLS pool endpoint")
			}
			c.entries = append(c.entries, entryConfig{endpoint: ep})
		}
		if !proxyMode && hasDTLS {
			return nil, fmt.Errorf("bare TCP listeners cannot share a DTLS pool; use listeners with to")
		}
		if proxyMode && c.ppv2 {
			return nil, fmt.Errorf("-ppv2 requires a bare tcp:// listener with agent -target")
		}
		if !hasSOCKS && serverIP != "" {
			return nil, fmt.Errorf("-socks-server-ip requires a SOCKS5 listener")
		}
	} else {
		if c.pool < 1 {
			return nil, fmt.Errorf("-pool must be at least 1")
		}
		proxyMode = target == ""
		if !proxyMode {
			if hasDTLS {
				return nil, fmt.Errorf("-target cannot be combined with a DTLS pool endpoint")
			}
			if c.target, err = parseEndpoint(target, "target"); err != nil {
				return nil, err
			}
		}
	}
	if idle <= 0 {
		return nil, fmt.Errorf("-udp-timeout must be positive")
	}
	if !proxyMode {
		if specified["udp-timeout"] {
			return nil, fmt.Errorf("-udp-timeout requires SOCKS5 or listeners using to; omit agent -target")
		}
	} else if role == "agent" {
		c.proxy, err = newProxyOptions("", idle)
		if err != nil {
			return nil, err
		}
	} else {
		for i := range c.entries {
			entry := &c.entries[i]
			advertisedIP := ""
			if entry.endpoint.scheme == "socks5" || entry.endpoint.scheme == "socks5s" {
				advertisedIP = serverIP
			}
			entry.proxy, err = newProxyOptions(advertisedIP, idle)
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
	if c.role == "server" {
		return runConfiguredServer(c)
	}
	return runConfiguredAgent(c)
}
