package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

type redirectKey struct {
	network string
	address string
}

// Built once at startup and shared read-only by all agent sessions.
type redirectRules map[redirectKey]string

func normalizeRedirectAddress(address string) (string, error) {
	if strings.ContainsAny(address, "/\\?#@=") || strings.ContainsFunc(address, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) {
		return "", fmt.Errorf("address must not contain whitespace, credentials or URL parameters")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("expected host:port; use brackets for IPv6")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("port must be 1..65535")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("port must be 1..65535")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if len(host) == 0 || len(host) > 253 {
			return "", fmt.Errorf("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 {
				return "", fmt.Errorf("invalid hostname label")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return "", fmt.Errorf("use an IP or ASCII hostname without wildcards, credentials or URL parameters")
				}
			}
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func parseRedirectRules(values []string) (redirectRules, error) {
	rules := make(redirectRules)
	for i, value := range values {
		errPrefix := fmt.Sprintf("-redirect rule %d", i+1)
		from, to, found := strings.Cut(value, "=")
		if !found || strings.Contains(to, "=") {
			return nil, fmt.Errorf("%s: expected [tcp://|udp://]host:port=host:port", errPrefix)
		}
		networks := []string{"tcp", "udp"}
		if network, rest, found := strings.Cut(from, "://"); found {
			if network != "tcp" && network != "udp" {
				return nil, fmt.Errorf("%s: protocol must be tcp or udp", errPrefix)
			}
			networks, from = []string{network}, rest
		}
		from, err := normalizeRedirectAddress(from)
		if err != nil {
			return nil, fmt.Errorf("%s source: %w", errPrefix, err)
		}
		to, err = normalizeRedirectAddress(to)
		if err != nil {
			return nil, fmt.Errorf("%s destination: %w", errPrefix, err)
		}
		for _, network := range networks {
			key := redirectKey{network, from}
			if _, exists := rules[key]; exists {
				return nil, fmt.Errorf("%s: duplicate or overlapping source for %s", errPrefix, network)
			}
			rules[key] = to
		}
	}
	return rules, nil
}

// Match the requested address before DNS; never recursively redirect the result.
func (rules redirectRules) rewrite(network, address string) string {
	if len(rules) == 0 {
		return address
	}
	normalized, err := normalizeRedirectAddress(address)
	if err != nil {
		return address
	}
	if target, ok := rules[redirectKey{network, normalized}]; ok {
		log.Printf("[agent] redirect %s: %s -> %s", network, normalized, target)
		return target
	}
	return address
}
