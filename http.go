package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const maxHTTPHeader = 64 << 10

func httpProxyError(c net.Conn, code int) {
	auth := ""
	if code == http.StatusProxyAuthRequired {
		auth = "Proxy-Authenticate: Basic realm=\"backpipe\"\r\n"
	}
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code), auth)
}

// Bound the request header without limiting the upload body. Replay it through
// the HTTP parser and retain every buffered byte, including early CONNECT data.
func readProxyHTTPRequest(r *bufio.Reader) (*http.Request, *bufio.Reader, int) {
	var header []byte
	lineSize := 0
	for {
		line, err := r.ReadSlice('\n')
		if len(header)+len(line) > maxHTTPHeader {
			return nil, nil, http.StatusRequestHeaderFieldsTooLarge
		}
		header = append(header, line...)
		lineSize += len(line)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, nil, http.StatusBadRequest
		}
		if lineSize == len(line) && (bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))) {
			break
		}
		lineSize = 0
	}
	replay := bufio.NewReader(io.MultiReader(bytes.NewReader(header), r))
	req, err := http.ReadRequest(replay)
	if err != nil {
		return nil, nil, http.StatusBadRequest
	}
	if req.ProtoMajor != 1 || req.ProtoMinor > 1 {
		return nil, nil, http.StatusHTTPVersionNotSupported
	}
	return req, replay, 0
}

func httpProxyAuthenticated(req *http.Request, options *proxyOptions) bool {
	if options.config.Username == "" {
		return true
	}
	values := req.Header.Values("Proxy-Authorization")
	// gonc's HTTP CONNECT client uses SetBasicAuth (Authorization). Accept
	// that spelling only for CONNECT, whose headers never reach the target.
	// Ordinary HTTP keeps Authorization exclusively for the origin server.
	if len(values) == 0 && req.Method == http.MethodConnect {
		values = req.Header.Values("Authorization")
	}
	if len(values) != 1 {
		return false
	}
	scheme, value, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	want := options.config.Username + ":" + options.config.Password
	return subtle.ConstantTimeCompare(decoded, []byte(want)) == 1
}

func httpProxyTarget(req *http.Request) (string, error) {
	u := req.URL
	port := "80"
	if req.Method == http.MethodConnect {
		var err error
		u, err = url.Parse("http://" + req.RequestURI)
		if err != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
			return "", fmt.Errorf("invalid CONNECT authority")
		}
		port = "443"
		if req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
			return "", fmt.Errorf("CONNECT body is unsupported")
		}
	} else {
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		if u.Host == "" {
			u.Host = req.Host
		}
		if u.Scheme != "http" {
			return "", fmt.Errorf("use CONNECT for HTTPS")
		}
	}
	if u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("invalid proxy target")
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, "\\/@?#[]") || strings.IndexFunc(host, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
		return "", fmt.Errorf("invalid target host")
	}
	if strings.Contains(host, ":") {
		ip, _, _ := strings.Cut(host, "%")
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("invalid IPv6 target")
		}
	}
	if u.Port() != "" {
		port = u.Port()
	} else if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("empty target port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid target port")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func stripHTTPHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}

func serveHTTPProxy(client net.Conn, reader *bufio.Reader, pool *connPool, options *proxyOptions) {
	req, replay, code := readProxyHTTPRequest(reader)
	if code != 0 {
		httpProxyError(client, code)
		return
	}
	client = &readerConn{Conn: client, reader: replay}
	if !httpProxyAuthenticated(req, options) {
		httpProxyError(client, http.StatusProxyAuthRequired)
		return
	}
	target, err := httpProxyTarget(req)
	if err != nil {
		httpProxyError(client, http.StatusBadRequest)
		return
	}
	expect := req.Header.Get("Expect")
	if expect != "" && !strings.EqualFold(expect, "100-continue") {
		httpProxyError(client, http.StatusExpectationFailed)
		return
	}
	// Authentication and validation precede pool allocation for both protocols.
	client.SetDeadline(time.Now().Add(options.poolWait + 30*time.Second))
	tunnel := pool.pick(options.poolWait)
	if tunnel == nil {
		httpProxyError(client, http.StatusServiceUnavailable)
		return
	}
	defer tunnel.Close()
	atomic.AddInt64(&relayCount, 1)
	defer atomic.AddInt64(&relayCount, -1)
	if err := openTCPTunnel(tunnel, target); err != nil {
		httpProxyError(client, http.StatusBadGateway)
		return
	}
	client.SetDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		if err := writeAll(client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		relay(client, tunnel)
		return
	}
	if expect != "" {
		if err := writeAll(client, []byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
			return
		}
		req.Header.Del("Expect")
	}
	stripHTTPHopHeaders(req.Header)
	req.RequestURI, req.Host, req.Close = "", req.URL.Host, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req = req.WithContext(ctx)
	// One HTTP transaction owns one pool connection, matching gonc's ordinary
	// HTTP forwarding behavior. Transport handles streaming uploads, chunking,
	// early upstream responses and response parsing without buffering bodies.
	var dialed atomic.Bool
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, fmt.Errorf("tunnel already used")
			}
			return tunnel, nil
		},
		DisableKeepAlives: true, DisableCompression: true,
		ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: maxHTTPHeader,
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		httpProxyError(client, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHTTPHopHeaders(resp.Header)
	resp.Close = true
	resp.Write(client)
}
