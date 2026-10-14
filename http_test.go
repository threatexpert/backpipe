package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/secure"
)

func TestHTTPProxyEntries(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" || r.Header.Get("X-Hop") != "" {
			http.Error(w, "proxy credentials or hop header leaked", 500)
			return
		}
		if r.Header.Get("Authorization") != "Bearer origin-token" {
			http.Error(w, "origin authorization lost", 500)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Keep-Alive", "timeout=10")
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // Exercise a streamed/chunked response.
		fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.RequestURI(), body)
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	server := startProcess(t, "server", "-listen", "socks5://127.0.0.1:0", "-listen", "socks5s://web:secret@127.0.0.1:0?psk=http-entry-key", "-accept", "tls://127.0.0.1:0?psk=http-pool-key")
	entries := entryAddresses(t, server, 2)
	startProcess(t, "agent", "-connect", "tls://"+listenerAddress(t, server, "agent")+"?psk=http-pool-key", "-pool", "2")
	await(t, func() bool { return strings.Count(server.logs.String(), "agent connection pooled:") == 2 }, server.logs.String)
	dial := func(entry int) net.Conn {
		t.Helper()
		var c net.Conn = dialClient(t, entries[entry])
		if entry == 1 {
			n, err := secure.DoNegotiation(goncTLSForTest(t, "http-entry-key", true), c, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			c = n
			t.Cleanup(func() { c.Close() })
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		return c
	}
	auth := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("web:secret")) + "\r\n"
	// All rejected requests must finish before claiming an idle connection.
	for _, tc := range []struct {
		entry   int
		request string
		status  int
	}{
		{1, "GET " + origin.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n", 407},
		{1, "GET " + origin.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Basic d2ViOnNlY3JldA==\r\n\r\n", 407},
		{1, "GET " + origin.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\n" + auth + auth + "\r\n", 407},
		{0, "CONNECT localhost:0 HTTP/1.1\r\nHost: localhost:0\r\n\r\n", 400},
		{0, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", 400},
		{0, "GET / HTTP/1.1\r\nHost: " + host + "\r\nExpect: unsupported\r\n\r\n", 417},
		{0, "GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Large: " + strings.Repeat("x", maxHTTPHeader) + "\r\n\r\n", 431},
	} {
		c := dial(tc.entry)
		c.Write([]byte(tc.request))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		c.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("got status %d, want %d", resp.StatusCode, tc.status)
		}
		if tc.status == 407 && resp.Header.Get("Proxy-Authenticate") == "" {
			t.Fatal("missing proxy auth challenge")
		}
	}
	if strings.Count(server.logs.String(), "agent connection pooled:") != 2 {
		t.Fatal("rejected HTTP request consumed pool")
	}
	// A failed destination dial must return 502, never a successful CONNECT.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	failed := dial(0)
	fmt.Fprintf(failed, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", closedAddr, closedAddr)
	failedResp, err := http.ReadResponse(bufio.NewReader(failed), nil)
	if err != nil {
		t.Fatal(err)
	}
	failedResp.Body.Close()
	failed.Close()
	if failedResp.StatusCode != 502 {
		t.Fatalf("failed target returned %d", failedResp.StatusCode)
	}
	for entry := range entries {
		t.Run(fmt.Sprintf("encrypted=%v", entry == 1), func(t *testing.T) {
			for _, tc := range []struct{ method, path, headers, body, want string }{
				{"GET", origin.URL + "/get?q=1", "", "", "GET /get?q=1 "},
				{"POST", origin.URL + "/upload", "Content-Length: 200000\r\n", strings.Repeat("b", 200000), "POST /upload " + strings.Repeat("b", 200000)},
				{"POST", origin.URL + "/chunked", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n0\r\n\r\n", "POST /chunked hello"},
				{"GET", "/origin-form", "", "", "GET /origin-form "},
			} {
				c := dial(entry)
				header := tc.method + " " + tc.path + " HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer origin-token\r\nConnection: X-Hop\r\nX-Hop: remove-me\r\nProxy-Connection: keep-alive\r\n"
				if entry == 1 {
					header += auth
				}
				if err := writeAll(c, []byte(header+tc.headers+"\r\n"+tc.body)); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				c.Close()
				if err != nil || resp.StatusCode != 200 || string(body) != tc.want {
					t.Fatalf("HTTP forwarding failed: status=%d len=%d err=%v", resp.StatusCode, len(body), err)
				}
				if resp.Header.Get("Keep-Alive") != "" || !resp.Close {
					t.Fatalf("response headers not normalized: close=%v headers=%v", resp.Close, resp.Header)
				}
			}
			// CONNECT plus payload in a single write must preserve buffered bytes
			// and allow half-close through both plain and TLS entries.
			c := dial(entry)
			target := tcpEcho(t, true)
			header := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
			if entry == 1 {
				header += auth
			}
			writeAll(c, []byte(header+"\r\nbuffered-connect"))
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(c)
			resp, err := http.ReadResponse(r, nil)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("CONNECT: %v", err)
			}
			expectBytes(t, r, []byte("reply:buffered-connect"))
			c.Close()
			// Exercise gonc's actual HTTP/HTTPS proxy client as well.
			proxyURL := "http://" + entries[entry]
			if entry == 1 {
				proxyURL = "https://web:secret@" + entries[entry] + "?psk=http-entry-key"
			}
			cfg, err := apps.ParseProxyURL(io.Discard, proxyURL)
			if err != nil {
				t.Fatal(err)
			}
			gc, err := apps.NewHttpConnectClient(cfg).DialTimeout("tcp", tcpEcho(t, false), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer gc.Close()
			gc.SetDeadline(time.Now().Add(3 * time.Second))
			gc.Write([]byte("gonc-http-connect"))
			expectBytes(t, gc, []byte("gonc-http-connect"))
		})
	}
	// A conventional HTTP client uses CONNECT to reach an actual HTTPS origin.
	httpsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "https-through-connect") }))
	defer httpsOrigin.Close()
	proxyURL, _ := url.Parse("http://" + entries[0])
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // local test certificate only
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(httpsOrigin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "https-through-connect" {
		t.Fatalf("HTTPS failed: %v", err)
	}

	// Expect: 100-continue must be acknowledged before reading the upload.
	c := dial(0)
	defer c.Close()
	fmt.Fprintf(c, "POST %s/expect HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer origin-token\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", origin.URL, host)
	r := bufio.NewReader(c)
	interim, err := http.ReadResponse(r, nil)
	if err != nil || interim.StatusCode != 100 {
		t.Fatalf("100 Continue failed: %v", err)
	}
	c.Write([]byte("body"))
	resp, err = http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "POST /expect body" {
		t.Fatalf("continued upload failed: %v", err)
	}
}

func TestHTTPUnavailablePool(t *testing.T) {
	s, c, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	opts, err := newProxyOptions("", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	opts.poolWait = 20 * time.Millisecond
	done := make(chan struct{})
	go func() { defer close(done); serveProxyClient(s, newConnPool(), opts) }()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("got %d, want 503", resp.StatusCode)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not exit")
	}
}
