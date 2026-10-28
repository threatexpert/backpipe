package main

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Optional cross-version check: provide a separately built v1.4.2 executable.
// This exercises both upgrade orders without fetching or building old source
// as part of the normal unit test suite.
func TestLegacyBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("BACKPIPE_LEGACY_BINARY")
	if binary == "" {
		t.Skip("set BACKPIPE_LEGACY_BINARY to a v1.4.2 executable")
	}
	startLegacy := func(t *testing.T, args ...string) *testProcess {
		t.Helper()
		p := &testProcess{done: make(chan struct{})}
		p.cmd = exec.Command(binary, args...)
		p.cmd.Stdout, p.cmd.Stderr = &p.logs, &p.logs
		if err := p.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { p.cmd.Wait(); close(p.done) }()
		t.Cleanup(func() {
			p.stop()
			if t.Failed() {
				t.Log(p.logs.String())
			}
		})
		return p
	}
	for _, mode := range []string{"tcp", "tls", "tls+dtls", "dtls"} {
		for _, oldRole := range []string{"server", "agent"} {
			t.Run(mode+"/old-"+oldRole, func(t *testing.T) {
				startServer, startAgent := startProcess, startProcess
				if oldRole == "server" {
					startServer = startLegacy
				} else {
					startAgent = startLegacy
				}
				target := tcpEcho(t, true)
				udpTarget := udpEcho(t)
				args := []string{"server", "-listen", "udp://127.0.0.1:0?to=" + udpTarget.String()}
				if mode != "dtls" {
					args = append(args, "-listen", "tcp://127.0.0.1:0?to="+target)
					scheme := "tls://127.0.0.1:0?psk=compat-key"
					if mode == "tcp" {
						scheme = "127.0.0.1:0"
					}
					args = append(args, "-accept", scheme)
				}
				if strings.Contains(mode, "dtls") {
					args = append(args, "-accept", "dtls://127.0.0.1:0?psk=compat-key")
				}
				server := startServer(t, args...)
				agentArgs := []string{"agent"}
				entryCount := 1
				if mode != "dtls" {
					entryCount++
					addr := listenerAddress(t, server, "agent")
					if mode != "tcp" {
						addr = "tls://" + addr + "?psk=compat-key"
					}
					agentArgs = append(agentArgs, "-connect", addr, "-pool", "2")
				}
				if strings.Contains(mode, "dtls") {
					agentArgs = append(agentArgs, "-connect", "dtls://"+listenerAddress(t, server, "UDP agent")+"?psk=compat-key", "-udp-pool", "2")
				}
				entries := entryAddresses(t, server, entryCount)
				startAgent(t, agentArgs...)
				udpAddr, err := net.ResolveUDPAddr("udp", entries[0])
				if err != nil {
					t.Fatal(err)
				}
				forwardUDPRoundTrip(t, forwardUDPClient(t), udpAddr, []byte("cross-version UDP"))
				if mode != "dtls" {
					c := dialClient(t, entries[1])
					c.Write([]byte("cross-version TCP"))
					c.CloseWrite()
					expectBytes(t, c, []byte("reply:cross-version TCP"))
					c.Close()
				}
			})
		}
	}
}
