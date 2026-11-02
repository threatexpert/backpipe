package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"testing"
)

// Set BACKPIPE_LEGACY_KCP_BINARY to a separately built v1.5.0 executable.
// The old peer always uses its original congestion control and no FEC.
func TestLegacyKCPBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("BACKPIPE_LEGACY_KCP_BINARY")
	if binary == "" {
		t.Skip("set BACKPIPE_LEGACY_KCP_BINARY to a v1.5.0 executable")
	}
	testLegacyKCPBinaryCompatibility(t, binary, false)
}

func TestLegacyKCPFECBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("BACKPIPE_LEGACY_KCP_FEC_BINARY")
	if binary == "" {
		t.Skip("set BACKPIPE_LEGACY_KCP_FEC_BINARY to a v1.6.0 executable")
	}
	testLegacyKCPBinaryCompatibility(t, binary, true)
}

func testLegacyKCPBinaryCompatibility(t *testing.T, binary string, fec bool) {
	t.Helper()
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
	for _, oldRole := range []string{"server", "agent"} {
		t.Run("old-"+oldRole, func(t *testing.T) {
			startServer, startAgent := startProcess, startProcess
			if oldRole == "server" {
				startServer = startLegacy
			} else {
				startAgent = startLegacy
			}
			target := tcpEcho(t, true)
			udpTarget := udpEcho(t)
			serverArgs := []string{"server", "-listen", "tcp://127.0.0.1:0?to=" + target,
				"-listen", "udp://127.0.0.1:0?to=" + udpTarget.String(), "-accept", "kcp+dtls://127.0.0.1:0?psk=compat-kcp"}
			if fec {
				serverArgs = append(serverArgs, "-kcp-fec", "10:3")
			}
			server := startServer(t, serverArgs...)
			entries := entryAddresses(t, server, 2)
			agentArgs := []string{"agent", "-connect", "kcp+dtls://" + listenerAddress(t, server, "agent") + "?psk=compat-kcp", "-pool", "2"}
			if fec {
				agentArgs = append(agentArgs, "-kcp-fec", "10:3")
			}
			startAgent(t, agentArgs...)
			c := dialClient(t, entries[0])
			payload := bytes.Repeat([]byte("cross-version KCP"), 10000)
			if err := writeAll(c, payload); err != nil {
				t.Fatal(err)
			}
			c.CloseWrite()
			expectBytes(t, c, append([]byte("reply:"), payload...))
			c.Close()
			addr, err := net.ResolveUDPAddr("udp", entries[1])
			if err != nil {
				t.Fatal(err)
			}
			forwardUDPRoundTrip(t, forwardUDPClient(t), addr, bytes.Repeat([]byte("KCP UDP"), 8000))
		})
	}
}
