package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

func TestUDPForwardHeaderPreservesAgentDestination(t *testing.T) {
	for _, tc := range []struct {
		target, host string
		port         int
	}{
		{"CHARON.invalid.:500", "charon.invalid", 500},
		{"192.0.2.1:53", "192.0.2.1", 53},
		{"[2001:db8::1]:4500", "2001:db8::1", 4500},
	} {
		t.Run(tc.target, func(t *testing.T) {
			header, err := udpForwardHeader(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			packet := append(header, []byte("payload")...)
			host, port, payload, err := parseUDPPacket(packet)
			if err != nil || host != tc.host || port != tc.port || string(payload) != "payload" {
				t.Fatalf("destination changed: %q:%d %q, %v", host, port, payload, err)
			}
		})
	}
	for _, target := range []string{"", "charon", ":500", "charon:0", "charon:65536", "charon\n:500"} {
		if _, err := udpForwardHeader(target); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
}

func TestUDPForwardPoolWaitCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan net.Conn, 1)
	go func() { done <- pickUDPForwardTunnel(ctx, newConnPool(), time.Hour) }()
	cancel()
	select {
	case c := <-done:
		if c != nil {
			c.Close()
			t.Fatal("canceled wait claimed a connection")
		}
	case <-time.After(time.Second):
		t.Fatal("pool wait ignored cancellation")
	}
}

func TestUDPForwardReplyWaitCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &udpForwarder{writes: make(chan struct{}, 1), options: &proxyOptions{udpTimeout: time.Second}}
	f.writes <- struct{}{} // another session owns the shared socket's writer
	s := &udpForwardSession{owner: f, ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.writeReply([]byte("reply")) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("write wait returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reply wait ignored session cancellation")
	}
	if len(f.writes) != 1 {
		t.Fatal("canceled session released another session's writer")
	}
}

func TestUDPForwardReplyQueueTimesOut(t *testing.T) {
	f := &udpForwarder{writes: make(chan struct{}, 1), options: &proxyOptions{udpTimeout: 20 * time.Millisecond}}
	f.writes <- struct{}{}
	s := &udpForwardSession{owner: f, ctx: context.Background()}
	done := make(chan error, 1)
	go func() { done <- s.writeReply([]byte("reply")) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked reply returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reply queue exceeded the idle timeout without any socket I/O")
	}
	if len(f.writes) != 1 {
		t.Fatal("timed out session released another session's writer")
	}
}

func startUDPForwardUnit(t *testing.T, pool *connPool, target string) (*net.UDPConn, *net.UDPConn, <-chan error) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	options, _ := newProxyOptions("", time.Second)
	options.poolWait = time.Hour
	done := make(chan error, 1)
	go func() { done <- serveUDPForward(listener, pool, target, options) }()
	t.Cleanup(func() {
		client.Close()
		listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("UDP forward did not stop after closing the listener")
		}
	})
	return listener, client, done
}

func TestUDPForwardShutdownInterruptsHandshake(t *testing.T) {
	pool := newConnPool()
	server, agent := net.Pipe()
	defer agent.Close()
	pool.add(server)
	listener, client, _ := startUDPForwardUnit(t, pool, "charon.invalid:500")
	if _, err := client.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	agent.SetDeadline(time.Now().Add(2 * time.Second))
	if request, err := netx.ReadString(agent, '\n', 1024); err != nil || request != "udp://0.0.0.0:0\n" {
		t.Fatalf("request: %q, %v", request, err)
	}
	listener.Close()
	var b [1]byte
	if _, err := agent.Read(b[:]); err == nil {
		t.Fatal("listener closure left the pending handshake alive")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("listener closure failed to interrupt the pending handshake")
	}
}

func TestUDPForwardDropsOversizeWithoutLosingSession(t *testing.T) {
	pool := newConnPool()
	server, agent := net.Pipe()
	defer agent.Close()
	pool.add(server)
	hostname := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	_, client, _ := startUDPForwardUnit(t, pool, hostname+":500")
	result := make(chan error, 1)
	go func() {
		agent.SetDeadline(time.Now().Add(3 * time.Second))
		if request, err := netx.ReadString(agent, '\n', 1024); err != nil || request != "udp://0.0.0.0:0\n" {
			result <- fmt.Errorf("request: %q, %v", request, err)
			return
		}
		if err := writeAll(agent, []byte("OK\n")); err != nil {
			result <- err
			return
		}
		buf := make([]byte, 65535)
		for _, want := range []string{"before", "", "after"} {
			packet, err := readUDPFrame(agent, buf)
			if err != nil {
				result <- err
				return
			}
			host, port, payload, err := parseUDPPacket(packet)
			if err != nil || host != hostname || port != 500 || string(payload) != want {
				result <- fmt.Errorf("unexpected frame %s:%d %q: %v", host, port, payload, err)
				return
			}
			packet = appendSOCKSAddress([]byte{0, 0, 0}, &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 500})
			if err := writeUDPFrame(agent, append(packet, payload...)); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	for _, text := range []string{"before", "", "after"} {
		if text == "after" {
			// IPv4 permits 65507 bytes, but the logical destination makes the
			// framed packet exceed 65535. Drop it and retain this session.
			if _, err := client.Write(make([]byte, 65507)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := client.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
		n, err := client.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], []byte(text)) {
			t.Fatalf("reply: %q, %v", buf[:n], err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
