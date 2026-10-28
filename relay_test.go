package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type relayHalfConn struct{ net.Conn }

func (c *relayHalfConn) CloseWrite() error { return nil }

// Return EOF (or an error) only once the opposite copy is blocked in Write.
type relayBlockedWriter struct {
	net.Conn
	writing chan struct{}
	once    sync.Once
	readErr error
}

func (c *relayBlockedWriter) Read([]byte) (int, error) {
	<-c.writing
	return 0, c.readErr
}
func (c *relayBlockedWriter) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.writing) })
	return c.Conn.Write(p)
}
func (c *relayBlockedWriter) CloseWrite() error { return nil }

func TestRelayBlockedWriteCleanup(t *testing.T) {
	for _, hardError := range []bool{false, true} {
		name := "EOF-drain"
		if hardError {
			name = "copy-error"
		}
		t.Run(name, func(t *testing.T) {
			source, writer := net.Pipe()
			destination, unread := net.Pipe()
			defer source.Close()
			defer writer.Close()
			defer destination.Close()
			defer unread.Close()
			readErr := error(io.EOF)
			drain := 80 * time.Millisecond
			if hardError {
				readErr = errors.New("broken transport")
				drain = time.Hour // errors must bypass the drain wait
			}
			blocked := &relayBlockedWriter{Conn: destination, writing: make(chan struct{}), readErr: readErr}
			done := make(chan struct{})
			go func() {
				relayWithDrainTimeout(&relayHalfConn{source}, blocked, drain)
				close(done)
			}()
			written := make(chan struct{})
			go func() { writer.Write(bytes.Repeat([]byte("x"), 64<<10)); close(written) }()
			select {
			case <-blocked.writing:
			case <-time.After(2 * time.Second):
				t.Fatal("write never started")
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("relay retained a blocked writer after EOF/error")
			}
			select {
			case <-written:
			case <-time.After(time.Second):
				t.Fatal("source writer was not released")
			}
		})
	}
}

type relayBlockedCloseWrite struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *relayBlockedCloseWrite) Read([]byte) (int, error) { return 0, io.EOF }
func (c *relayBlockedCloseWrite) CloseWrite() error {
	<-c.closed
	return net.ErrClosed
}
func (c *relayBlockedCloseWrite) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestRelayBlockedHalfCloseCleanup(t *testing.T) {
	a, b := net.Pipe()
	c1 := &relayBlockedCloseWrite{Conn: a, closed: make(chan struct{})}
	c2 := &relayBlockedCloseWrite{Conn: b, closed: make(chan struct{})}
	defer c1.Close()
	defer c2.Close()
	done := make(chan struct{})
	go func() { relayWithDrainTimeout(c1, c2, 80*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain timer did not cover blocked CloseWrite calls")
	}
}

func TestRelayPreservesReplyAfterHalfClose(t *testing.T) {
	a, client, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer client.Close()
	b, target, err := tcpPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	defer target.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	target.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan struct{})
	go func() { relayWithDrainTimeout(a, b, time.Second); close(done) }()
	payload := bytes.Repeat([]byte("half-close"), 10000)
	result := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(target)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("payload lost before EOF")
		}
		if err == nil {
			time.Sleep(20 * time.Millisecond)
			err = writeAll(target, []byte("reply after EOF"))
		}
		target.(*net.TCPConn).CloseWrite()
		result <- err
	}()
	if err := writeAll(client, payload); err != nil {
		t.Fatal(err)
	}
	client.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "reply after EOF" {
		t.Fatalf("reply: %q, %v", reply, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not join its forwarding workers")
	}
}
