package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKCPPair(t *testing.T, hookA, hookB func([]byte) [][]byte, settings ...func(*kcpSettings)) (*kcpStreamConn, *kcpStreamConn, *testRecordConn, *testRecordConn) {
	t.Helper()
	a, b := newTestRecordPipe()
	a.hook, b.hook = hookA, hookB
	cfg := defaultKCPSettings()
	cfg.Heartbeat, cfg.Timeout, cfg.CloseTimeout = 50*time.Millisecond, time.Second, time.Second
	for _, configure := range settings {
		configure(&cfg)
	}
	ca, err := newKCPStream(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := newKCPStream(b, cfg)
	if err != nil {
		ca.abort(err)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ca.abort(net.ErrClosed)
		cb.abort(net.ErrClosed)
		if a.concurrentReaders.Load() || b.concurrentReaders.Load() {
			t.Error("concurrent carrier readers")
		}
		if a.readDeadlineCalls.Load() != 0 || b.readDeadlineCalls.Load() != 0 {
			t.Error("application deadline reached carrier")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ca.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cb.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return ca, cb, a, b
}

func TestKCPHalfCloseWithLossAndReordering(t *testing.T) {
	impair := func() func([]byte) [][]byte {
		count := 0
		var held []byte
		return func(p []byte) [][]byte {
			if p[4] != kcpPacketData {
				return [][]byte{p}
			}
			count++
			if count%7 == 0 {
				return nil
			}
			if held != nil {
				out := [][]byte{p, held, p}
				held = nil
				return out
			}
			if count%5 == 0 {
				held = p
				return nil
			}
			return [][]byte{p}
		}
	}
	a, b, rawA, rawB := testKCPPair(t, impair(), impair())
	a.SetDeadline(time.Now().Add(15 * time.Second))
	b.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte("ordered payload"), 30000)
	result := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(b)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("payload mismatch before EOF")
		}
		if err == nil {
			_, err = b.Write([]byte("reply after EOF"))
		}
		if err == nil {
			err = b.CloseWrite()
		}
		result <- err
	}()
	if _, err := a.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after FIN: %v", err)
	}
	got, err := io.ReadAll(a)
	if err != nil || string(got) != "reply after EOF" {
		t.Fatalf("reply %q: %v", got, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if rawA.maxWrite.Load()+datagramRecordOverhead > 1200 || rawB.maxWrite.Load()+datagramRecordOverhead > 1200 {
		t.Fatal("outer MTU exceeded")
	}
}

func TestKCPDeadlinesAndPoolClaim(t *testing.T) {
	a, b, _, _ := testKCPPair(t, nil, nil)
	a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %v", err)
	}
	a.SetReadDeadline(time.Time{})
	p := newConnPool()
	defer p.close()
	p.add(a)
	c := p.pick(time.Second)
	if c == nil {
		t.Fatal("deadline-interrupted idle session discarded")
	}
	a.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := a.Write([]byte("not sent")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline: %v", err)
	}
	a.SetWriteDeadline(time.Time{})
	if _, err := b.Write([]byte("first reply")); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	expectBytes(t, c, []byte("first reply"))
}

func TestKCPHeartbeatBlackholeAndIdlePoolRemoval(t *testing.T) {
	var blackhole atomic.Bool
	drop := func(p []byte) [][]byte {
		if blackhole.Load() {
			return nil
		}
		return [][]byte{p}
	}
	a, b, _, _ := testKCPPair(t, drop, drop)
	p := newConnPool()
	defer p.close()
	p.add(a)
	// Idle heartbeats must not be mistaken for an application activation.
	time.Sleep(1200 * time.Millisecond)
	if p.size() != 1 {
		t.Fatal("healthy idle session lost")
	}
	blackhole.Store(true)
	await(t, func() bool { return p.size() == 0 }, func() string { return "blackholed idle session retained" })
	select {
	case <-b.done:
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not detect blackhole")
	}
}

func TestKCPFINACKLossAndBoundedClose(t *testing.T) {
	var dropped atomic.Bool
	a, b, _, _ := testKCPPair(t, nil, func(p []byte) [][]byte {
		if p[4] == kcpPacketFINACK && dropped.CompareAndSwap(false, true) {
			return nil
		}
		return [][]byte{p}
	})
	if _, err := a.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "tail" {
		t.Fatalf("close lost data: %q %v", got, err)
	}
	if !dropped.Load() {
		t.Fatal("FIN ACK loss was not exercised")
	}
}

func TestKCPBackpressureDeadlineAndHeartbeat(t *testing.T) {
	a, b, _, _ := testKCPPair(t, nil, nil)
	result := make(chan error, 1)
	go func() { _, err := a.Write(bytes.Repeat([]byte("x"), 4<<20)); result <- err }()
	// Let the receiver fill, then interrupt an already blocked writer.
	time.Sleep(1500 * time.Millisecond)
	select {
	case <-a.done:
		t.Fatal("backpressure mistaken for dead peer")
	default:
	}
	a.SetWriteDeadline(time.Now())
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not interrupt")
	}
	b.mu.Lock()
	buffered := b.buffer.Len()
	b.mu.Unlock()
	if buffered > kcpReceiveLimit {
		t.Fatalf("unbounded receive buffer: %d", buffered)
	}
}

func TestKCPPartialFrameReadDeadline(t *testing.T) {
	a, b, _, _ := testKCPPair(t, nil, nil)
	// Inject a split frame at the stream boundary, not at a UDP boundary.
	if _, err := b.sess.Write([]byte{kcpFrameData, 0}); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.sess.Write([]byte{3, 'a', 'b', 'c'}); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, a, []byte("abc"))
}

func TestKCPCloseUnblocksWriterAndReader(t *testing.T) {
	a, _, rawA, _ := testKCPPair(t, nil, nil)
	rawA.hookMu.Lock()
	rawA.hook = func([]byte) [][]byte { return nil }
	rawA.hookMu.Unlock()
	writeDone := make(chan error, 1)
	readDone := make(chan error, 1)
	go func() { _, err := a.Write(make([]byte, 4<<20)); writeDone <- err }()
	go func() { _, err := a.Read(make([]byte, 1)); readDone <- err }()
	closeDone := make(chan struct{})
	go func() { a.Close(); close(closeDone) }()
	for _, done := range []<-chan error{writeDone, readDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked operation succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("close left operation blocked")
		}
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close did not return")
	}
}

func TestKCPOneWayLossAndForgedLiveness(t *testing.T) {
	var loseReplies atomic.Bool
	a, _, _, _ := testKCPPair(t, nil, func(p []byte) [][]byte {
		if !loseReplies.Load() {
			return [][]byte{p}
		}
		// Incoming ping/data traffic alone cannot prove a bidirectional path.
		// A repeated old pong must not keep a dead session alive either.
		if p[4] == kcpPacketPong {
			clear(p[5:])
		}
		return [][]byte{p}
	})
	loseReplies.Store(true)
	select {
	case <-a.done:
		if !errors.Is(a.packets.terminal(), os.ErrDeadlineExceeded) {
			t.Fatalf("expected heartbeat timeout, got %v", a.packets.terminal())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("one-way failure was masked by incoming traffic")
	}
}

func TestKCPGracefulCloseDrainsBufferedTail(t *testing.T) {
	a, b, _, _ := testKCPPair(t, nil, nil)
	payload := bytes.Repeat([]byte("tail"), 100000)
	done := make(chan error, 1)
	go func() {
		_, err := a.Write(payload)
		if err == nil {
			err = a.Close()
		}
		done <- err
	}()
	// The tail exceeds the receive budget: close must wait for its FIN,
	// which follows all queued data, rather than merely flushing KCP once.
	time.Sleep(100 * time.Millisecond)
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("truncated close: %d/%d bytes, %v", len(got), len(payload), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKCPProtocolMismatchAndInvalidFrames(t *testing.T) {
	for _, kind := range []string{"envelope", "empty-data", "oversized", "data-after-fin"} {
		t.Run(kind, func(t *testing.T) {
			a, b, _, rawB := testKCPPair(t, nil, nil)
			switch kind {
			case "envelope":
				rawB.Write([]byte("native DTLS record"))
			case "empty-data":
				b.sess.Write([]byte{kcpFrameData, 0, 0})
			case "oversized":
				b.sess.Write([]byte{kcpFrameData, 255, 255})
			case "data-after-fin":
				b.CloseWrite()
				b.sess.Write([]byte{kcpFrameData, 0, 1, 'x'})
			}
			select {
			case <-a.done:
			case <-time.After(time.Second):
				t.Fatal("invalid protocol was accepted")
			}
		})
	}
}

// Simulate a carrier write stuck below KCP's mutex. Closing the carrier
// releases it; changing a KCP deadline cannot acquire the mutex to do so.
type stalledKCPConn struct {
	*testRecordConn
	stall   atomic.Bool
	writing chan struct{}
	once    sync.Once
}

func (c *stalledKCPConn) Write(p []byte) (int, error) {
	if c.stall.Load() {
		c.once.Do(func() { close(c.writing) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.testRecordConn.Write(p)
}

func TestKCPCloseInterruptsBlockedCarrier(t *testing.T) {
	for _, half := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "close-write"}[half], func(t *testing.T) {
			rawA, rawB := newTestRecordPipe()
			blocked := &stalledKCPConn{testRecordConn: rawA, writing: make(chan struct{})}
			cfg := defaultKCPSettings()
			cfg.CloseTimeout = 150 * time.Millisecond
			a, err := newKCPStream(blocked, cfg)
			if err != nil {
				t.Fatal(err)
			}
			b, err := newKCPStream(rawB, cfg)
			if err != nil {
				a.abort(err)
				t.Fatal(err)
			}
			t.Cleanup(func() { a.abort(net.ErrClosed); b.abort(net.ErrClosed) })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := a.WaitReady(ctx); err != nil {
				t.Fatal(err)
			}
			if err := b.WaitReady(ctx); err != nil {
				t.Fatal(err)
			}
			blocked.stall.Store(true)
			written := make(chan struct{})
			go func() { a.Write(make([]byte, 1<<20)); close(written) }()
			select {
			case <-blocked.writing:
			case <-ctx.Done():
				t.Fatal("carrier did not block")
			}
			closed := make(chan struct{})
			go func() {
				if half {
					a.CloseWrite()
				} else {
					a.Close()
				}
				close(closed)
			}()
			for _, done := range []<-chan struct{}{closed, written} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("carrier write defeated close deadline")
				}
			}
		})
	}
}
