package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This transport preserves DTLS record boundaries and can drop, duplicate and
// reorder application records. net.Pipe is a stream and cannot model DTLS Read.
type testRecordConn struct {
	peer              *testRecordConn
	rx                chan []byte
	closed            chan struct{}
	once              sync.Once
	mu                sync.Mutex
	deadline          time.Time
	wake              chan struct{}
	hookMu            sync.Mutex
	hook              func([]byte) [][]byte
	maxWrite          atomic.Int64
	readDeadlineCalls atomic.Int64
	readers           atomic.Int64
	concurrentReaders atomic.Bool
}

func newTestRecordPipe() (*testRecordConn, *testRecordConn) {
	a := &testRecordConn{rx: make(chan []byte, 2048), closed: make(chan struct{}), wake: make(chan struct{})}
	b := &testRecordConn{rx: make(chan []byte, 2048), closed: make(chan struct{}), wake: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *testRecordConn) Read(buf []byte) (int, error) {
	if c.readers.Add(1) != 1 {
		c.concurrentReaders.Store(true)
	}
	defer c.readers.Add(-1)
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, io.EOF
	case p := <-c.rx:
		if len(p) > len(buf) {
			return 0, io.ErrShortBuffer
		}
		return copy(buf, p), nil
	}
}

func (c *testRecordConn) Write(p []byte) (int, error) {
	for {
		old := c.maxWrite.Load()
		if int64(len(p)) <= old || c.maxWrite.CompareAndSwap(old, int64(len(p))) {
			break
		}
	}
	copyP := bytes.Clone(p)
	c.hookMu.Lock()
	out := [][]byte{copyP}
	if c.hook != nil {
		out = c.hook(copyP)
	}
	c.hookMu.Unlock()
	for _, packet := range out {
		for {
			c.mu.Lock()
			deadline, wake := c.deadline, c.wake
			c.mu.Unlock()
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			var timer *time.Timer
			var timeout <-chan time.Time
			if !deadline.IsZero() {
				timer = time.NewTimer(time.Until(deadline))
				timeout = timer.C
			}
			sent := false
			select {
			case <-c.closed:
				if timer != nil {
					timer.Stop()
				}
				return 0, net.ErrClosed
			case <-c.peer.closed:
				if timer != nil {
					timer.Stop()
				}
				return 0, io.EOF
			case <-wake:
			case <-timeout:
			case c.peer.rx <- bytes.Clone(packet):
				sent = true
			}
			if timer != nil {
				timer.Stop()
			}
			if sent {
				break
			}
		}
	}
	return len(p), nil
}

func (c *testRecordConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (c *testRecordConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}
func (c *testRecordConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
}
func (c *testRecordConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *testRecordConn) SetReadDeadline(time.Time) error { c.readDeadlineCalls.Add(1); return nil }
func (c *testRecordConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	close(c.wake)
	c.wake = make(chan struct{})
	return nil
}

func newTestDatagramPair(t *testing.T, serverCfg, agentCfg datagramSessionConfig, serverHook, agentHook func([]byte) [][]byte) (*datagramSession, *datagramSession, *testRecordConn, *testRecordConn) {
	t.Helper()
	sc, ac := newTestRecordPipe()
	sc.hook, ac.hook = serverHook, agentHook
	serverCfg.Server = true
	agentCfg.Server = false
	server := newDatagramSession(sc, serverCfg)
	agent := newDatagramSession(ac, agentCfg)
	t.Cleanup(func() {
		server.Close()
		agent.Close()
		if sc.concurrentReaders.Load() || ac.concurrentReaders.Load() {
			t.Error("more than one underlying record reader")
		}
		if sc.readDeadlineCalls.Load() != 0 || ac.readDeadlineCalls.Load() != 0 {
			t.Error("business deadline changed the underlying record reader")
		}
	})
	return server, agent, sc, ac
}

func openTestDatagramPair(t *testing.T, server, agent *datagramSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := agent.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := server.Open(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-agent.Activated():
	default:
		t.Fatal("agent was not activated")
	}
}

func testDatagramFrame(id uint64, total, offset int, payload []byte) []byte {
	frame := make([]byte, datagramHeaderSize+len(payload))
	copy(frame, datagramMagic[:])
	frame[4] = datagramData
	binary.BigEndian.PutUint64(frame[6:14], id)
	binary.BigEndian.PutUint16(frame[14:16], uint16(total))
	binary.BigEndian.PutUint16(frame[16:18], uint16(offset))
	copy(frame[18:], payload)
	return frame
}

func TestDatagramSessionControlRetryAndPrepareOnce(t *testing.T) {
	var prepared atomic.Int64
	serverDrops := map[byte]bool{datagramReady: true, datagramReadyACK: true, datagramOpen: true}
	agentDrops := map[byte]bool{datagramReady: true, datagramReadyACK: true, datagramOpenACK: true}
	drop := func(kinds map[byte]bool) func([]byte) [][]byte {
		return func(p []byte) [][]byte {
			if kinds[p[4]] {
				delete(kinds, p[4])
				return nil
			}
			return [][]byte{p}
		}
	}
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{Prepare: func(*datagramSession) (func(), error) {
		prepared.Add(1)
		return nil, nil
	}}, drop(serverDrops), drop(agentDrops))
	if err := s.WritePacket([]byte("early")); !errors.Is(err, errDatagramNotActive) {
		t.Fatalf("early DATA: %v", err)
	}
	openTestDatagramPair(t, s, a)
	if prepared.Load() != 1 {
		t.Fatalf("Prepare called %d times", prepared.Load())
	}
	if err := s.WritePacket([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	p, err := a.ReadPacket(make([]byte, 32))
	if err != nil || string(p) != "hello" {
		t.Fatalf("packet %q: %v", p, err)
	}
}

func TestDatagramSessionLargePacketReorderDuplicateAndMTU(t *testing.T) {
	var held [][]byte
	reorder := func(p []byte) [][]byte {
		if p[4] != datagramData {
			return [][]byte{p}
		}
		held = append(held, p)
		if int(binary.BigEndian.Uint16(p[16:18]))+len(p)-18 != int(binary.BigEndian.Uint16(p[14:16])) {
			return nil
		}
		out := make([][]byte, 0, 2*len(held))
		for i := len(held) - 1; i >= 0; i-- {
			out = append(out, held[i], held[i])
		}
		held = nil
		return out
	}
	s, a, sc, _ := newTestDatagramPair(t, datagramSessionConfig{MTU: 1400}, datagramSessionConfig{MTU: 900}, reorder, nil)
	openTestDatagramPair(t, s, a)
	payload := make([]byte, datagramMaxPacket)
	for i := range payload {
		payload[i] = byte(i * 17)
	}
	if err := s.WritePacket(payload); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	p, err := a.ReadPacket(make([]byte, datagramMaxPacket))
	if err != nil || !bytes.Equal(p, payload) {
		t.Fatalf("large packet: len=%d err=%v", len(p), err)
	}
	if sc.maxWrite.Load()+datagramRecordOverhead > 900 {
		t.Fatalf("exceeded negotiated MTU: record %d", sc.maxWrite.Load())
	}
	a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := a.ReadPacket(make([]byte, datagramMaxPacket)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("duplicate was delivered: %v", err)
	}
	if err := a.WritePacket([]byte("reverse")); err != nil {
		t.Fatal(err)
	}
	s.SetReadDeadline(time.Now().Add(time.Second))
	p, err = s.ReadPacket(make([]byte, 32))
	if err != nil || string(p) != "reverse" {
		t.Fatalf("reverse packet: %q %v", p, err)
	}
}

func TestDatagramSessionLostFragmentDoesNotBlockNextPacket(t *testing.T) {
	drop := func(p []byte) [][]byte {
		if p[4] == datagramData && binary.BigEndian.Uint64(p[6:14]) == 1 && binary.BigEndian.Uint16(p[16:18]) != 0 {
			return nil
		}
		return [][]byte{p}
	}
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, drop, nil)
	openTestDatagramPair(t, s, a)
	if err := s.WritePacket(make([]byte, 4000)); err != nil {
		t.Fatal(err)
	}
	if err := s.WritePacket([]byte("next")); err != nil {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Now().Add(time.Second))
	p, err := a.ReadPacket(make([]byte, 65535))
	if err != nil || string(p) != "next" {
		t.Fatalf("later packet blocked: %q %v", p, err)
	}
	a.mu.Lock()
	if len(a.assemblies) != 1 {
		t.Errorf("expected one incomplete packet, got %d", len(a.assemblies))
	}
	for _, assembly := range a.assemblies {
		assembly.expires = time.Now().Add(-time.Second)
	}
	a.mu.Unlock()
	limit := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		count, memory := len(a.assemblies), a.memory
		a.mu.Unlock()
		if count == 0 {
			if memory != 0 {
				t.Errorf("expired packet retained %d bytes", memory)
			}
			break
		}
		if time.Now().After(limit) {
			t.Fatal("incomplete packet never expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDatagramSessionConflictingFragmentsAndReplay(t *testing.T) {
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
	openTestDatagramPair(t, s, a)
	a.receiveFragment(testDatagramFrame(1, 6, 0, []byte("abc")))
	a.receiveFragment(testDatagramFrame(1, 6, 2, []byte("XYZ"))) // overlap poisons this packet
	a.receiveFragment(testDatagramFrame(1, 6, 0, []byte("abcdef")))
	a.receiveFragment(testDatagramFrame(2, 6, 0, []byte("abc")))
	a.receiveFragment(testDatagramFrame(2, 7, 3, []byte("defg"))) // inconsistent total
	a.receiveFragment(testDatagramFrame(2, 6, 0, []byte("abcdef")))
	a.receiveFragment(testDatagramFrame(3, 6, 5, []byte("too long")))
	a.receiveFragment(testDatagramFrame(4, 2, 0, []byte("ok")))
	a.SetReadDeadline(time.Now().Add(time.Second))
	p, err := a.ReadPacket(make([]byte, 32))
	if err != nil || string(p) != "ok" {
		t.Fatalf("invalid fragment survived: %q %v", p, err)
	}
	a.receiveFragment(testDatagramFrame(5000, 1, 0, []byte("x")))
	a.receiveFragment(testDatagramFrame(4, 2, 0, []byte("ok"))) // older than replay window
	p, err = a.ReadPacket(make([]byte, 32))
	if err != nil || string(p) != "x" {
		t.Fatalf("new packet: %q %v", p, err)
	}
	a.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	if _, err := a.ReadPacket(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("old/rejected packet delivered: %v", err)
	}
}

func TestDatagramSessionPreparationRejectAndOpenTimeout(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		var prepared atomic.Int64
		s, _, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{Prepare: func(*datagramSession) (func(), error) {
			prepared.Add(1)
			return nil, errors.New("test socket creation failed")
		}}, nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Open(ctx); err == nil {
			t.Fatal("rejected preparation succeeded")
		}
		select {
		case <-s.Done():
		default:
			t.Fatal("failed Open did not close session")
		}
		select {
		case <-s.Activated():
			t.Fatal("rejected session activated")
		default:
		}
		if prepared.Load() != 1 {
			t.Fatalf("Prepare calls %d", prepared.Load())
		}
	})
	t.Run("lost_ack", func(t *testing.T) {
		var dataWrites atomic.Int64
		s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, func(p []byte) [][]byte {
			if p[4] == datagramData {
				dataWrites.Add(1)
			}
			return [][]byte{p}
		}, func(p []byte) [][]byte {
			if p[4] == datagramOpenACK {
				return nil
			}
			return [][]byte{p}
		})
		readyCtx, cancelReady := context.WithTimeout(context.Background(), time.Second)
		defer cancelReady()
		if err := s.WaitReady(readyCtx); err != nil {
			t.Fatal(err)
		}
		if err := a.WaitReady(readyCtx); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		if err := s.Open(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Open timeout: %v", err)
		}
		if err := s.WritePacket([]byte("must not escape")); err == nil {
			t.Fatal("DATA accepted after failed OPEN")
		}
		if dataWrites.Load() != 0 {
			t.Fatal("business data sent before OPEN acknowledgement")
		}
	})
}

func TestDatagramSessionDeadlinesDoNotStopHeartbeat(t *testing.T) {
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{Heartbeat: 40 * time.Millisecond}, datagramSessionConfig{Heartbeat: 40 * time.Millisecond}, nil, nil)
	openTestDatagramPair(t, s, a)
	s.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := s.ReadPacket(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %v", err)
	}
	// A business timeout must not prevent control packets from keeping the
	// association alive, and extending it must allow another business read.
	time.Sleep(180 * time.Millisecond)
	select {
	case <-s.Done():
		t.Fatalf("heartbeat stopped: %v", s.err())
	default:
	}
	s.SetReadDeadline(time.Time{})
	result := make(chan error, 1)
	go func() { _, err := s.ReadPacket(make([]byte, 32)); result <- err }()
	s.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("updated deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("changing deadline did not wake blocked reader")
	}
	s.SetReadDeadline(time.Now().Add(time.Second))
	if err := a.WritePacket([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	p, err := s.ReadPacket(make([]byte, 32))
	if err != nil || string(p) != "alive" {
		t.Fatalf("after heartbeat: %q %v", p, err)
	}
	s.SetWriteDeadline(time.Now().Add(-time.Second))
	if err := s.WritePacket([]byte("late")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline: %v", err)
	}
	s.SetWriteDeadline(time.Time{})
	if err := s.WritePacket([]byte("again")); err != nil {
		t.Fatal(err)
	}
}

func TestDatagramSessionHeartbeatDetectsSilentPeer(t *testing.T) {
	var drop atomic.Bool
	hook := func(p []byte) [][]byte {
		if drop.Load() {
			return nil
		}
		return [][]byte{p}
	}
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{Heartbeat: 40 * time.Millisecond}, datagramSessionConfig{Heartbeat: 40 * time.Millisecond}, hook, hook)
	openTestDatagramPair(t, s, a)
	drop.Store(true)
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("silent DTLS peer stayed alive")
	}
}

func TestDatagramSessionResourceLimitsAndClose(t *testing.T) {
	datagramResources.Lock()
	baselineMemory, baselinePieces := datagramResources.memory, datagramResources.pieces
	datagramResources.Unlock()
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
	openTestDatagramPair(t, s, a)
	for id := uint64(1); id <= 100; id++ {
		a.receiveFragment(testDatagramFrame(id, 65535, 0, []byte("x")))
	}
	a.mu.Lock()
	if a.memory > datagramSessionMemory || len(a.assemblies) > datagramMaxAssemblies || a.pieces > datagramSessionPieces {
		t.Error("per-session resource budget exceeded")
	}
	a.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := a.ReadPacket(make([]byte, 65535)); result <- err }()
	a.Close()
	s.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed ReadPacket succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadPacket")
	}
	datagramResources.Lock()
	memory, pieces := datagramResources.memory, datagramResources.pieces
	datagramResources.Unlock()
	if memory != baselineMemory || pieces != baselinePieces {
		t.Fatalf("resource leak: memory %d -> %d, pieces %d -> %d", baselineMemory, memory, baselinePieces, pieces)
	}
}

func TestDatagramSessionQueueAndFragmentCountLimits(t *testing.T) {
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
	openTestDatagramPair(t, s, a)
	for id := uint64(1); id <= 100; id++ {
		a.receiveFragment(testDatagramFrame(id, 1, 0, []byte("q")))
	}
	if len(a.packets) != datagramQueuePackets {
		t.Fatalf("queue has %d packets", len(a.packets))
	}
	a.mu.Lock()
	memory := a.memory
	a.mu.Unlock()
	if memory != datagramQueuePackets {
		t.Fatalf("queue retained %d bytes", memory)
	}
	for offset := 0; offset <= datagramMaxFragments; offset++ {
		a.receiveFragment(testDatagramFrame(101, 1000, offset, []byte("f")))
	}
	a.mu.Lock()
	count, pieces := len(a.assemblies), a.pieces
	a.mu.Unlock()
	if count != 0 || pieces != 0 {
		t.Fatalf("excess fragment packet retained: assemblies=%d pieces=%d", count, pieces)
	}
}

func TestDatagramSessionReplayRingKeepsInWindowPackets(t *testing.T) {
	s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
	openTestDatagramPair(t, s, a)
	for _, id := range []uint64{1, 4097, 4096, 4097, 1, 4096, 2} {
		a.receiveFragment(testDatagramFrame(id, 1, 0, []byte{byte(id)}))
	}
	for _, want := range []byte{1, 1, 0, 2} {
		a.SetReadDeadline(time.Now().Add(time.Second))
		packet, err := a.ReadPacket(make([]byte, 8))
		if err != nil || len(packet) != 1 || packet[0] != want {
			t.Fatalf("replay ring packet %v, want %d: %v", packet, want, err)
		}
	}
	if len(a.packets) != 0 {
		t.Fatal("duplicate packet survived ring wrap")
	}
}

func TestDatagramSessionCloseAndDeadlineUnblockQueuedWriter(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "close"}[closeSession], func(t *testing.T) {
			s, a, _, _ := newTestDatagramPair(t, datagramSessionConfig{}, datagramSessionConfig{}, nil, nil)
			openTestDatagramPair(t, s, a)
			<-s.writeGate
			defer func() { s.writeGate <- struct{}{} }()
			result := make(chan error, 1)
			go func() { result <- s.WritePacket([]byte("blocked")) }()
			if closeSession {
				s.Close()
			} else {
				s.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("blocked write succeeded")
				}
				if !closeSession && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("queued write deadline: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("queued writer did not unblock")
			}
		})
	}
}

func TestDatagramSessionGlobalFragmentBudget(t *testing.T) {
	sessions := make([]*datagramSession, 0, 30)
	defer func() {
		for _, s := range sessions {
			s.mu.Lock()
			s.releaseLocked(s.memory, s.pieces)
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 30; i++ {
		s := &datagramSession{}
		sessions = append(sessions, s)
		s.mu.Lock()
		accepted := s.reserveLocked(0, datagramSessionPieces)
		s.mu.Unlock()
		if !accepted {
			datagramResources.Lock()
			pieces := datagramResources.pieces
			datagramResources.Unlock()
			if pieces > datagramGlobalPieces || pieces < datagramGlobalPieces-datagramSessionPieces {
				t.Fatalf("unexpected global piece count %d", pieces)
			}
			return
		}
	}
	t.Fatal("global fragment limit did not reject allocations")
}

func TestDatagramSessionGlobalBudget(t *testing.T) {
	// No goroutines or transport are needed to exercise global accounting.
	sessions := make([]*datagramSession, 0, 100)
	defer func() {
		for _, s := range sessions {
			s.mu.Lock()
			s.releaseLocked(s.memory, s.pieces)
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 100; i++ {
		s := &datagramSession{}
		sessions = append(sessions, s)
		s.mu.Lock()
		accepted := s.reserveLocked(datagramSessionMemory, 100)
		s.mu.Unlock()
		if !accepted {
			datagramResources.Lock()
			memory := datagramResources.memory
			datagramResources.Unlock()
			if memory > datagramGlobalMemory || memory < datagramGlobalMemory-datagramSessionMemory {
				t.Fatalf("unexpected global memory usage %d", memory)
			}
			return
		}
	}
	t.Fatal("global memory limit did not reject allocations")
}
