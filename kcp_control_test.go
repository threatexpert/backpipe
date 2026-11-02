package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func kcpTestRecord(kind byte, payload []byte) []byte {
	return append(append(bytes.Clone(kcpMagic), kind), payload...)
}

func waitKCPTestDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("KCP worker did not finish")
	}
}

func TestKCPControlReceiveProgressDuringBlockedWrite(t *testing.T) {
	raw, peer := newTestRecordPipe()
	defer peer.Close()
	blocked := &stalledKCPConn{testRecordConn: raw, writing: make(chan struct{})}
	blocked.stall.Store(true)
	p := newKCPPackets(blocked, defaultKCPSettings())
	t.Cleanup(func() { p.Close() })
	p.sent = 7
	p.finSent.Store(true)
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		n, _, err := p.ReadFrom(buf)
		if err == nil && string(buf[:n]) != "still receiving" {
			err = io.ErrUnexpectedEOF
		}
		result <- err
	}()
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], 1)
	peer.Write(kcpTestRecord(kcpPacketPing, seq[:]))
	waitKCPTestDone(t, blocked.writing)
	// A stalled pong must not block newer pings, liveness replies, FINACK,
	// or KCP data. Thousands of replies collapse into a fixed-size state.
	for i := uint64(2); i <= 2000; i++ {
		binary.BigEndian.PutUint64(seq[:], i)
		peer.Write(kcpTestRecord(kcpPacketPing, seq[:]))
	}
	binary.BigEndian.PutUint64(seq[:], 3) // reordered ping cannot replace 2000
	peer.Write(kcpTestRecord(kcpPacketPing, seq[:]))
	binary.BigEndian.PutUint64(seq[:], 7)
	peer.Write(kcpTestRecord(kcpPacketPong, seq[:]))
	peer.Write(kcpTestRecord(kcpPacketFINACK, nil))
	peer.Write(kcpTestRecord(kcpPacketData, []byte("still receiving")))
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop waited behind a blocked pong")
	}
	p.mu.Lock()
	acked := p.acked
	p.mu.Unlock()
	if acked != 7 {
		t.Fatal("valid liveness reply was not processed")
	}
	waitKCPTestDone(t, p.finAck)
	p.controlMu.Lock()
	pending, newest := p.pongPending, p.pong
	p.controlMu.Unlock()
	if !pending || newest != 2000 {
		t.Fatalf("pong coalescing: pending=%t sequence=%d", pending, newest)
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	waitKCPTestDone(t, closed)
	waitKCPTestDone(t, p.controlDone)
}

func TestKCPControlsPrecedeNextDataAndCoalesce(t *testing.T) {
	raw, peer := newTestRecordPipe()
	defer peer.Close()
	p := newKCPPackets(raw, defaultKCPSettings())
	t.Cleanup(func() { p.Close() })
	<-p.writeGate
	for i := uint64(1); i <= 1000; i++ {
		p.queueControl(kcpPacketPong, i)
		p.queueControl(kcpPacketFINACK, 0)
	}
	result := make(chan error, 1)
	go func() { result <- p.send(kcpPacketData, []byte("data")) }()
	p.writeGate <- struct{}{}
	for _, kind := range []byte{kcpPacketFINACK, kcpPacketPong, kcpPacketData} {
		select {
		case record := <-peer.rx:
			if record[4] != kind {
				t.Fatalf("control priority: got %d want %d", record[4], kind)
			}
			if kind == kcpPacketPong && binary.BigEndian.Uint64(record[5:]) != 1000 {
				t.Fatal("did not send newest pong")
			}
		case <-time.After(time.Second):
			t.Fatal("missing record")
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	p.Close()
	if len(peer.rx) != 0 {
		t.Fatal("coalesced controls were sent repeatedly")
	}
}

func TestKCPControlCloseInterruptsGateWait(t *testing.T) {
	raw, peer := newTestRecordPipe()
	defer peer.Close()
	p := newKCPPackets(raw, defaultKCPSettings())
	<-p.writeGate
	p.queueControl(kcpPacketPong, 1)
	result := make(chan error, 1)
	go func() { result <- p.send(kcpPacketData, nil) }()
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	waitKCPTestDone(t, closed)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed writer succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt gate wait")
	}
	p.writeGate <- struct{}{}
}

func TestKCPACKModesWithLossAndHalfClose(t *testing.T) {
	for _, immediate := range []bool{false, true} {
		name := "batched"
		if immediate {
			name = "immediate"
		}
		t.Run(name, func(t *testing.T) {
			count := 0
			a, b, _, _ := testKCPPair(t, func(packet []byte) [][]byte {
				if packet[4] == kcpPacketData {
					count++
					if count%11 == 0 {
						return nil
					}
				}
				return [][]byte{packet}
			}, nil, func(cfg *kcpSettings) { cfg.ACKNoDelay = immediate })
			a.SetDeadline(time.Now().Add(5 * time.Second))
			b.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("ack-mode"), 16000)
			result := make(chan error, 1)
			go func() {
				_, err := a.Write(payload)
				if err == nil {
					err = a.CloseWrite()
				}
				result <- err
			}()
			got, err := io.ReadAll(b)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("loss/half-close: %d bytes, %v", len(got), err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if _, err := b.Write([]byte("reply")); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, a, []byte("reply"))
			a.abort(net.ErrClosed)
			waitKCPTestDone(t, a.packets.controlDone)
		})
	}
}
