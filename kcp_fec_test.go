package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

func TestKCPFECRecoveryAndHalfClose(t *testing.T) {
	for _, tc := range []struct{ mtu, data, parity int }{{576, 10, 3}, {1200, 10, 3}, {1400, 10, 3}, {1200, 4, 2}, {1200, 32, 32}} {
		t.Run(fmt.Sprintf("mtu%d_fec%d:%d", tc.mtu, tc.data, tc.parity), func(t *testing.T) {
			var dropped, parity atomic.Int64
			impair := func() func([]byte) [][]byte {
				var held []byte
				return func(p []byte) [][]byte {
					if p[4] != kcpPacketFECData {
						return [][]byte{p}
					}
					// Envelope (7), then kcp-go FEC sequence (4) and type (2).
					seq := binary.LittleEndian.Uint32(p[7:])
					kind := binary.LittleEndian.Uint16(p[11:])
					if kind == 0xf2 {
						parity.Add(1)
					}
					groupSize := uint32(tc.data + tc.parity)
					if seq%groupSize == 2 { // erase one data shard per group
						dropped.Add(1)
						return nil
					}
					if held != nil {
						out := [][]byte{p, held, p}
						held = nil
						return out
					}
					if seq%groupSize == 4 { // reorder and duplicate within the group
						held = p
						return nil
					}
					return [][]byte{p}
				}
			}
			before := kcp.DefaultSnmp.Copy().FECRecovered
			a, b, rawA, rawB := testKCPPair(t, impair(), impair(), func(cfg *kcpSettings) {
				cfg.FECData, cfg.FECParity, cfg.MTU = tc.data, tc.parity, tc.mtu
			})
			a.SetDeadline(time.Now().Add(10 * time.Second))
			b.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("FEC loss/reorder/half-close"), 10000)
			result := make(chan error, 1)
			go func() {
				got, err := io.ReadAll(b)
				if err == nil && !bytes.Equal(got, payload) {
					err = fmt.Errorf("request payload corrupted")
				}
				if err == nil {
					err = writeAll(b, payload)
				}
				if err == nil {
					err = b.CloseWrite()
				}
				result <- err
			}()
			if err := writeAll(a, payload); err != nil {
				t.Fatal(err)
			}
			if err := a.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(a)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("reply payload: %d bytes, %v", len(got), err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if dropped.Load() == 0 || parity.Load() == 0 || kcp.DefaultSnmp.Copy().FECRecovered <= before {
				t.Fatal("test did not exercise FEC recovery")
			}
			if rawA.maxWrite.Load()+datagramRecordOverhead > int64(tc.mtu) || rawB.maxWrite.Load()+datagramRecordOverhead > int64(tc.mtu) {
				t.Fatal("FEC data/parity exceeded outer MTU")
			}
		})
	}
}

func TestKCPFECProfileMismatch(t *testing.T) {
	for _, profiles := range [][2]string{{"off", "10:3"}, {"10:3", "off"}, {"10:3", "10:2"}, {"10:3", "9:3"}} {
		t.Run(profiles[0]+"/"+profiles[1], func(t *testing.T) {
			a, b := newTestRecordPipe()
			defer a.Close()
			defer b.Close()
			cfgA, cfgB := defaultKCPSettings(), defaultKCPSettings()
			cfgA.setFEC(profiles[0])
			cfgB.setFEC(profiles[1])
			ca, err := newKCPStream(a, cfgA)
			if err != nil {
				t.Fatal(err)
			}
			defer ca.abort(net.ErrClosed)
			cb, cbErr := newKCPStream(b, cfgB)
			if cb != nil {
				defer cb.abort(net.ErrClosed)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = ca.WaitReady(ctx)
			if cbErr == nil {
				cbErr = cb.WaitReady(ctx)
			}
			if err == nil || cbErr == nil {
				t.Fatalf("mismatched profiles reached ready: %v, %v", err, cbErr)
			}
			if !strings.Contains(fmt.Sprint(err, cbErr), "FEC mismatch") {
				t.Fatalf("missing configuration diagnostic: %v, %v", err, cbErr)
			}
		})
	}
}

// Check the actual sender behavior, not just the parsed flag: with all ACKs
// suppressed after the handshake, disabling cwnd permits a larger initial burst.
func TestKCPCongestionControlSwitch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("congestion=%t", enabled), func(t *testing.T) {
			var measure atomic.Bool
			var mu sync.Mutex
			segments := make(map[uint32]bool)
			capture := func(p []byte) [][]byte {
				if measure.Load() && p[4] == kcpPacketData {
					for b := p[5:]; len(b) >= 24; {
						if b[4] == 81 {
							mu.Lock()
							segments[binary.LittleEndian.Uint32(b[12:])] = true
							mu.Unlock()
						}
						n := 24 + int(binary.LittleEndian.Uint32(b[20:]))
						b = b[n:]
					}
					return nil
				}
				return [][]byte{p}
			}
			a, _, _, _ := testKCPPair(t, capture, nil, func(cfg *kcpSettings) { cfg.NoCongestion = !enabled })
			time.Sleep(50 * time.Millisecond) // settle HELLO acknowledgments
			measure.Store(true)
			if err := writeAll(a, make([]byte, 32<<10)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			mu.Lock()
			n := len(segments)
			mu.Unlock()
			if (!enabled && n < 16) || (enabled && (n == 0 || n >= 16)) {
				t.Fatalf("unexpected initial flight with congestion=%t: %d segments", enabled, n)
			}
		})
	}
}
