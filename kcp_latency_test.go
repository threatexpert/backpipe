package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type delayedKCPRecord struct {
	at   time.Time
	data []byte
}

// Delay propagation without sleeping in Write: local write queueing would
// incorrectly simulate a slow socket instead of a high-latency network.
type delayedKCPConn struct {
	*testRecordConn
	delay   time.Duration
	queue   chan delayedKCPRecord
	done    chan struct{}
	packets atomic.Int64
	drops   atomic.Int64
}

func newDelayedKCPConn(raw *testRecordConn, delay time.Duration) *delayedKCPConn {
	c := &delayedKCPConn{testRecordConn: raw, delay: delay, queue: make(chan delayedKCPRecord, 2048), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			select {
			case <-c.closed:
				return
			case record := <-c.queue:
				timer := time.NewTimer(time.Until(record.at))
				select {
				case <-c.closed:
					timer.Stop()
					return
				case <-timer.C:
				}
				select {
				case c.peer.rx <- record.data:
				case <-c.closed:
					return
				case <-c.peer.closed:
					return
				}
			}
		}
	}()
	return c
}

func (c *delayedKCPConn) Write(data []byte) (int, error) {
	if data[4] == kcpPacketData && c.packets.Add(1)%7 == 0 {
		c.drops.Add(1)
		return len(data), nil
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.queue <- delayedKCPRecord{time.Now().Add(c.delay), bytes.Clone(data)}:
		return len(data), nil
	default:
		c.drops.Add(1)
		return len(data), nil
	}
}

func TestKCPACKModesHighRTT(t *testing.T) {
	for _, rtt := range []time.Duration{100 * time.Millisecond, 500 * time.Millisecond} {
		for _, immediate := range []bool{false, true} {
			t.Run(fmt.Sprintf("rtt%s_immediate%t", rtt, immediate), func(t *testing.T) {
				ra, rb := newTestRecordPipe()
				a, b := newDelayedKCPConn(ra, rtt/2), newDelayedKCPConn(rb, rtt/2)
				t.Cleanup(func() {
					a.Close()
					b.Close()
					waitKCPTestDone(t, a.done)
					waitKCPTestDone(t, b.done)
				})
				cfg := defaultKCPSettings()
				cfg.ACKNoDelay = immediate
				cfg.Heartbeat, cfg.Timeout = 100*time.Millisecond, 3*time.Second
				left, err := newKCPStream(a, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { left.abort(net.ErrClosed) })
				right, err := newKCPStream(b, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { right.abort(net.ErrClosed) })
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				for _, stream := range []*kcpStreamConn{left, right} {
					if err := stream.WaitReady(ctx); err != nil {
						t.Fatal(err)
					}
				}
				start := time.Now()
				for i := 0; i < 8; i++ {
					deadline := time.Now().Add(3 * time.Second)
					left.SetDeadline(deadline)
					right.SetDeadline(deadline)
					if _, err := left.Write([]byte("query")); err != nil {
						t.Fatal(err)
					}
					expectBytes(t, right, []byte("query"))
					if _, err := right.Write([]byte("reply")); err != nil {
						t.Fatal(err)
					}
					expectBytes(t, left, []byte("reply"))
				}
				if a.drops.Load()+b.drops.Load() == 0 {
					t.Fatal("loss was not exercised")
				}
				t.Logf("8 request/replies with loss: %s", time.Since(start))
			})
		}
	}
}
