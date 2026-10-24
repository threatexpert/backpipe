package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// Most queue tests register sessions without starting their consumers. This
// makes the exact admission boundary deterministic without relying on UDP loss
// or goroutine scheduling. The pipe tests below also exercise the real run loop.
func newForwardQueueFixture(t *testing.T) (*udpForwarder, context.CancelFunc) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	header, err := udpForwardHeader("charon:500")
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	options, err := newProxyOptions("", 5*time.Second)
	if err != nil {
		cancel()
		udp.Close()
		t.Fatal(err)
	}
	options.poolWait = time.Second
	f := &udpForwarder{
		udp: udp, pool: newConnPool(), target: "charon:500", header: header,
		options: options, ctx: ctx, writes: make(chan struct{}, 1),
		sessions: make(map[string]*udpForwardSession),
	}
	t.Cleanup(func() {
		cancel()
		f.mu.Lock()
		sessions := make([]*udpForwardSession, 0, len(f.sessions))
		for _, s := range f.sessions {
			sessions = append(sessions, s)
		}
		f.mu.Unlock()
		for _, s := range sessions {
			s.stop()
		}
		f.wg.Wait()
		// run() cleans its own sessions. Only the deliberately unstarted
		// sessions remain; do not call cleanup twice on a completed run.
		f.mu.Lock()
		sessions = sessions[:0]
		for _, s := range f.sessions {
			sessions = append(sessions, s)
		}
		f.mu.Unlock()
		for _, s := range sessions {
			s.cleanup()
		}
		f.pool.close()
		udp.Close()
	})
	return f, cancel
}

func registerForwardQueueSession(f *udpForwarder, index int, pending bool) *udpForwardSession {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10000 + index}
	ctx, cancel := context.WithCancel(f.ctx)
	s := &udpForwardSession{
		owner: f, peer: peer, key: peer.String(), packets: make(chan []byte, udpForwardQueuePackets),
		ctx: ctx, cancel: cancel, pending: pending,
	}
	f.mu.Lock()
	f.sessions[s.key] = s
	if pending {
		f.pending++
	}
	f.mu.Unlock()
	return s
}

func snapshotForwardQueue(f *udpForwarder, s *udpForwardSession) (udpForwardQueueStats, udpForwardDrops, udpForwardQueueStats, udpForwardDrops) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		return f.queueStats, f.drops, udpForwardQueueStats{}, udpForwardDrops{}
	}
	return f.queueStats, f.drops, s.queueStats, s.drops
}

func consumeForwardQueuePacket(t *testing.T, s *udpForwardSession) []byte {
	t.Helper()
	select {
	case payload := <-s.packets:
		s.dequeue(payload)
		return payload
	default:
		t.Fatal("expected a queued datagram")
		return nil
	}
}

func TestForwardQueuePacketLimitAndPayloadOwnership(t *testing.T) {
	f, _ := newForwardQueueFixture(t)
	s := registerForwardQueueSession(f, 1, false)
	payload := []byte("original")
	for i := 0; i < udpForwardQueuePackets; i++ {
		f.enqueue(s.peer, payload)
	}
	f.enqueue(s.peer, []byte("overflow"))
	payload[0] = 'X'
	fq, fd, sq, sd := snapshotForwardQueue(f, s)
	if fq.packets != 256 || sq.packets != 256 || len(s.packets) != 256 {
		t.Fatalf("packet limit: listener=%+v session=%+v channel=%d", fq, sq, len(s.packets))
	}
	if fq.bytes != 256*len(payload) || sq.bytes != fq.bytes || fd.queuePackets != 1 || sd.queuePackets != 1 {
		t.Fatalf("overflow changed budget or missed counter: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
	if got := consumeForwardQueuePacket(t, s); string(got) != "original" {
		t.Fatalf("queue borrowed receive buffer: %q", got)
	}
	f.enqueue(s.peer, []byte("replacement"))
	fq, fd, sq, sd = snapshotForwardQueue(f, s)
	if sq.packets != 256 || fq.packets != 256 || sq.peakPackets != 256 || fq.peakPackets != 256 || fd.queuePackets != 1 || sd.queuePackets != 1 {
		t.Fatalf("one freed slot was not reusable: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
}

func TestForwardQueueSessionByteLimitAndIsolation(t *testing.T) {
	f, _ := newForwardQueueFixture(t)
	a := registerForwardQueueSession(f, 1, false)
	b := registerForwardQueueSession(f, 2, false)
	payload := make([]byte, 32768)
	for i := 0; i < 8; i++ {
		f.enqueue(a.peer, payload)
	}
	f.enqueue(a.peer, []byte("x"))
	f.enqueue(b.peer, []byte("independent"))
	fq, fd, aq, ad := snapshotForwardQueue(f, a)
	_, _, bq, bd := snapshotForwardQueue(f, b)
	if aq.bytes != udpForwardSessionQueuedBytes || aq.packets != 8 || ad.sessionBytes != 1 || fd.sessionBytes != 1 {
		t.Fatalf("session byte cap: listener=%+v/%+v session=%+v/%+v", fq, fd, aq, ad)
	}
	if bq.packets != 1 || bq.bytes != len("independent") || bd != (udpForwardDrops{}) {
		t.Fatalf("one full session blocked another: %+v/%+v", bq, bd)
	}
	consumeForwardQueuePacket(t, a)
	f.enqueue(a.peer, payload)
	_, _, aq, ad = snapshotForwardQueue(f, a)
	if aq.bytes != udpForwardSessionQueuedBytes || aq.peakBytes != udpForwardSessionQueuedBytes || ad.sessionBytes != 1 {
		t.Fatalf("byte budget not reusable: %+v/%+v", aq, ad)
	}
	a.cleanup()
	fq, fd, aq, ad = snapshotForwardQueue(f, a)
	if aq.bytes != 0 || aq.packets != 0 || aq.peakBytes != udpForwardSessionQueuedBytes || ad.abandoned != 8 {
		t.Fatalf("session cleanup lost peak or budget: %+v/%+v", aq, ad)
	}
	if fq.bytes != len("independent") || fq.packets != 1 || fd.abandoned != 8 {
		t.Fatalf("cleanup changed another session: %+v/%+v", fq, fd)
	}
	if got := consumeForwardQueuePacket(t, b); string(got) != "independent" {
		t.Fatalf("other session data changed: %q", got)
	}
}

func TestForwardQueueListenerByteLimit(t *testing.T) {
	f, _ := newForwardQueueFixture(t)
	sessions := make([]*udpForwardSession, 33)
	payload := make([]byte, 32768)
	for i := range sessions {
		sessions[i] = registerForwardQueueSession(f, i, false)
		if i < 32 {
			for j := 0; j < 8; j++ {
				f.enqueue(sessions[i].peer, payload)
			}
		}
	}
	last := sessions[32]
	f.enqueue(last.peer, []byte("overflow"))
	fq, fd, sq, sd := snapshotForwardQueue(f, last)
	if fq.bytes != udpForwardMaxQueuedBytes || fq.packets != 256 || fd.listenerBytes != 1 || sd.listenerBytes != 1 || sq.bytes != 0 || sq.packets != 0 {
		t.Fatalf("listener byte cap: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
	consumeForwardQueuePacket(t, sessions[0])
	f.enqueue(last.peer, payload)
	fq, fd, sq, sd = snapshotForwardQueue(f, last)
	if fq.bytes != udpForwardMaxQueuedBytes || fq.peakBytes != udpForwardMaxQueuedBytes || sq.bytes != len(payload) || sq.packets != 1 || fd.listenerBytes != 1 || sd.listenerBytes != 1 {
		t.Fatalf("listener budget not reusable: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
	for _, s := range sessions {
		s.cleanup()
	}
	fq, _, _, _ = snapshotForwardQueue(f, nil)
	if fq.bytes != 0 || fq.packets != 0 || fq.peakBytes != udpForwardMaxQueuedBytes {
		t.Fatalf("listener cleanup did not retain peak and release budget: %+v", fq)
	}
}

func TestForwardQueueAdmissionLimitsDoNotBlockExistingSessions(t *testing.T) {
	for _, pendingLimit := range []bool{true, false} {
		t.Run(map[bool]string{true: "pending", false: "sessions"}[pendingLimit], func(t *testing.T) {
			f, _ := newForwardQueueFixture(t)
			count := udpForwardMaxSessions
			if pendingLimit {
				count = udpForwardMaxPending
			}
			var existing *udpForwardSession
			for i := 0; i < count; i++ {
				existing = registerForwardQueueSession(f, i, pendingLimit)
			}
			peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20000}
			f.enqueue(peer, []byte("new"))
			f.enqueue(existing.peer, []byte("existing"))
			fq, fd, sq, sd := snapshotForwardQueue(f, existing)
			f.mu.Lock()
			gotSessions, gotPending := len(f.sessions), f.pending
			f.mu.Unlock()
			if gotSessions != count || fq.packets != 1 || sq.packets != 1 || sd != (udpForwardDrops{}) {
				t.Fatalf("admission changed an existing session: count=%d pending=%d listener=%+v/%+v session=%+v/%+v", gotSessions, gotPending, fq, fd, sq, sd)
			}
			if pendingLimit && (fd.pendingLimit != 1 || fd.sessionLimit != 0 || gotPending != count) {
				t.Fatalf("pending admission counter: %+v, pending=%d", fd, gotPending)
			}
			if !pendingLimit && (fd.sessionLimit != 1 || fd.pendingLimit != 0) {
				t.Fatalf("session admission counter: %+v", fd)
			}
		})
	}
}

func TestForwardQueueOversizeAndZeroLength(t *testing.T) {
	f, _ := newForwardQueueFixture(t)
	s := registerForwardQueueSession(f, 1, false)
	oversize := make([]byte, 65536-len(f.header))
	f.enqueue(s.peer, oversize)
	newPeer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 20000}
	f.enqueue(newPeer, oversize)
	fq, fd, sq, sd := snapshotForwardQueue(f, s)
	f.mu.Lock()
	sessions := len(f.sessions)
	f.mu.Unlock()
	if sessions != 1 || fq.packets != 0 || fq.bytes != 0 || sq.packets != 0 || fd.oversize != 2 || sd.oversize != 1 {
		t.Fatalf("oversize queued or admitted a session: count=%d listener=%+v/%+v session=%+v/%+v", sessions, fq, fd, sq, sd)
	}
	f.enqueue(s.peer, nil)
	f.enqueue(s.peer, []byte{})
	fq, _, sq, _ = snapshotForwardQueue(f, s)
	if fq.packets != 2 || sq.packets != 2 || fq.bytes != 0 || sq.bytes != 0 {
		t.Fatalf("empty datagrams lost: listener=%+v session=%+v", fq, sq)
	}
	if got := consumeForwardQueuePacket(t, s); len(got) != 0 {
		t.Fatalf("empty packet became %q", got)
	}
	s.cleanup()
	fq, fd, sq, sd = snapshotForwardQueue(f, s)
	if fq.packets != 0 || sq.packets != 0 || fd.abandoned != 1 || sd.abandoned != 1 || sq.peakPackets != 2 {
		t.Fatalf("empty datagram cleanup: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
}

func TestForwardQueueClosingDoesNotAllocate(t *testing.T) {
	t.Run("session", func(t *testing.T) {
		f, _ := newForwardQueueFixture(t)
		a := registerForwardQueueSession(f, 1, false)
		b := registerForwardQueueSession(f, 2, false)
		a.cancel()
		f.enqueue(a.peer, []byte("closed"))
		f.enqueue(b.peer, []byte("live"))
		fq, fd, aq, ad := snapshotForwardQueue(f, a)
		if fq.packets != 1 || fq.bytes != 4 || aq.packets != 0 || aq.bytes != 0 || fd.closing != 1 || ad.closing != 1 {
			t.Fatalf("closed session retained data: listener=%+v/%+v session=%+v/%+v", fq, fd, aq, ad)
		}
	})
	t.Run("listener", func(t *testing.T) {
		f, cancel := newForwardQueueFixture(t)
		s := registerForwardQueueSession(f, 1, true)
		cancel()
		f.enqueue(s.peer, []byte("existing"))
		f.enqueue(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 4), Port: 20000}, []byte("new"))
		fq, fd, sq, _ := snapshotForwardQueue(f, s)
		f.mu.Lock()
		sessions, pending := len(f.sessions), f.pending
		f.mu.Unlock()
		if sessions != 1 || pending != 1 || fq.packets != 0 || fq.bytes != 0 || sq.packets != 0 || fd.closing != 2 {
			t.Fatalf("closed listener allocated: sessions=%d pending=%d listener=%+v/%+v session=%+v", sessions, pending, fq, fd, sq)
		}
		s.cleanup()
		f.mu.Lock()
		sessions, pending = len(f.sessions), f.pending
		f.mu.Unlock()
		if sessions != 0 || pending != 0 {
			t.Fatalf("pending cleanup: sessions=%d pending=%d", sessions, pending)
		}
	})
}

type forwardQueueBlockedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *forwardQueueBlockedConn) Write(payload []byte) (int, error) {
	if !bytes.HasPrefix(payload, []byte("udp://")) {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Write(payload)
}

func startBlockedForwardQueue(t *testing.T) (*udpForwarder, *udpForwardSession, net.Conn, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	f, cancel := newForwardQueueFixture(t)
	s := registerForwardQueueSession(f, 1, true)
	server, agent := net.Pipe()
	wrapped := &forwardQueueBlockedConn{Conn: server, started: make(chan struct{})}
	f.pool.add(wrapped)
	f.wg.Add(1)
	done := make(chan struct{})
	go func() { defer close(done); s.run() }()
	t.Cleanup(func() {
		cancel()
		s.stop()
		agent.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("forward run did not stop")
		}
	})
	agent.SetDeadline(time.Now().Add(3 * time.Second))
	request, err := netx.ReadString(agent, '\n', 1024)
	if err != nil || request != "udp://0.0.0.0:0\n" {
		t.Fatalf("UDP setup: %q %v", request, err)
	}
	if err := writeAll(agent, []byte("OK\n")); err != nil {
		t.Fatal(err)
	}
	f.enqueue(s.peer, []byte("first"))
	select {
	case <-wrapped.started:
	case <-time.After(time.Second):
		t.Fatal("business writer did not start")
	}
	return f, s, agent, cancel, done
}

func TestForwardQueueBurstSurvivesBlockedWriter(t *testing.T) {
	f, s, agent, _, done := startBlockedForwardQueue(t)
	const burst = 64 // The previous 16-packet queue dropped most of this burst.
	for i := 1; i <= burst; i++ {
		var payload [4]byte
		binary.BigEndian.PutUint32(payload[:], uint32(i))
		f.enqueue(s.peer, payload[:])
	}
	fq, fd, sq, sd := snapshotForwardQueue(f, s)
	if fq.packets != burst || sq.packets != burst || fq.bytes != burst*4 || fd != (udpForwardDrops{}) || sd != (udpForwardDrops{}) {
		t.Fatalf("burst dropped while writer blocked: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
	buf := make([]byte, 65535)
	for i := 0; i <= burst; i++ {
		packet, err := readUDPFrame(agent, buf)
		if err != nil {
			t.Fatalf("read burst packet %d: %v", i, err)
		}
		host, port, payload, err := parseUDPPacket(packet)
		if err != nil || host != "charon" || port != 500 {
			t.Fatalf("destination changed: %s:%d %v", host, port, err)
		}
		if i == 0 {
			if string(payload) != "first" {
				t.Fatalf("first packet: %q", payload)
			}
		} else if len(payload) != 4 || binary.BigEndian.Uint32(payload) != uint32(i) {
			t.Fatalf("burst packet %d: %x", i, payload)
		}
	}
	agent.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forward did not finish after peer closure")
	}
	fq, fd, sq, sd = snapshotForwardQueue(f, s)
	if fq.packets != 0 || fq.bytes != 0 || sq.packets != 0 || sq.bytes != 0 || sq.peakPackets != burst || fd.abandoned != 0 || sd.abandoned != 0 {
		t.Fatalf("drained burst retained budget: listener=%+v/%+v session=%+v/%+v", fq, fd, sq, sd)
	}
}

func TestForwardQueueCancellationReleasesBlockedBurst(t *testing.T) {
	f, s, agent, cancel, done := startBlockedForwardQueue(t)
	for i := 0; i < 64; i++ {
		f.enqueue(s.peer, []byte("queued"))
	}
	cancel()
	// Exercise shutdown racing with the reader's enqueue path. None of these
	// packets may start a replacement session or increase a canceled queue.
	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 25; j++ {
				f.enqueue(s.peer, []byte("late"))
			}
		}()
	}
	s.stop()
	writers.Wait()
	agent.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked writer")
	}
	fq, fd, sq, sd := snapshotForwardQueue(f, s)
	f.mu.Lock()
	sessions, pending := len(f.sessions), f.pending
	f.mu.Unlock()
	if sessions != 0 || pending != 0 || fq.packets != 0 || fq.bytes != 0 || sq.packets != 0 || sq.bytes != 0 {
		t.Fatalf("canceled burst leaked: sessions=%d pending=%d listener=%+v session=%+v", sessions, pending, fq, sq)
	}
	if fd.abandoned != 64 || sd.abandoned != 64 || fd.closing != 200 || fd.writeError != 1 || sd.writeError != 1 || fd.total() != 265 {
		t.Fatalf("canceled burst counters: listener=%+v session=%+v", fd, sd)
	}
}

func TestForwardQueueStatsSuppressUnchangedReports(t *testing.T) {
	f, _ := newForwardQueueFixture(t)
	var output processLog
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	count := func() int { return strings.Count(output.String(), "UDP forward stats:") }
	f.reportStats(false)
	if count() != 0 {
		t.Fatal("empty unchanged listener emitted a report")
	}
	s := registerForwardQueueSession(f, 1, false)
	f.reportStats(false)
	f.reportStats(false)
	if count() != 1 {
		t.Fatalf("unchanged session count emitted %d reports", count())
	}
	f.enqueue(s.peer, []byte("abc"))
	f.reportStats(false)
	f.reportStats(false)
	if count() != 2 {
		t.Fatalf("queue change/unchanged reports: %d", count())
	}
	consumeForwardQueuePacket(t, s)
	f.reportStats(false)
	f.reportStats(false)
	if count() != 3 {
		t.Fatalf("queue drain change/unchanged reports: %d", count())
	}
	f.enqueue(s.peer, make([]byte, 65536-len(f.header)))
	f.reportStats(false)
	f.reportStats(false)
	if count() != 4 {
		t.Fatalf("drop change/unchanged reports: %d", count())
	}
	report := output.String()
	last := report[strings.LastIndex(report, "UDP forward stats:"):]
	for _, field := range []string{"queued_packets=0", "queued_bytes=0", "peak_packets=1", "peak_bytes=3", "dropped=1", "oversize=1"} {
		if !strings.Contains(last, field) {
			t.Errorf("report omitted %s: %s", field, last)
		}
	}
	f.reportStats(true)
	if count() != 5 {
		t.Fatal("forced final report was suppressed")
	}
}

func TestForwardQueueReportLoopStopsOnCancellation(t *testing.T) {
	f, cancel := newForwardQueueFixture(t)
	done := make(chan struct{})
	go func() { defer close(done); f.reportLoop() }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stats loop ignored listener cancellation")
	}
}
