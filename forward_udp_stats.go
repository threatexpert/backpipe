package main

import (
	"log"
	"time"
)

const udpForwardStatsInterval = 10 * time.Second

// All queue and drop accounting is guarded by the owning forwarder's mutex.
// Bytes count waiting payloads only, without tunnel headers or kernel buffers.
type udpForwardQueueStats struct {
	packets, bytes         int
	peakPackets, peakBytes int
}

func (q *udpForwardQueueStats) add(size int) {
	q.packets++
	q.bytes += size
	q.peakPackets = max(q.peakPackets, q.packets)
	q.peakBytes = max(q.peakBytes, q.bytes)
}

type udpForwardDropReason uint8

const (
	udpDropQueuePackets udpForwardDropReason = iota
	udpDropSessionBytes
	udpDropListenerBytes
	udpDropPendingLimit
	udpDropSessionLimit
	udpDropOversize
	udpDropClosing
	udpDropAbandoned
	udpDropWriteError
)

// These are locally observed discards or failed writes, not a measurement of
// network loss or packets dropped by the kernel before ReadFromUDP returns.
type udpForwardDrops struct {
	queuePackets, sessionBytes, listenerBytes uint64
	pendingLimit, sessionLimit, oversize      uint64
	closing, abandoned, writeError            uint64
}

func (d *udpForwardDrops) total() uint64 {
	return d.queuePackets + d.sessionBytes + d.listenerBytes + d.pendingLimit +
		d.sessionLimit + d.oversize + d.closing + d.abandoned + d.writeError
}

func (d *udpForwardDrops) add(reason udpForwardDropReason, count uint64) {
	switch reason {
	case udpDropQueuePackets:
		d.queuePackets += count
	case udpDropSessionBytes:
		d.sessionBytes += count
	case udpDropListenerBytes:
		d.listenerBytes += count
	case udpDropPendingLimit:
		d.pendingLimit += count
	case udpDropSessionLimit:
		d.sessionLimit += count
	case udpDropOversize:
		d.oversize += count
	case udpDropClosing:
		d.closing += count
	case udpDropAbandoned:
		d.abandoned += count
	case udpDropWriteError:
		d.writeError += count
	}
}

func (f *udpForwarder) dropLocked(s *udpForwardSession, reason udpForwardDropReason, count uint64) {
	f.drops.add(reason, count)
	if s != nil {
		s.drops.add(reason, count)
	}
}

func (f *udpForwarder) recordDrop(s *udpForwardSession, reason udpForwardDropReason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropLocked(s, reason, 1)
}

type udpForwardSnapshot struct {
	queue             udpForwardQueueStats
	drops             udpForwardDrops
	sessions, pending int
}

func (f *udpForwarder) reportLoop() {
	ticker := time.NewTicker(udpForwardStatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.reportStats(false)
		}
	}
}

func (f *udpForwarder) reportStats(force bool) {
	f.mu.Lock()
	snapshot := udpForwardSnapshot{f.queueStats, f.drops, len(f.sessions), f.pending}
	if !force && snapshot == f.lastReport {
		f.mu.Unlock()
		return
	}
	f.lastReport = snapshot
	f.mu.Unlock()
	q, d := snapshot.queue, snapshot.drops
	log.Printf("[server] UDP forward stats: %s (sessions=%d pending=%d queued_packets=%d queued_bytes=%d peak_packets=%d peak_bytes=%d dropped=%d queue_packets=%d session_bytes=%d listener_bytes=%d pending_limit=%d session_limit=%d oversize=%d closing=%d abandoned=%d write_error=%d)",
		f.udp.LocalAddr(), snapshot.sessions, snapshot.pending, q.packets, q.bytes, q.peakPackets, q.peakBytes, d.total(),
		d.queuePackets, d.sessionBytes, d.listenerBytes, d.pendingLimit, d.sessionLimit, d.oversize, d.closing, d.abandoned, d.writeError)
}
