package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"
)

const (
	defaultDatagramMTU = 1200
	minDatagramMTU     = 576
	// Pion's UDP listener currently reads at most 8192 bytes per datagram.
	maxDatagramMTU = 8192

	datagramRecordOverhead = 37 // DTLS 1.2 AES-GCM: header + explicit nonce + tag.
	datagramHeaderSize     = 18
	datagramMaxPacket      = 65535
	datagramMaxFragments   = 256
	datagramMaxAssemblies  = 64
	datagramQueuePackets   = 64
	datagramSessionMemory  = 1 << 20
	datagramGlobalMemory   = 64 << 20
	datagramSessionPieces  = 2048
	datagramGlobalPieces   = 32768
	datagramReplayWindow   = 4096
	// Includes the fixed-capacity fragment ranges and map/object overhead.
	datagramAssemblyMemory = 4096
	datagramControlRetry   = 200 * time.Millisecond
	datagramFragmentTTL    = 3 * time.Second
	datagramWriteTimeout   = 5 * time.Second
	datagramReadyTimeout   = 30 * time.Second
)

const (
	datagramReady byte = iota + 1
	datagramReadyACK
	datagramOpen
	datagramOpenACK
	datagramOpenReject
	datagramPing
	datagramPong
	datagramData
)

var (
	datagramMagic        = [4]byte{'B', 'P', 'D', 1}
	errDatagramStream    = errors.New("DTLS session requires ReadPacket/WritePacket, not stream I/O")
	errDatagramNotActive = errors.New("DTLS UDP session has not been activated")
	datagramResources    struct {
		sync.Mutex
		memory int
		pieces int
	}
)

type datagramSessionConfig struct {
	Server    bool
	MTU       int
	Prepare   func(*datagramSession) (func(), error)
	Heartbeat time.Duration
}

type datagramSpan struct{ offset, length uint16 }

type datagramAssembly struct {
	data     []byte
	spans    []datagramSpan
	received int
	expires  time.Time
}

// datagramSession owns exactly one record reader. Business deadlines never
// interrupt it: idle pooled sessions still receive READY and heartbeat records.
// DATA is intentionally unreliable and unordered; only setup is retransmitted.
type datagramSession struct {
	conn net.Conn
	cfg  datagramSessionConfig
	mu   sync.Mutex

	done         chan struct{}
	ready        chan struct{}
	activated    chan struct{}
	packets      chan []byte
	writeGate    chan struct{}
	closeOnce    sync.Once
	openMu       sync.Mutex
	terminal     error
	closed       bool
	readyOK      bool
	active       bool
	peerMTU      int
	ackMTU       int
	mtu          int
	opening      bool
	preparing    bool
	prepared     bool
	prepareErr   error
	openRejected bool
	openWake     chan struct{}

	created       time.Time
	lastReceived  time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	readWake      chan struct{}
	writeWake     chan struct{}
	writing       bool
	writeStarted  time.Time
	writeBusiness bool

	nextPacket    uint64
	highestPacket uint64
	// A packet ID ring gives O(1) duplicate checks without scanning a replay
	// map for every packet. Two IDs within the live window cannot share a slot.
	finished   [datagramReplayWindow]uint64
	assemblies map[uint64]*datagramAssembly
	memory     int
	pieces     int
}

func newDatagramSession(conn net.Conn, cfg datagramSessionConfig) *datagramSession {
	if cfg.MTU == 0 {
		cfg.MTU = defaultDatagramMTU
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 20 * time.Second
	}
	now := time.Now()
	s := &datagramSession{
		conn: conn, cfg: cfg, mtu: cfg.MTU,
		done: make(chan struct{}), ready: make(chan struct{}), activated: make(chan struct{}),
		packets: make(chan []byte, datagramQueuePackets), writeGate: make(chan struct{}, 1),
		openWake: make(chan struct{}), readWake: make(chan struct{}), writeWake: make(chan struct{}),
		created: now, lastReceived: now,
		assemblies: make(map[uint64]*datagramAssembly),
	}
	s.writeGate <- struct{}{}
	if cfg.MTU < minDatagramMTU || cfg.MTU > maxDatagramMTU {
		s.closeWithError(fmt.Errorf("DTLS MTU must be between %d and %d", minDatagramMTU, maxDatagramMTU))
		return s
	}
	go s.readRecords()
	go s.maintain()
	return s
}

func (s *datagramSession) Activated() <-chan struct{} { return s.activated }
func (s *datagramSession) Done() <-chan struct{}      { return s.done }
func (s *datagramSession) LocalAddr() net.Addr        { return s.conn.LocalAddr() }
func (s *datagramSession) RemoteAddr() net.Addr       { return s.conn.RemoteAddr() }
func (s *datagramSession) Read([]byte) (int, error)   { return 0, errDatagramStream }
func (s *datagramSession) Write([]byte) (int, error)  { return 0, errDatagramStream }

func (s *datagramSession) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return s.terminal
	}
	return net.ErrClosed
}

func (s *datagramSession) WaitReady(ctx context.Context) error {
	select {
	case <-s.done:
		return s.err()
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ready:
		select {
		case <-s.done:
			return s.err()
		default:
			return nil
		}
	}
}

// Open does not send business data. A failed activation destroys the session;
// no business payload can escape through an unconfirmed UDP exit socket.
func (s *datagramSession) Open(ctx context.Context) error {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if !s.cfg.Server {
		return errors.New("only the server can activate a DTLS UDP session")
	}
	if err := s.WaitReady(ctx); err != nil {
		s.closeWithError(err)
		return err
	}
	// Cancellation also interrupts a control write blocked in the transport.
	stopCancellation := context.AfterFunc(ctx, func() { s.closeWithError(ctx.Err()) })
	defer stopCancellation()
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return nil
	}
	s.opening = true
	s.mu.Unlock()
	ticker := time.NewTicker(datagramControlRetry)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			s.closeWithError(err)
			return err
		}
		if err := s.sendControl(datagramOpen, nil); err != nil {
			s.closeWithError(err)
			return err
		}
		s.mu.Lock()
		wake := s.openWake
		rejected := s.openRejected
		s.mu.Unlock()
		if rejected {
			err := errors.New("agent rejected DTLS UDP session preparation")
			s.closeWithError(err)
			return err
		}
		select {
		case <-s.done:
			return s.err()
		case <-ctx.Done():
			s.closeWithError(ctx.Err())
			return ctx.Err()
		case <-s.activated:
			return nil
		case <-wake:
		case <-ticker.C:
		}
	}
}

func (s *datagramSession) ReadPacket(buf []byte) ([]byte, error) {
	for {
		s.mu.Lock()
		deadline, wake, closed := s.readDeadline, s.readWake, s.closed
		s.mu.Unlock()
		if closed {
			return nil, s.err()
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case packet := <-s.packets:
			if timer != nil {
				timer.Stop()
			}
			s.mu.Lock()
			s.releaseLocked(len(packet), 0)
			s.mu.Unlock()
			if len(packet) > len(buf) {
				return nil, io.ErrShortBuffer
			}
			return buf[:copy(buf, packet)], nil
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			return nil, s.err()
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			// A simultaneous deadline update must be observed before timing out.
		}
	}
}

func (s *datagramSession) WritePacket(packet []byte) error {
	if len(packet) == 0 || len(packet) > datagramMaxPacket {
		return fmt.Errorf("invalid DTLS UDP packet length: %d", len(packet))
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.err()
	}
	if !s.active {
		s.mu.Unlock()
		return errDatagramNotActive
	}
	s.nextPacket++
	id, mtu := s.nextPacket, s.mtu
	s.mu.Unlock()
	if id == 0 {
		err := errors.New("DTLS UDP packet identifier exhausted")
		s.closeWithError(err)
		return err
	}
	chunk := mtu - datagramRecordOverhead - datagramHeaderSize
	frame := make([]byte, datagramHeaderSize+min(chunk, len(packet)))
	copy(frame, datagramMagic[:])
	frame[4] = datagramData
	binary.BigEndian.PutUint64(frame[6:14], id)
	binary.BigEndian.PutUint16(frame[14:16], uint16(len(packet)))
	for offset := 0; offset < len(packet); {
		n := min(chunk, len(packet)-offset)
		binary.BigEndian.PutUint16(frame[16:18], uint16(offset))
		copy(frame[18:], packet[offset:offset+n])
		if err := s.writeRecord(frame[:18+n], true); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

func (s *datagramSession) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

func (s *datagramSession) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline = t
	close(s.readWake)
	s.readWake = make(chan struct{})
	return nil
}

func (s *datagramSession) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.writeDeadline = t
	close(s.writeWake)
	s.writeWake = make(chan struct{})
	if s.writing && s.writeBusiness {
		return s.conn.SetWriteDeadline(earlierDeadline(s.writeStarted.Add(datagramWriteTimeout), t))
	}
	return nil
}

func earlierDeadline(a, b time.Time) time.Time {
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func (s *datagramSession) Close() error {
	s.closeWithError(net.ErrClosed)
	return nil
}

func (s *datagramSession) closeWithError(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed, s.terminal = true, err
		close(s.done)
		for id := range s.assemblies {
			s.discardAssemblyLocked(id)
		}
		clear(s.finished[:])
		draining := true
		for draining {
			select {
			case packet := <-s.packets:
				s.releaseLocked(len(packet), 0)
			default:
				draining = false
			}
		}
		s.mu.Unlock()
		s.conn.Close()
	})
}

func (s *datagramSession) sendControl(kind byte, body []byte) error {
	packet := make([]byte, 6+len(body))
	copy(packet, datagramMagic[:])
	packet[4] = kind
	copy(packet[6:], body)
	return s.writeRecord(packet, false)
}

func (s *datagramSession) writeRecord(packet []byte, business bool) error {
	limit := time.Now().Add(datagramWriteTimeout)
	for {
		s.mu.Lock()
		deadline, wake, closed := limit, s.writeWake, s.closed
		if business {
			deadline = earlierDeadline(deadline, s.writeDeadline)
		}
		s.mu.Unlock()
		if closed {
			return s.err()
		}
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-s.writeGate:
			timer.Stop()
			defer func() { s.writeGate <- struct{}{} }()
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return s.err()
			}
			s.writing, s.writeBusiness, s.writeStarted = true, business, time.Now()
			deadline = s.writeStarted.Add(datagramWriteTimeout)
			if business {
				deadline = earlierDeadline(deadline, s.writeDeadline)
			}
			err := s.conn.SetWriteDeadline(deadline)
			s.mu.Unlock()
			var n int
			if err == nil {
				n, err = s.conn.Write(packet)
			}
			s.mu.Lock()
			s.writing = false
			s.mu.Unlock()
			if err == nil && n != len(packet) {
				err = io.ErrShortWrite
			}
			if err != nil {
				s.closeWithError(err)
			}
			return err
		case <-s.done:
			timer.Stop()
			return s.err()
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *datagramSession) readRecords() {
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			s.closeWithError(err)
			return
		}
		if err := s.handleRecord(buf[:n]); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *datagramSession) handleRecord(packet []byte) error {
	if len(packet) < 6 || !bytes.Equal(packet[:4], datagramMagic[:]) || packet[5] != 0 {
		return errors.New("invalid DTLS UDP protocol header/version")
	}
	kind := packet[4]
	if kind < datagramReady || kind > datagramData {
		return errors.New("unknown DTLS UDP record type")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.lastReceived = time.Now()
	s.mu.Unlock()
	switch kind {
	case datagramReady, datagramReadyACK:
		if len(packet) != 8 {
			return errors.New("invalid DTLS READY record")
		}
		mtu := int(binary.BigEndian.Uint16(packet[6:8]))
		if mtu < minDatagramMTU || mtu > maxDatagramMTU {
			return errors.New("invalid peer DTLS MTU")
		}
		s.mu.Lock()
		if kind == datagramReady {
			if s.peerMTU != 0 && s.peerMTU != mtu {
				s.mu.Unlock()
				return errors.New("peer changed DTLS MTU")
			}
			s.peerMTU, s.mtu = mtu, min(s.cfg.MTU, mtu)
		} else {
			if mtu > s.cfg.MTU || (s.ackMTU != 0 && s.ackMTU != mtu) {
				s.mu.Unlock()
				return errors.New("invalid DTLS READY acknowledgement")
			}
			s.ackMTU = mtu
		}
		if s.peerMTU != 0 && s.ackMTU != 0 {
			if s.ackMTU != s.mtu {
				s.mu.Unlock()
				return errors.New("inconsistent negotiated DTLS MTU")
			}
			if !s.readyOK {
				s.readyOK = true
				close(s.ready)
			}
		}
		negotiated := s.mtu
		s.mu.Unlock()
		if kind == datagramReady {
			var body [2]byte
			binary.BigEndian.PutUint16(body[:], uint16(negotiated))
			return s.sendControl(datagramReadyACK, body[:])
		}
	case datagramOpen:
		if len(packet) != 6 || s.cfg.Server {
			return errors.New("unexpected DTLS OPEN")
		}
		s.mu.Lock()
		if !s.readyOK {
			s.mu.Unlock()
			return nil
		}
		prepared, preparing, rejected := s.prepared, s.preparing, s.prepareErr != nil
		if !prepared && !preparing && !rejected {
			s.preparing = true
		}
		s.mu.Unlock()
		if prepared {
			return s.sendControl(datagramOpenACK, nil)
		}
		if rejected {
			return s.sendControl(datagramOpenReject, nil)
		}
		if !preparing {
			go s.prepare()
		}
	case datagramOpenACK, datagramOpenReject:
		if len(packet) != 6 || !s.cfg.Server {
			return errors.New("unexpected DTLS OPEN response")
		}
		s.mu.Lock()
		if s.opening && !s.active {
			if kind == datagramOpenACK {
				s.active = true
				close(s.activated)
			} else {
				s.openRejected = true
			}
			close(s.openWake)
			s.openWake = make(chan struct{})
		}
		s.mu.Unlock()
	case datagramPing:
		if len(packet) != 14 {
			return errors.New("invalid DTLS heartbeat")
		}
		return s.sendControl(datagramPong, packet[6:])
	case datagramPong:
		if len(packet) != 14 {
			return errors.New("invalid DTLS heartbeat response")
		}
	case datagramData:
		s.receiveFragment(packet)
	}
	return nil
}

func (s *datagramSession) prepare() {
	var run func()
	var err error
	if s.cfg.Prepare != nil {
		run, err = s.cfg.Prepare(s)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.preparing, s.prepareErr = false, err
	if err == nil {
		s.prepared, s.active = true, true
		close(s.activated)
	}
	s.mu.Unlock()
	if err != nil {
		if writeErr := s.sendControl(datagramOpenReject, nil); writeErr != nil {
			s.closeWithError(writeErr)
		}
		return
	}
	if err := s.sendControl(datagramOpenACK, nil); err != nil {
		s.closeWithError(err)
		return
	}
	if run != nil {
		go run()
	}
}

func (s *datagramSession) maintain() {
	interval := min(datagramControlRetry, s.cfg.Heartbeat/4)
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	nextReady := time.Time{}
	nextHeartbeat := time.Now().Add(s.heartbeatDelay())
	for {
		now := time.Now()
		s.mu.Lock()
		ready, lastReceived := s.readyOK, s.lastReceived
		for id, assembly := range s.assemblies {
			if !now.Before(assembly.expires) {
				s.discardAssemblyLocked(id)
				s.finished[id%datagramReplayWindow] = id
			}
		}
		s.mu.Unlock()
		if (!ready && now.Sub(s.created) >= datagramReadyTimeout) || now.Sub(lastReceived) >= 3*s.cfg.Heartbeat {
			s.closeWithError(errors.New("DTLS UDP session heartbeat/setup timeout"))
			return
		}
		if !ready && !now.Before(nextReady) {
			var body [2]byte
			binary.BigEndian.PutUint16(body[:], uint16(s.cfg.MTU))
			if err := s.sendControl(datagramReady, body[:]); err != nil {
				s.closeWithError(err)
				return
			}
			nextReady = now.Add(datagramControlRetry)
		}
		if ready && !now.Before(nextHeartbeat) {
			var body [8]byte
			binary.BigEndian.PutUint64(body[:], uint64(now.UnixNano()))
			if err := s.sendControl(datagramPing, body[:]); err != nil {
				s.closeWithError(err)
				return
			}
			nextHeartbeat = now.Add(s.heartbeatDelay())
		}
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
	}
}

func (s *datagramSession) heartbeatDelay() time.Duration {
	jitter := max(int64(s.cfg.Heartbeat/10), 1)
	return s.cfg.Heartbeat + time.Duration(rand.Int64N(2*jitter+1)-jitter)
}

// All resource methods require s.mu. Every incomplete or queued packet counts
// against both budgets; dropping/reading/closing releases the same allocation.
func (s *datagramSession) reserveLocked(memory, pieces int) bool {
	if s.memory+memory > datagramSessionMemory || s.pieces+pieces > datagramSessionPieces {
		return false
	}
	datagramResources.Lock()
	defer datagramResources.Unlock()
	if datagramResources.memory+memory > datagramGlobalMemory || datagramResources.pieces+pieces > datagramGlobalPieces {
		return false
	}
	datagramResources.memory += memory
	datagramResources.pieces += pieces
	s.memory += memory
	s.pieces += pieces
	return true
}

func (s *datagramSession) releaseLocked(memory, pieces int) {
	datagramResources.Lock()
	datagramResources.memory -= memory
	datagramResources.pieces -= pieces
	datagramResources.Unlock()
	s.memory -= memory
	s.pieces -= pieces
}

func (s *datagramSession) discardAssemblyLocked(id uint64) {
	if assembly := s.assemblies[id]; assembly != nil {
		s.releaseLocked(len(assembly.data)+datagramAssemblyMemory, len(assembly.spans))
		delete(s.assemblies, id)
	}
}

// A lost fragment must not pin a full table until the TTL expires and make
// every later fragmented packet fail too. Retire the oldest incomplete packet
// at capacity, retaining the replay tombstone so late pieces cannot reopen it.
func (s *datagramSession) evictOldestAssemblyLocked() {
	var oldestID uint64
	var oldestExpiry time.Time
	for id, assembly := range s.assemblies {
		if oldestID == 0 || assembly.expires.Before(oldestExpiry) || (assembly.expires.Equal(oldestExpiry) && id < oldestID) {
			oldestID, oldestExpiry = id, assembly.expires
		}
	}
	if oldestID != 0 {
		s.discardAssemblyLocked(oldestID)
		s.finished[oldestID%datagramReplayWindow] = oldestID
	}
}

func (s *datagramSession) receiveFragment(packet []byte) {
	if len(packet) <= datagramHeaderSize {
		return
	}
	id := binary.BigEndian.Uint64(packet[6:14])
	total := int(binary.BigEndian.Uint16(packet[14:16]))
	offset := int(binary.BigEndian.Uint16(packet[16:18]))
	payload := packet[datagramHeaderSize:]
	if id == 0 || total == 0 || offset+len(payload) > total {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.active || len(packet) > s.mtu-datagramRecordOverhead {
		return
	}
	if s.highestPacket >= datagramReplayWindow && id <= s.highestPacket-datagramReplayWindow {
		return
	}
	if id > s.highestPacket {
		s.highestPacket = id
		if id >= datagramReplayWindow {
			floor := id - datagramReplayWindow
			for previous := range s.assemblies {
				if previous <= floor {
					s.discardAssemblyLocked(previous)
				}
			}
		}
	}
	if s.finished[id%datagramReplayWindow] == id {
		return
	}
	assembly := s.assemblies[id]
	if assembly == nil && offset == 0 && len(payload) == total {
		s.finished[id%datagramReplayWindow] = id
		if len(s.packets) == cap(s.packets) || !s.reserveLocked(total, 0) {
			return
		}
		// A complete datagram needs no assembly, fragment ranges or metadata
		// reservation. Copy once because the single record reader reuses buf.
		select {
		case s.packets <- bytes.Clone(payload):
		default:
			s.releaseLocked(total, 0)
		}
		return
	}
	if assembly == nil {
		if len(s.assemblies) >= datagramMaxAssemblies {
			s.evictOldestAssemblyLocked()
		}
		if !s.reserveLocked(total+datagramAssemblyMemory, 0) {
			s.finished[id%datagramReplayWindow] = id
			return
		}
		chunk := s.mtu - datagramRecordOverhead - datagramHeaderSize
		usualPieces := (total + chunk - 1) / chunk
		assembly = &datagramAssembly{data: make([]byte, total), spans: make([]datagramSpan, 0, usualPieces), expires: time.Now().Add(datagramFragmentTTL)}
		s.assemblies[id] = assembly
	}
	if len(assembly.data) != total {
		s.discardAssemblyLocked(id)
		s.finished[id%datagramReplayWindow] = id
		return
	}
	for _, span := range assembly.spans {
		start, end := int(span.offset), int(span.offset)+int(span.length)
		if start == offset && end == offset+len(payload) && bytes.Equal(assembly.data[start:end], payload) {
			return
		}
		if offset < end && offset+len(payload) > start {
			s.discardAssemblyLocked(id)
			s.finished[id%datagramReplayWindow] = id
			return
		}
	}
	if len(assembly.spans) >= datagramMaxFragments || !s.reserveLocked(0, 1) {
		s.discardAssemblyLocked(id)
		s.finished[id%datagramReplayWindow] = id
		return
	}
	copy(assembly.data[offset:], payload)
	assembly.spans = append(assembly.spans, datagramSpan{uint16(offset), uint16(len(payload))})
	assembly.received += len(payload)
	if assembly.received == total {
		delete(s.assemblies, id)
		s.finished[id%datagramReplayWindow] = id
		s.releaseLocked(datagramAssemblyMemory, len(assembly.spans))
		select {
		case s.packets <- assembly.data:
		default:
			s.releaseLocked(total, 0)
		}
	}
}
