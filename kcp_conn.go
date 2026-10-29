package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const (
	kcpEnvelopeSize       = 5
	kcpFrameSize          = 16 << 10
	kcpReceiveLimit       = 256 << 10
	kcpPacketData    byte = 1
	kcpPacketPing    byte = 2
	kcpPacketPong    byte = 3
	kcpPacketFINACK  byte = 4
	kcpPacketFECData byte = 5
	kcpFrameHello    byte = 1
	kcpFrameData     byte = 2
	kcpFrameFIN      byte = 3
)

var kcpMagic = []byte{'B', 'P', 'K', 1}

type kcpSettings struct {
	MTU                              int
	SendWindow, ReceiveWindow        int
	NoCongestion                     bool
	FECData, FECParity               int
	Heartbeat, Timeout, CloseTimeout time.Duration
}

func defaultKCPSettings() kcpSettings {
	return kcpSettings{MTU: 1200, SendWindow: 128, ReceiveWindow: 128, NoCongestion: true, Heartbeat: 10 * time.Second, Timeout: 30 * time.Second, CloseTimeout: 5 * time.Second}
}

func (cfg kcpSettings) validFEC() bool {
	return (cfg.FECData == 0 && cfg.FECParity == 0) ||
		(cfg.FECData >= 1 && cfg.FECData <= 32 && cfg.FECParity >= 1 && cfg.FECParity <= 32)
}

func (cfg kcpSettings) fecProfile() string {
	if cfg.FECData == 0 && cfg.FECParity == 0 {
		return "off"
	}
	return fmt.Sprintf("%d:%d", cfg.FECData, cfg.FECParity)
}

func (cfg *kcpSettings) setFEC(value string) error {
	if value == "off" {
		cfg.FECData, cfg.FECParity = 0, 0
		return nil
	}
	data, parity, ok := strings.Cut(value, ":")
	d, de := strconv.Atoi(data)
	p, pe := strconv.Atoi(parity)
	if !ok || de != nil || pe != nil || d < 1 || d > 32 || p < 1 || p > 32 {
		return fmt.Errorf("-kcp-fec must be off or data:parity (each 1..32), for example 10:3")
	}
	cfg.FECData, cfg.FECParity = d, p
	return nil
}

func (cfg kcpSettings) packetHeaderSize() int {
	if cfg.FECData != 0 {
		return kcpEnvelopeSize + 2 // authenticated FEC data/parity profile
	}
	return kcpEnvelopeSize
}

// Keep the current 128-segment baseline as the minimum and bound per-session
// memory exposure at the upper end.
func validKCPWindow(n int) bool { return n >= 128 && n <= 4096 }

// One authenticated DTLS connection belongs to one KCP session. Heartbeats and
// FIN acknowledgments bypass KCP flow control, but never bypass DTLS. A stalled
// application reader must not be mistaken for a dead network connection.
type kcpPackets struct {
	conn        net.Conn
	cfg         kcpSettings
	done        chan struct{}
	writeGate   chan struct{}
	once        sync.Once
	mu          sync.Mutex
	err         error
	lastPong    time.Time
	sent, acked uint64
	finReceived atomic.Bool
	finSent     atomic.Bool
	finAck      chan struct{}
	finAckOnce  sync.Once
}

func (p *kcpPackets) fail(err error) {
	p.once.Do(func() {
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
		// Close the carrier before closing KCP: a KCP flush can be waiting
		// inside a carrier write while holding KCP's mutex.
		p.conn.Close()
	})
}

func (p *kcpPackets) terminal() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *kcpPackets) send(kind byte, payload []byte) error {
	timer := time.NewTimer(p.cfg.Timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return p.terminal()
	case <-timer.C:
		return os.ErrDeadlineExceeded
	case <-p.writeGate:
	}
	defer func() { p.writeGate <- struct{}{} }()
	headerSize := kcpEnvelopeSize
	if kind == kcpPacketFECData {
		headerSize += 2
	}
	frame := make([]byte, headerSize+len(payload))
	copy(frame, kcpMagic)
	frame[4] = kind
	if kind == kcpPacketFECData {
		frame[5], frame[6] = byte(p.cfg.FECData), byte(p.cfg.FECParity)
	}
	copy(frame[headerSize:], payload)
	p.conn.SetWriteDeadline(time.Now().Add(p.cfg.Timeout))
	n, err := p.conn.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		p.fail(err)
	}
	return err
}

func (p *kcpPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 8192)
	for {
		n, err := p.conn.Read(buf)
		if err != nil {
			p.fail(err)
			return 0, nil, p.terminal()
		}
		if n < kcpEnvelopeSize || !bytes.Equal(buf[:4], kcpMagic) {
			err = fmt.Errorf("invalid KCP/DTLS protocol envelope")
			p.fail(err)
			return 0, nil, err
		}
		payload := buf[5:n]
		switch buf[4] {
		case kcpPacketData, kcpPacketFECData:
			// Plain records retain the v1.5.0 wire format. FEC records carry
			// their profile so mismatched peers fail before feeding KCP's decoder.
			if buf[4] == kcpPacketFECData {
				if len(payload) < 2 {
					p.fail(fmt.Errorf("truncated KCP FEC profile"))
					return 0, nil, p.terminal()
				}
				if p.cfg.FECData == 0 || int(payload[0]) != p.cfg.FECData || int(payload[1]) != p.cfg.FECParity {
					p.fail(fmt.Errorf("KCP FEC mismatch: local=%s peer=%d:%d", p.cfg.fecProfile(), payload[0], payload[1]))
					return 0, nil, p.terminal()
				}
				payload = payload[2:]
			} else if p.cfg.FECData != 0 {
				p.fail(fmt.Errorf("KCP FEC mismatch: local=%s peer=off", p.cfg.fecProfile()))
				return 0, nil, p.terminal()
			}
			if len(payload) > len(b) {
				p.fail(io.ErrShortBuffer)
				return 0, nil, io.ErrShortBuffer
			}
			return copy(b, payload), p.conn.RemoteAddr(), nil
		case kcpPacketPing:
			if len(payload) != 8 {
				break
			}
			if err := p.send(kcpPacketPong, payload); err != nil {
				return 0, nil, err
			}
			continue
		case kcpPacketPong:
			if len(payload) != 8 {
				break
			}
			seq := binary.BigEndian.Uint64(payload)
			p.mu.Lock()
			if seq > p.acked && seq <= p.sent {
				p.acked = seq
				p.lastPong = time.Now()
			}
			p.mu.Unlock()
			continue
		case kcpPacketFINACK:
			if len(payload) != 0 {
				break
			}
			if p.finSent.Load() {
				p.finAckOnce.Do(func() { close(p.finAck) })
			}
			continue
		}
		err = fmt.Errorf("invalid KCP/DTLS control record")
		p.fail(err)
		return 0, nil, err
	}
}

func (p *kcpPackets) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b)+p.cfg.packetHeaderSize()+datagramRecordOverhead > p.cfg.MTU {
		return 0, fmt.Errorf("KCP packet exceeds DTLS MTU")
	}
	kind := kcpPacketData
	if p.cfg.FECData != 0 {
		kind = kcpPacketFECData
	}
	if err := p.send(kind, b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *kcpPackets) Close() error                       { p.fail(net.ErrClosed); return nil }
func (p *kcpPackets) LocalAddr() net.Addr                { return p.conn.LocalAddr() }
func (p *kcpPackets) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *kcpPackets) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *kcpPackets) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

// The watchdog must not wait behind a blocked carrier write or heartbeat.
func (p *kcpPackets) watchdog() {
	interval := min(p.cfg.Heartbeat, 200*time.Millisecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-ticker.C:
			p.mu.Lock()
			expired := now.Sub(p.lastPong) >= p.cfg.Timeout
			p.mu.Unlock()
			if expired {
				p.fail(fmt.Errorf("KCP heartbeat timeout: %w", os.ErrDeadlineExceeded))
				return
			}
		}
	}
}

func (p *kcpPackets) heartbeat() {
	ticker := time.NewTicker(min(p.cfg.Heartbeat, 200*time.Millisecond))
	defer ticker.Stop()
	var lastPing time.Time
	for {
		select {
		case <-p.done:
			return
		case now := <-ticker.C:
			if now.Sub(lastPing) >= p.cfg.Heartbeat {
				p.mu.Lock()
				p.sent++
				seq := p.sent
				p.mu.Unlock()
				var payload [8]byte
				binary.BigEndian.PutUint64(payload[:], seq)
				if err := p.send(kcpPacketPing, payload[:]); err != nil {
					p.fail(err)
					return
				}
				lastPing = now
			}
			if p.finReceived.Load() {
				if err := p.send(kcpPacketFINACK, nil); err != nil {
					p.fail(err)
					return
				}
			}
		}
	}
}

// The sole frame reader never receives application deadlines. Partial frames
// survive a Read timeout and the pool's interrupted idle read. Only a bounded
// amount of application data is buffered; KCP supplies the remaining backpressure.
type kcpStreamConn struct {
	sess                         *kcp.UDPSession
	packets                      *kcpPackets
	cfg                          kcpSettings
	mu                           sync.Mutex
	buffer                       bytes.Buffer
	readEOF, writeClosed, closed bool
	err                          error
	rd, wd                       time.Time
	wake                         chan struct{}
	writeGate                    chan struct{}
	done, ready                  chan struct{}
	abortOnce, closeOnce         sync.Once
	closeErr                     error
}

func newKCPStream(conn net.Conn, cfg kcpSettings) (*kcpStreamConn, error) {
	if cfg.MTU < 576 || cfg.MTU > 1400 || !validKCPWindow(cfg.SendWindow) || !validKCPWindow(cfg.ReceiveWindow) || !cfg.validFEC() || cfg.Heartbeat <= 0 || cfg.Timeout < 3*cfg.Heartbeat || cfg.CloseTimeout <= 0 {
		return nil, fmt.Errorf("invalid KCP settings")
	}
	p := &kcpPackets{conn: conn, cfg: cfg, done: make(chan struct{}), writeGate: make(chan struct{}, 1), lastPong: time.Now(), finAck: make(chan struct{})}
	p.writeGate <- struct{}{}
	// DTLS already authenticates and encrypts every KCP/FEC packet.
	sess, err := kcp.NewConn4(0, conn.RemoteAddr(), nil, cfg.FECData, cfg.FECParity, true, p)
	if err != nil {
		p.Close()
		return nil, err
	}
	sess.SetStreamMode(true)
	nocwnd := 0
	if cfg.NoCongestion {
		nocwnd = 1
	}
	sess.SetNoDelay(1, 20, 2, nocwnd)
	sess.SetWindowSize(cfg.SendWindow, cfg.ReceiveWindow)
	sess.SetACKNoDelay(true)
	// SetMtu already deducts kcp-go's FEC header (8 bytes when enabled).
	// Reserve only our envelope and the DTLS record overhead here.
	if !sess.SetMtu(cfg.MTU - datagramRecordOverhead - cfg.packetHeaderSize()) {
		p.Close()
		sess.Close()
		return nil, fmt.Errorf("invalid KCP MTU")
	}
	c := &kcpStreamConn{sess: sess, packets: p, cfg: cfg, wake: make(chan struct{}), writeGate: make(chan struct{}, 1), done: make(chan struct{}), ready: make(chan struct{})}
	c.writeGate <- struct{}{}
	go p.heartbeat()
	go p.watchdog()
	go c.readFrames()
	go func() { <-p.done; c.abort(p.terminal()) }()
	if _, err := c.writeFrame(kcpFrameHello, kcpMagic, time.Now().Add(dtlsHandshakeTimeout)); err != nil {
		c.abort(err)
		return nil, err
	}
	return c, nil
}

func (c *kcpStreamConn) signalLocked() { close(c.wake); c.wake = make(chan struct{}) }
func (c *kcpStreamConn) abort(err error) {
	c.abortOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.err = err
		c.signalLocked()
		c.mu.Unlock()
		close(c.done)
		c.packets.Close()
		c.sess.Close()
	})
}

func (c *kcpStreamConn) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		c.abort(ctx.Err())
		return ctx.Err()
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.err
	case <-c.ready:
		return nil
	}
}

func (c *kcpStreamConn) readFrames() {
	hello := false
	for {
		var header [3]byte
		if _, err := io.ReadFull(c.sess, header[:]); err != nil {
			c.abort(err)
			return
		}
		size := int(binary.BigEndian.Uint16(header[1:]))
		if size > kcpFrameSize {
			c.abort(fmt.Errorf("oversized KCP stream frame"))
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(c.sess, payload); err != nil {
			c.abort(err)
			return
		}
		if !hello {
			if header[0] != kcpFrameHello || !bytes.Equal(payload, kcpMagic) {
				c.abort(fmt.Errorf("invalid KCP stream handshake"))
				return
			}
			hello = true
			close(c.ready)
			continue
		}
		c.mu.Lock()
		if c.readEOF {
			c.mu.Unlock()
			c.abort(fmt.Errorf("KCP stream data after FIN"))
			return
		}
		c.mu.Unlock()
		switch header[0] {
		case kcpFrameData:
			if size == 0 {
				c.abort(fmt.Errorf("empty KCP data frame"))
				return
			}
			for {
				c.mu.Lock()
				if c.closed {
					c.mu.Unlock()
					return
				}
				if c.buffer.Len()+size <= kcpReceiveLimit {
					c.buffer.Write(payload)
					c.signalLocked()
					c.mu.Unlock()
					break
				}
				wake := c.wake
				c.mu.Unlock()
				select {
				case <-c.done:
					return
				case <-wake:
				}
			}
		case kcpFrameFIN:
			if size != 0 {
				c.abort(fmt.Errorf("invalid KCP FIN"))
				return
			}
			c.mu.Lock()
			c.readEOF = true
			c.signalLocked()
			c.mu.Unlock()
			c.packets.finReceived.Store(true)
			// ACK is repeated by the carrier heartbeat until it is closed.
			if err := c.packets.send(kcpPacketFINACK, nil); err != nil {
				c.abort(err)
				return
			}
		default:
			c.abort(fmt.Errorf("invalid KCP stream frame"))
			return
		}
	}
}

func waitKCP(wake, done <-chan struct{}, deadline time.Time) error {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-wake:
		return nil
	case <-done:
		return net.ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

func (c *kcpStreamConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if !c.rd.IsZero() && !time.Now().Before(c.rd) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if c.buffer.Len() > 0 {
			n, _ := c.buffer.Read(b)
			c.signalLocked()
			c.mu.Unlock()
			return n, nil
		}
		if c.readEOF {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.closed {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		wake, deadline := c.wake, c.rd
		c.mu.Unlock()
		if err := waitKCP(wake, c.done, deadline); err == os.ErrDeadlineExceeded {
			return 0, err
		}
	}
}

// Caller holds writeGate. A partial frame cannot be retried after a timeout.
func (c *kcpStreamConn) writeFrame(kind byte, payload []byte, deadline time.Time) (int, error) {
	frame := make([]byte, 3+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint16(frame[1:], uint16(len(payload)))
	copy(frame[3:], payload)
	for {
		c.mu.Lock()
		if c.closed {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		limit := deadline
		if kind == kcpFrameData {
			limit = c.wd
		}
		if !limit.IsZero() && !time.Now().Before(limit) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		// kcp-go v5.6.72 does not re-arm a previously absent deadline
		// when a blocked write is interrupted. Always install a short timer,
		// then re-check the application's current deadline on each retry.
		poll := time.Now().Add(100 * time.Millisecond)
		if !limit.IsZero() && limit.Before(poll) {
			poll = limit
		}
		c.sess.SetWriteDeadline(poll)
		c.mu.Unlock()
		n, err := c.sess.Write(frame)
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		var timeout net.Error
		if n == 0 && errors.As(err, &timeout) && timeout.Timeout() {
			continue
		}
		if err != nil && n > 0 {
			c.abort(err)
		}
		return max(0, n-3), err
	}
}

func (c *kcpStreamConn) lockWrite(limit time.Time) error {
	for {
		c.mu.Lock()
		if c.closed {
			err := c.err
			c.mu.Unlock()
			return err
		}
		deadline, wake := c.wd, c.wake
		if !limit.IsZero() && (deadline.IsZero() || deadline.After(limit)) {
			deadline = limit
		}
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		select {
		case <-c.writeGate:
			return nil
		default:
		}
		// Include the gate itself without losing dynamic deadline updates.
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-c.writeGate:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-timeout:
			return os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (c *kcpStreamConn) Write(b []byte) (int, error) {
	if err := c.lockWrite(time.Time{}); err != nil {
		return 0, err
	}
	defer func() { c.writeGate <- struct{}{} }()
	written := 0
	for len(b) > 0 {
		c.mu.Lock()
		closed, deadline := c.writeClosed, c.wd
		c.mu.Unlock()
		if closed {
			return written, net.ErrClosed
		}
		n := min(len(b), kcpFrameSize)
		sent, err := c.writeFrame(kcpFrameData, b[:n], deadline)
		written += sent
		if err != nil {
			return written, err
		}
		b = b[n:]
	}
	return written, nil
}

func (c *kcpStreamConn) CloseWrite() error {
	return c.closeWrite(time.Now().Add(c.cfg.CloseTimeout))
}

func (c *kcpStreamConn) closeWrite(limit time.Time) error {
	// KCP may hold its mutex while flushing to the carrier. Interrupt the
	// carrier independently of that mutex so CloseWrite stays bounded even
	// when a concurrent send is stuck in the underlying DTLS write.
	stop := time.AfterFunc(time.Until(limit), func() { c.packets.fail(os.ErrDeadlineExceeded) })
	defer stop.Stop()
	if err := c.lockWrite(limit); err != nil {
		return err
	}
	defer func() { c.writeGate <- struct{}{} }()
	c.mu.Lock()
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	deadline := c.wd
	if deadline.IsZero() || deadline.After(limit) {
		deadline = limit
	}
	c.mu.Unlock()
	c.packets.finSent.Store(true)
	_, err := c.writeFrame(kcpFrameFIN, nil, deadline)
	if err == nil {
		c.mu.Lock()
		c.writeClosed = true
		c.mu.Unlock()
	} else {
		c.packets.finSent.Store(false)
	}
	return err
}

func (c *kcpStreamConn) Close() error {
	c.closeOnce.Do(func() {
		deadline := time.Now().Add(c.cfg.CloseTimeout)
		stop := time.AfterFunc(time.Until(deadline), func() { c.packets.fail(os.ErrDeadlineExceeded) })
		defer stop.Stop()
		c.closeErr = c.closeWrite(deadline)
		if c.closeErr == nil {
			c.closeErr = waitKCP(c.packets.finAck, c.done, deadline)
		}
		c.abort(net.ErrClosed)
	})
	return c.closeErr
}
func (c *kcpStreamConn) LocalAddr() net.Addr  { return c.sess.LocalAddr() }
func (c *kcpStreamConn) RemoteAddr() net.Addr { return c.sess.RemoteAddr() }
func (c *kcpStreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *kcpStreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *kcpStreamConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
