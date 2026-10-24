package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/transport/v5/deadline"
)

const (
	dtlsAcceptBacklog      = 128
	dtlsPeerQueuePackets   = 256
	dtlsPeerQueueBytes     = 256 << 10
	dtlsListenerQueueBytes = 16 << 20
	dtlsListenerPackets    = 16384
	dtlsSocketReadBuffer   = 1 << 20
)

// Pion's default listener has an unbounded raw datagram queue per remote.
// This PacketListener bounds memory before authentication and decryption.
type dtlsPacketListener struct {
	udp       *net.UDPConn
	mu        sync.Mutex
	peers     map[string]*dtlsPacketPeer
	accept    chan *dtlsPacketPeer
	done      chan struct{}
	closed    bool
	whitelist map[string]bool
	bytes     int
	packets   int
	writes    chan struct{}
	writer    *dtlsPacketPeer
	dropped   uint64
	oversized uint64
}

type dtlsPacketPeer struct {
	listener      *dtlsPacketListener
	remote        *net.UDPAddr
	queue         chan []byte
	done          chan struct{}
	closed        bool // all peer accounting is protected by listener.mu
	bytes         int
	readDeadline  *deadline.Deadline
	writeDeadline *deadline.Deadline
}

type dtlsPoolListener struct {
	net.Listener
	packets *dtlsPacketListener
}

func newDTLSPacketListener(addr *net.UDPAddr) (*dtlsPacketListener, error) {
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	// Absorb fragment bursts before decryption; the OS may clamp this request
	// to its configured receive-buffer maximum. User-space queues stay bounded.
	_ = udp.SetReadBuffer(dtlsSocketReadBuffer)
	l := &dtlsPacketListener{
		udp: udp, peers: make(map[string]*dtlsPacketPeer),
		accept: make(chan *dtlsPacketPeer, dtlsAcceptBacklog),
		done:   make(chan struct{}), writes: make(chan struct{}, 1),
	}
	l.writes <- struct{}{}
	go l.readPackets()
	return l, nil
}

func (l *dtlsPacketListener) Addr() net.Addr { return l.udp.LocalAddr() }

func (l *dtlsPacketListener) setWhitelist(whitelist map[string]bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.whitelist = make(map[string]bool, len(whitelist))
	for ip, allowed := range whitelist {
		l.whitelist[ip] = allowed
	}
	for _, peer := range l.peers {
		if len(l.whitelist) > 0 && !l.whitelist[peer.remote.IP.String()] {
			peer.closeLocked()
		}
	}
}

func (l *dtlsPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	for {
		select {
		case <-l.done:
			return nil, nil, net.ErrClosed
		case peer := <-l.accept:
			l.mu.Lock()
			closed := l.closed || peer.closed
			l.mu.Unlock()
			if !closed {
				return peer, peer.remote, nil
			}
		}
	}
}

func (l *dtlsPacketListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	for _, peer := range l.peers {
		peer.closeLocked()
	}
	return l.udp.Close()
}

func (l *dtlsPacketListener) readPackets() {
	// Read the maximum UDP size so Windows also discards oversized datagrams
	// without turning a truncated receive into a fatal socket error.
	buf := make([]byte, 65535)
	for {
		n, addr, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			l.Close()
			return
		}
		l.deliver(buf[:n], addr)
	}
}

func (l *dtlsPacketListener) deliver(packet []byte, addr *net.UDPAddr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || (len(l.whitelist) > 0 && !l.whitelist[addr.IP.String()]) {
		return
	}
	if len(packet) > maxDatagramMTU {
		l.oversized++
		return
	}
	if l.bytes+len(packet) > dtlsListenerQueueBytes || l.packets >= dtlsListenerPackets {
		l.dropped++
		return
	}
	key := addr.String()
	peer := l.peers[key]
	if peer == nil {
		// Only a DTLS 1.2 epoch-zero ClientHello may allocate a peer. Pion
		// remains responsible for full validation and its cookie exchange.
		if len(packet) < 25 || packet[0] != 22 || packet[1] != 0xfe || packet[2] != 0xfd ||
			packet[3] != 0 || packet[4] != 0 || packet[13] != 1 ||
			binary.BigEndian.Uint16(packet[11:13]) < 12 ||
			int(binary.BigEndian.Uint16(packet[11:13])) > len(packet)-13 {
			return
		}
		if len(l.peers) >= dtlsMaxSessions || len(l.accept) >= cap(l.accept) {
			l.dropped++
			return
		}
		peer = &dtlsPacketPeer{
			listener: l, remote: addr, queue: make(chan []byte, dtlsPeerQueuePackets),
			done: make(chan struct{}), readDeadline: deadline.New(), writeDeadline: deadline.New(),
		}
		l.peers[key] = peer
		l.accept <- peer
	}
	if peer.bytes+len(packet) > dtlsPeerQueueBytes || len(peer.queue) >= cap(peer.queue) {
		l.dropped++
		return
	}
	peer.queue <- append([]byte(nil), packet...)
	peer.bytes += len(packet)
	l.bytes += len(packet)
	l.packets++
}

func (p *dtlsPacketPeer) LocalAddr() net.Addr { return p.listener.Addr() }

func (p *dtlsPacketPeer) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case <-p.readDeadline.Done():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-p.done:
		return 0, nil, net.ErrClosed
	case <-p.readDeadline.Done():
		return 0, nil, os.ErrDeadlineExceeded
	case packet := <-p.queue:
		l := p.listener
		l.mu.Lock()
		p.bytes -= len(packet)
		l.bytes -= len(packet)
		l.packets--
		closed := p.closed
		l.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		if len(buf) < len(packet) {
			return 0, p.remote, io.ErrShortBuffer
		}
		return copy(buf, packet), p.remote, nil
	}
}

func (p *dtlsPacketPeer) WriteTo(packet []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != p.remote.String() {
		return 0, &net.AddrError{Err: "DTLS peer address cannot change"}
	}
	l := p.listener
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case <-p.writeDeadline.Done():
		return 0, os.ErrDeadlineExceeded
	case <-l.writes:
	}
	defer func() { l.writes <- struct{}{} }()
	l.mu.Lock()
	if p.closed || p.writeDeadline.Err() != nil {
		closed := p.closed
		l.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		return 0, os.ErrDeadlineExceeded
	}
	l.writer = p
	until, _ := p.writeDeadline.Deadline()
	l.udp.SetWriteDeadline(until)
	l.mu.Unlock()
	n, err := l.udp.WriteToUDP(packet, p.remote)
	l.mu.Lock()
	l.writer = nil
	l.udp.SetWriteDeadline(time.Time{})
	l.mu.Unlock()
	return n, err
}

func (p *dtlsPacketPeer) Close() error {
	p.listener.mu.Lock()
	defer p.listener.mu.Unlock()
	p.closeLocked()
	return nil
}

func (p *dtlsPacketPeer) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	close(p.done)
	p.readDeadline.Set(time.Time{})
	p.writeDeadline.Set(time.Time{})
	delete(p.listener.peers, p.remote.String())
	if p.listener.writer == p {
		p.listener.udp.SetWriteDeadline(time.Now())
	}
	for {
		select {
		case packet := <-p.queue:
			p.bytes -= len(packet)
			p.listener.bytes -= len(packet)
			p.listener.packets--
		default:
			return
		}
	}
}

func (p *dtlsPacketPeer) SetReadDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	return nil
}

func (p *dtlsPacketPeer) SetWriteDeadline(t time.Time) error {
	l := p.listener
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.closed {
		// Close may have set the socket deadline to interrupt this peer's
		// current write. A late deadline reset must never undo that interrupt.
		return net.ErrClosed
	}
	p.writeDeadline.Set(t)
	// Only the peer currently writing may change the shared socket deadline.
	// Other peers keep their deadlines in their own timers while waiting.
	if l.writer == p {
		return l.udp.SetWriteDeadline(t)
	}
	return nil
}

func (p *dtlsPacketPeer) SetDeadline(t time.Time) error {
	p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
