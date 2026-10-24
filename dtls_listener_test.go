package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func testDTLSRawListener(t *testing.T) *dtlsPacketListener {
	t.Helper()
	l, err := newDTLSPacketListener(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// Only the record header is needed to test raw queue admission. The real DTLS
// authentication tests separately exercise Pion's full ClientHello validation.
func testDTLSHello() []byte {
	b := make([]byte, 25)
	b[0], b[1], b[2], b[12], b[13] = 22, 0xfe, 0xfd, 12, 1
	return b
}

func testDTLSRawPeer(t *testing.T, l *dtlsPacketListener, port int) *dtlsPacketPeer {
	t.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	l.deliver(testDTLSHello(), addr)
	raw, _, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return raw.(*dtlsPacketPeer)
}

func TestDTLSRawListenerQueueBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peers int
		size  int
	}{
		{"peer packet limit", 1, 1},
		{"peer byte limit", 1, maxDatagramMTU},
		{"global packet limit", 300, 1},
		{"global byte limit", 80, maxDatagramMTU},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testDTLSRawListener(t)
			peers := make([]*dtlsPacketPeer, tc.peers)
			// Create all peers before filling buffers so the global cap doesn't
			// prevent this test from reaching its intended admission point.
			for i := range peers {
				peers[i] = testDTLSRawPeer(t, l, 2000+i)
			}
			packet := make([]byte, tc.size)
			for _, peer := range peers {
				for i := 0; i < dtlsPeerQueuePackets+10; i++ {
					l.deliver(packet, peer.remote)
				}
			}
			l.mu.Lock()
			if l.dropped == 0 || l.bytes > dtlsListenerQueueBytes || l.packets > dtlsListenerPackets {
				t.Errorf("global limits failed: dropped=%d bytes=%d packets=%d", l.dropped, l.bytes, l.packets)
			}
			for _, peer := range peers {
				if peer.bytes > dtlsPeerQueueBytes || len(peer.queue) > dtlsPeerQueuePackets {
					t.Errorf("peer limits failed: bytes=%d packets=%d", peer.bytes, len(peer.queue))
				}
			}
			l.mu.Unlock()
			l.Close()
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.bytes != 0 || l.packets != 0 || len(l.peers) != 0 {
				t.Fatalf("shutdown retained datagrams: bytes=%d packets=%d peers=%d", l.bytes, l.packets, len(l.peers))
			}
		})
	}
}

func TestDTLSRawListenerAdmissionBounds(t *testing.T) {
	t.Run("backlog", func(t *testing.T) {
		l := testDTLSRawListener(t)
		for i := 0; i < dtlsAcceptBacklog+10; i++ {
			l.deliver(testDTLSHello(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000 + i})
		}
		if len(l.peers) != dtlsAcceptBacklog || len(l.accept) != dtlsAcceptBacklog {
			t.Fatal("accept backlog did not bound newly allocated peers")
		}
	})
	t.Run("peer count", func(t *testing.T) {
		l := testDTLSRawListener(t)
		for i := 0; i < dtlsMaxSessions; i++ {
			testDTLSRawPeer(t, l, 2000+i)
		}
		l.deliver(testDTLSHello(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000 + dtlsMaxSessions})
		if len(l.peers) != dtlsMaxSessions || len(l.accept) != 0 {
			t.Fatal("peer cap admitted an extra peer")
		}
	})
	t.Run("whitelist and oversized", func(t *testing.T) {
		l := testDTLSRawListener(t)
		l.setWhitelist(map[string]bool{"127.0.0.1": true})
		l.deliver(testDTLSHello(), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2000})
		l.deliver([]byte("not DTLS"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2001})
		large := make([]byte, maxDatagramMTU+1)
		copy(large, testDTLSHello())
		l.deliver(large, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2002})
		if len(l.peers) != 0 || l.oversized != 1 {
			t.Fatal("invalid, denied or oversized datagram allocated a peer")
		}
	})
}

func TestDTLSRawListenerMaximumPacketFragmentBurst(t *testing.T) {
	l := testDTLSRawListener(t)
	peer := testDTLSRawPeer(t, l, 2000)
	if _, _, err := peer.ReadFrom(make([]byte, maxDatagramMTU)); err != nil {
		t.Fatal(err)
	}
	// A maximum-sized business packet at the minimum MTU must fit into an
	// otherwise empty raw queue even when it arrives before decryption runs.
	payloadPerFragment := minDatagramMTU - datagramRecordOverhead - datagramHeaderSize
	fragments := (datagramMaxPacket + payloadPerFragment - 1) / payloadPerFragment
	for i := 0; i < fragments; i++ {
		l.deliver(make([]byte, minDatagramMTU), peer.remote)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dropped != 0 || len(peer.queue) != fragments {
		t.Fatalf("maximum packet burst lost fragments: want=%d queued=%d dropped=%d", fragments, len(peer.queue), l.dropped)
	}
}

func TestDTLSRawPeerDeadlineAndCloseIsolation(t *testing.T) {
	l := testDTLSRawListener(t)
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	first := testDTLSRawPeer(t, l, 2000)
	second := testDTLSRawPeer(t, l, receiver.LocalAddr().(*net.UDPAddr).Port)
	buf := make([]byte, maxDatagramMTU)
	if _, _, err := first.ReadFrom(buf); err != nil { // consume the ClientHello
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, _, err := first.ReadFrom(buf); readDone <- err }()
	first.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read deadline returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read deadline did not interrupt receive")
	}
	first.SetReadDeadline(time.Time{})
	// Expiry while waiting for the shared write gate must not touch another
	// peer's deadline or leave the gate held after returning.
	<-l.writes
	first.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	writeDone := make(chan error, 1)
	go func() { _, err := first.WriteTo([]byte("timeout"), first.remote); writeDone <- err }()
	select {
	case err := <-writeDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write deadline returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write gate ignored deadline")
	}
	l.writes <- struct{}{}
	first.Close()
	if err := first.SetWriteDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed peer accepted a deadline reset: %v", err)
	}
	if _, err := second.WriteTo([]byte("other peer still live"), second.remote); err != nil {
		t.Fatal(err)
	}
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "other peer still live" {
		t.Fatalf("closing/expiring one peer interrupted another: %q %v", buf[:n], err)
	}
	if _, err := second.WriteTo([]byte("wrong destination"), first.remote); err == nil {
		t.Fatal("peer migrated to a different address")
	}
	l.Close()
	if _, _, err := second.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener shutdown left peer open: %v", err)
	}
	if _, _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener shutdown left Accept open: %v", err)
	}
}
