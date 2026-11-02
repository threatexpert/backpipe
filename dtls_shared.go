package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// Replay exactly one decrypted record. A stream reader (io.MultiReader) would
// merge/split DTLS messages and corrupt both KCP and native datagram framing.
type firstDTLSRecordConn struct {
	net.Conn
	first []byte
}

func (c *firstDTLSRecordConn) Read(buf []byte) (int, error) {
	if c.first == nil {
		return c.Conn.Read(buf)
	}
	if len(buf) < len(c.first) {
		return 0, io.ErrShortBuffer
	}
	n := copy(buf, c.first)
	c.first = nil
	return n, nil
}

// Call only after DTLS authentication. Existing agents send either BPK1 or
// BPD1 records first, so no new preface, wire version or negotiation is needed.
func classifyDTLSCarrier(ctx context.Context, conn net.Conn) (net.Conn, bool, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, false, err
	}
	buf := make([]byte, maxDatagramMTU)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	if n < 5 {
		return nil, false, fmt.Errorf("truncated shared DTLS protocol record")
	}
	native := bytes.Equal(buf[:4], datagramMagic[:])
	if !native && !bytes.Equal(buf[:4], kcpMagic) {
		return nil, false, fmt.Errorf("unknown shared DTLS protocol")
	}
	return &firstDTLSRecordConn{Conn: conn, first: buf[:n]}, native, nil
}

// One UDP socket owns both protocols, with common authentication/session
// limits. Every accepted DTLS connection still belongs to exactly one pool.
func acceptSharedDTLSPoolConns(ctx context.Context, ln net.Listener, streams *connPool, datagrams *datagramPool, whitelist map[string]bool, cfg kcpSettings, mtu int) error {
	if bounded, ok := ln.(*dtlsPoolListener); ok {
		bounded.packets.setWhitelist(whitelist)
	}
	var sockets dtlsConnSet
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { ln.Close(); sockets.closeAll() })
	defer func() { stop(); ln.Close(); sockets.closeAll(); workers.Wait() }()
	sem := make(chan struct{}, dtlsMaxHandshakes)
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !checkWhitelist(raw, whitelist) {
			raw.Close()
			continue
		}
		conn, ok := raw.(*dtls.Conn)
		if !ok {
			raw.Close()
			return fmt.Errorf("unexpected shared DTLS carrier")
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !sockets.register(conn, dtlsMaxSessions) {
			<-sem
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer sockets.remove(conn)
			defer conn.Close()
			hsCtx, cancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
			defer cancel()
			err := conn.HandshakeContext(hsCtx)
			var carrier net.Conn
			var native bool
			if err == nil {
				carrier, native, err = classifyDTLSCarrier(hsCtx, conn)
			}
			var stream *kcpStreamConn
			var session *datagramSession
			if err == nil {
				if native {
					session = newDatagramSession(carrier, datagramSessionConfig{Server: true, MTU: mtu})
					defer session.Close()
					err = session.WaitReady(hsCtx)
				} else {
					stream, err = newKCPStream(carrier, cfg)
					if stream != nil {
						defer stream.abort(net.ErrClosed)
					}
					if err == nil {
						err = stream.WaitReady(hsCtx)
					}
				}
			}
			cancel()
			<-sem
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("[server] shared DTLS handshake failed: %s: %v", conn.RemoteAddr(), err)
				}
				return
			}
			var done <-chan struct{}
			if native {
				datagrams.add(session)
				done = session.Done()
				log.Printf("[server] UDP agent session pooled: %s (shared DTLS)", conn.RemoteAddr())
			} else {
				streams.add(stream)
				done = stream.done
				log.Printf("[server] agent connection pooled: %s (shared KCP/DTLS)", conn.RemoteAddr())
			}
			select {
			case <-done:
			case <-ctx.Done():
			}
		}()
	}
}
