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

// Keep the legacy TCP/TLS accept path unchanged. KCP sessions enter the same
// stream pool only after DTLS authentication and the KCP protocol handshake.
func acceptKCPPoolConns(ctx context.Context, ln net.Listener, pool *connPool, whitelist map[string]bool, cfg kcpSettings) error {
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
			return fmt.Errorf("unexpected KCP DTLS carrier")
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
			err := conn.HandshakeContext(hsCtx)
			var stream *kcpStreamConn
			if err == nil {
				stream, err = newKCPStream(conn, cfg)
			}
			if err == nil {
				err = stream.WaitReady(hsCtx)
			}
			cancel()
			<-sem
			if err != nil {
				if stream != nil {
					stream.abort(err)
				}
				if ctx.Err() == nil {
					log.Printf("[server] KCP/DTLS handshake failed: %s: %v", conn.RemoteAddr(), err)
				}
				return
			}
			defer stream.abort(net.ErrClosed)
			pool.add(stream)
			log.Printf("[server] agent connection pooled: %s (KCP/DTLS)", stream.RemoteAddr())
			select {
			case <-stream.done:
			case <-ctx.Done():
			}
		}()
	}
}

func runKCPAgent(ctx context.Context, ep endpoint, poolSize int, cfg kcpSettings, target string, proxy *proxyOptions, redirects redirectRules) error {
	opts, err := newDTLSPSKOptions(ep.psk, cfg.MTU)
	if err != nil {
		return err
	}
	var sockets dtlsConnSet
	var workers, active sync.WaitGroup
	stop := context.AfterFunc(ctx, sockets.closeAll)
	defer stop()
	log.Printf("[agent] KCP/DTLS server: %s, idle pool: %d", ep.address, poolSize)
	for i := 0; i < poolSize; i++ {
		workers.Add(1)
		go func(slot int) {
			defer workers.Done()
			attempt := 0
			for ctx.Err() == nil {
				hsCtx, cancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
				conn, err := dialDTLSPool(hsCtx, ep.address, opts)
				var stream *kcpStreamConn
				if err == nil && !sockets.register(conn, 0) {
					conn.Close()
					cancel()
					return
				}
				if err == nil {
					stream, err = newKCPStream(conn, cfg)
				}
				if err == nil {
					err = stream.WaitReady(hsCtx)
				}
				cancel()
				if err != nil {
					if stream != nil {
						stream.abort(err)
					}
					if conn != nil {
						sockets.remove(conn)
						conn.Close()
					}
					if ctx.Err() == nil {
						log.Printf("[agent-kcp-%d] connect failed: %v", slot, err)
					}
					if !dtlsRetryWait(ctx, attempt) {
						return
					}
					attempt++
					continue
				}
				attempt = 0
				log.Printf("[agent-kcp-%d] idle connection ready (KCP/DTLS)", slot)
				buf := make([]byte, 32*1024)
				n, err := stream.Read(buf)
				if err != nil {
					log.Printf("[agent-kcp-%d] idle connection lost: %v", slot, err)
					stream.abort(err)
					sockets.remove(conn)
					if !dtlsRetryWait(ctx, 0) {
						return
					}
					continue
				}
				// The slot replenishes immediately; active sessions stay tracked
				// separately so process shutdown also interrupts their forwarding.
				active.Add(1)
				go func() {
					defer active.Done()
					defer sockets.remove(conn)
					defer stream.Close()
					if proxy != nil {
						serveProxyTunnel(&readerConn{Conn: stream, reader: io.MultiReader(bytes.NewReader(buf[:n]), stream)}, proxy, redirects)
						return
					}
					dialer := net.Dialer{Timeout: 10 * time.Second}
					dst, err := dialer.DialContext(ctx, "tcp", redirects.rewrite("tcp", target))
					if err != nil {
						log.Printf("[agent-kcp-%d] target connect failed: %v", slot, err)
						return
					}
					defer dst.Close()
					setKeepalive(dst)
					if err := writeAll(dst, buf[:n]); err != nil {
						return
					}
					relay(stream, dst)
				}()
			}
		}(i + 1)
	}
	workers.Wait()
	sockets.closeAll()
	active.Wait()
	return nil
}
