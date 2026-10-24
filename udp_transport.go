package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// Packet boundaries are explicit for both carriers. DTLS never passes through
// stream framing, which would incorrectly impose reliable/ordered delivery.
type udpPacketTunnel interface {
	net.Conn
	ReadPacket([]byte) ([]byte, error)
	WritePacket([]byte) error
}

func udpTransportName(tunnel net.Conn) string {
	if _, ok := tunnel.(udpPacketTunnel); ok {
		return "dtls"
	}
	return "tcp"
}

// Transport is chosen by configuration, never by transient pool availability.
// A failed activation ends this association; no payload is replayed or moved
// to a TCP connection or another agent. Replenishing the idle pool is separate.
func selectUDPTunnel(ctx context.Context, tcp *connPool, options *proxyOptions) net.Conn {
	if options.udpTransport != "udp" {
		if tcp == nil {
			return nil
		}
		return pickUDPForwardTunnel(ctx, tcp, options.poolWait)
	}
	if options.udpPool == nil {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, options.poolWait)
	defer cancel()
	for waitCtx.Err() == nil {
		if session := options.udpPool.tryClaim(); session != nil {
			openCtx, stop := context.WithTimeout(waitCtx, 3*time.Second)
			err := session.Open(openCtx)
			stop()
			if err == nil && waitCtx.Err() == nil {
				return session
			}
			session.Close()
			log.Printf("[server] UDP agent activation failed: %v", err)
			return nil
		}
		select {
		case <-waitCtx.Done():
		case <-options.udpPool.done:
			return nil
		case <-options.udpPool.avail:
		}
	}
	return nil
}

func openUDPTunnel(ctx context.Context, tunnel net.Conn) error {
	if _, ok := tunnel.(udpPacketTunnel); ok {
		return ctx.Err() // already activated and acknowledged by selectUDPTunnel
	}
	stop := context.AfterFunc(ctx, func() { tunnel.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	tunnel.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeAll(tunnel, []byte("udp://0.0.0.0:0\n")); err != nil {
		return err
	}
	response, err := netx.ReadString(tunnel, '\n', 1024)
	if err != nil {
		return err
	}
	if response != "OK\n" {
		return fmt.Errorf("agent could not open UDP exit")
	}
	return ctx.Err()
}
