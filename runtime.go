package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// All listeners are bound before publishing any of them. TCP and UDP may use
// the same numeric port; a failed bind rolls the entire startup back.
func runConfiguredServer(c *commandConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var streamLn, datagramLn net.Listener
	var tlsConf *tlsPSKConfig
	var streamPool *connPool
	var udpPool *datagramPool
	defer func() {
		cancel()
		if streamLn != nil {
			streamLn.Close()
			streamPool.close()
		}
		if datagramLn != nil {
			datagramLn.Close()
			udpPool.close()
		}
	}()
	for _, ep := range c.tunnels {
		var err error
		if ep.scheme == "dtls" {
			udpPool = newDatagramPool()
			datagramLn, err = listenDTLSPool(ep, c.udpMTU)
		} else if ep.scheme == "kcp+dtls" {
			streamPool = newConnPool()
			streamLn, err = listenDTLSPool(ep, c.kcp.MTU)
		} else {
			streamPool = newConnPool()
			if ep.scheme == "tls" {
				tlsConf, err = newTLSPSKConfig(ep.psk, false)
				if err != nil {
					return fmt.Errorf("[server] cannot initialize TLS: %w", err)
				}
			}
			streamLn, err = net.Listen("tcp", ep.address)
		}
		if err != nil {
			return fmt.Errorf("[server] %s agent pool listen on %s: %w", ep.scheme, ep.address, err)
		}
	}
	listeners, err := bindClientListeners(c.entries)
	if err != nil {
		return fmt.Errorf("[server] startup failed: %w", err)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	whitelist := parseWhitelist(c.allow)
	finished := make(chan error, len(listeners)+1)
	if streamLn != nil {
		if c.tunnel.scheme == "kcp+dtls" {
			log.Printf("[server] agent pool: KCP over DTLS 1.2 with PSK mutual authentication, mtu=%d sndwnd=%d rcvwnd=%d heartbeat=%s timeout=%s", c.kcp.MTU, c.kcp.SendWindow, c.kcp.ReceiveWindow, c.kcp.Heartbeat, c.kcp.Timeout)
		} else if tlsConf != nil {
			log.Printf("[server] agent pool: TLS 1.2-1.3 with PSK mutual authentication")
		}
		log.Printf("[server] waiting for agent connections on %s", streamLn.Addr())
		if c.tunnel.scheme == "kcp+dtls" {
			go func() { finished <- acceptKCPPoolConns(ctx, streamLn, streamPool, whitelist, c.kcp) }()
		} else {
			go acceptPoolConns(streamLn, streamPool, whitelist, tlsConf)
		}
	}
	if datagramLn != nil {
		log.Printf("[server] waiting for UDP agent connections on %s (DTLS 1.2, PSK mutual authentication, mtu=%d)", datagramLn.Addr(), c.udpMTU)
		go func() { finished <- acceptDTLSPoolConns(ctx, datagramLn, udpPool, whitelist, c.udpMTU) }()
	}
	go statusTickerPools(ctx, streamPool, udpPool)
	for i, ln := range listeners {
		entry := c.entries[i]
		if entry.proxy != nil {
			entry.proxy.udpPool = udpPool
			entry.proxy.udpTransport = c.udpTransport
		}
		log.Printf("[server] waiting for user connections on %s (entry %d: %s)", ln.Addr(), i+1, entry.endpoint.scheme)
		if entry.endpoint.target != "" {
			log.Printf("[server] forwarding entry %d: %s -> %s via agent", i+1, entry.endpoint.scheme, entry.endpoint.target)
		}
		go func() {
			if ln.udp != nil {
				finished <- serveUDPForward(ln.udp, streamPool, entry.endpoint.target, entry.proxy)
			} else {
				finished <- acceptUserConns(ln.tcp, streamPool, c.ppv2, entry)
			}
		}()
	}
	return <-finished
}

func statusTickerPools(ctx context.Context, tcp *connPool, udp *datagramPool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	previous := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			idle, idleUDP := 0, 0
			if tcp != nil {
				idle = tcp.size()
			}
			if udp != nil {
				idleUDP = udp.size()
			}
			status := fmt.Sprintf("idle=%d relays=%d", idle, atomic.LoadInt64(&relayCount))
			if udp != nil {
				status += fmt.Sprintf(" udp-idle=%d", idleUDP)
			}
			if status != previous {
				log.Printf("[server] status: %s", status)
				previous = status
			}
		}
	}
}

func runConfiguredAgent(c *commandConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, len(c.tunnels))
	for _, ep := range c.tunnels {
		if ep.scheme == "dtls" {
			go func() { finished <- runDTLSAgent(ctx, ep, c.udpPool, c.udpMTU, c.proxy.udpTimeout, c.redirects) }()
		} else if ep.scheme == "kcp+dtls" {
			go func() { finished <- runKCPAgent(ctx, ep, c.pool, c.kcp, c.target.address, c.proxy, c.redirects) }()
		} else {
			proto := "plain"
			if ep.scheme == "tls" {
				proto = "tls"
			}
			go func() {
				runAgent(ep.address, c.target.address, c.pool, proto, ep.psk, c.proxy, c.redirects)
				finished <- nil
			}()
		}
	}
	return <-finished
}
