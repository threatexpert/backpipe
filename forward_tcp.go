package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// The same target-bearing tunnel serves HTTP and raw TCP forward entries.
// ReadString stops exactly at the newline, preserving a target's early banner.
func openTCPTunnel(tunnel net.Conn, target string) error {
	tunnel.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeAll(tunnel, []byte("tcp://"+target+"\n")); err != nil {
		return err
	}
	response, err := netx.ReadString(tunnel, '\n', 1024)
	if err != nil {
		return err
	}
	if strings.TrimSpace(response) != "OK" {
		return fmt.Errorf("agent could not connect")
	}
	return tunnel.SetDeadline(time.Time{})
}

func serveTCPForward(client net.Conn, pool *connPool, target string, options *proxyOptions) {
	defer client.Close()
	tunnel := pool.pick(options.poolWait)
	if tunnel == nil {
		log.Printf("[server] no agent connection available, dropping TCP forward: %s -> %s", client.RemoteAddr(), target)
		return
	}
	defer tunnel.Close()
	atomic.AddInt64(&relayCount, 1)
	defer atomic.AddInt64(&relayCount, -1)
	if err := openTCPTunnel(tunnel, target); err != nil {
		log.Printf("[server] TCP forward failed: %s -> %s: %v", client.RemoteAddr(), target, err)
		return
	}
	log.Printf("[server] TCP forward started: %s via %s -> %s", client.RemoteAddr(), client.LocalAddr(), target)
	relay(client, tunnel)
	log.Printf("[server] TCP forward ended: %s -> %s", client.RemoteAddr(), target)
}
