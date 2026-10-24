package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

// UDP is carried as [uint16 big-endian length][SOCKS5 UDP header + payload],
// compatible with gonc's tunnel protocol. A timed-out partial frame terminates
// the association; it must never be retried as the start of the next frame.
func readUDPFrame(r io.Reader, buf []byte) ([]byte, error) {
	if packets, ok := r.(udpPacketTunnel); ok {
		return packets.ReadPacket(buf)
	}
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > len(buf) {
		return nil, fmt.Errorf("invalid UDP frame length: %d", n)
	}
	_, err := io.ReadFull(r, buf[:n])
	return buf[:n], err
}

func writeUDPFrame(w io.Writer, packet []byte) error {
	if packets, ok := w.(udpPacketTunnel); ok {
		return packets.WritePacket(packet)
	}
	if len(packet) == 0 || len(packet) > 65535 {
		return fmt.Errorf("invalid UDP packet length: %d", len(packet))
	}
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	return writeAll(w, frame)
}

func parseUDPPacket(packet []byte) (string, int, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, nil, fmt.Errorf("invalid or fragmented SOCKS5 UDP packet")
	}
	r := bytes.NewReader(packet[4:])
	host, port, err := readSOCKSAddress(r, packet[3])
	if err != nil {
		return "", 0, nil, err
	}
	return host, port, packet[len(packet)-r.Len():], nil
}

// Finish as soon as any direction ends, then unblock and join all remaining
// readers/writers. Both the SOCKS control TCP connection and tunnel own the
// UDP association's lifetime.
func runUDPLoops(closeAll func(), loops ...func()) {
	var wg sync.WaitGroup
	finished := make(chan struct{}, len(loops))
	for _, loop := range loops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { finished <- struct{}{} }()
			loop()
		}()
	}
	<-finished
	closeAll()
	wg.Wait()
}

func serveUDPAssociation(client, tunnel net.Conn, options *proxyOptions, key [32]byte) {
	local := client.LocalAddr().(*net.TCPAddr)
	peer := client.RemoteAddr().(*net.TCPAddr)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		socksReply(client, 1, nil)
		return
	}
	configureBusinessUDPReadBuffer(udp, "server")
	defer udp.Close()
	var packets net.PacketConn = udp
	if options.entryTLS != nil {
		// Match gonc: encrypt UDP with this control connection's TLS exporter
		// key. The pool carries ordinary framed packets inside its own transport.
		packets, err = secure.NewSecureUDPConn(udp, key)
		if err != nil {
			socksReply(client, 1, nil)
			return
		}
	}
	if err := openUDPTunnel(context.Background(), tunnel); err != nil {
		socksReply(client, 1, nil)
		return
	}
	bound := *udp.LocalAddr().(*net.UDPAddr)
	// Match gonc: advertise an unspecified IPv4 address by default so clients
	// use the TCP peer's address instead of a potentially private server IP.
	bound.IP = net.IPv4zero
	bound.Zone = ""
	if options.config.ServerIP != "" {
		bound.IP = net.ParseIP(options.config.ServerIP)
	}
	// Announce success only after both the server UDP listener and agent exit
	// socket are ready. The address belongs to the server, never the agent.
	if err := socksReply(client, 0, &bound); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	var refreshMu sync.Mutex
	refresh := func() {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		deadline := time.Now().Add(options.udpTimeout)
		udp.SetDeadline(deadline)
		tunnel.SetDeadline(deadline)
	}
	refresh()
	var peerMu sync.Mutex
	var endpoint *net.UDPAddr
	var sent, received int64
	log.Printf("[server] UDP association: %s via %s (transport=%s)", peer, udp.LocalAddr(), udpTransportName(tunnel))
	runUDPLoops(func() {
		client.Close()
		tunnel.Close()
		udp.Close()
	}, func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := packets.ReadFrom(buf)
			if err != nil {
				return
			}
			src := addr.(*net.UDPAddr)
			// Some clients (including gonc) put the destination in UDP
			// ASSOCIATE. Others advertise a pre-NAT source port. Learn the
			// actual endpoint from its first valid packet, never that field.
			if !src.IP.Equal(peer.IP) {
				continue
			}
			if _, _, _, err := parseUDPPacket(buf[:n]); err != nil {
				continue
			}
			peerMu.Lock()
			if endpoint == nil {
				endpoint = src
				log.Printf("[server] UDP client bound: %s via %s", src, udp.LocalAddr())
			}
			matches := endpoint.Port == src.Port && endpoint.IP.Equal(src.IP) && endpoint.Zone == src.Zone
			peerMu.Unlock()
			if !matches {
				continue
			}
			refresh()
			if err := writeUDPFrame(tunnel, buf[:n]); err != nil {
				return
			}
			sent++
		}
	}, func() {
		buf := make([]byte, 65535)
		for {
			packet, err := readUDPFrame(tunnel, buf)
			if err != nil {
				return
			}
			if _, _, _, err := parseUDPPacket(packet); err != nil {
				return
			}
			peerMu.Lock()
			dst := endpoint
			peerMu.Unlock()
			if dst != nil {
				refresh()
				if _, err := packets.WriteTo(packet, dst); err != nil {
					return
				}
				received++
			}
		}
	}, func() {
		// No data is expected on the control connection after UDP ASSOCIATE.
		var b [1]byte
		client.Read(b[:])
	})
	log.Printf("[server] UDP association ended: %s (sent=%d received=%d packets)", peer, sent, received)
}

func serveUDPTunnel(tunnel net.Conn, idle time.Duration, redirects redirectRules) {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		writeAll(tunnel, []byte("ERROR: cannot create UDP socket\n"))
		return
	}
	configureBusinessUDPReadBuffer(udp, "agent")
	defer udp.Close()
	tunnel.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeAll(tunnel, []byte("OK\n")); err != nil {
		return
	}
	serveUDPExit(tunnel, udp, idle, redirects)
}

// DTLS opens this socket before acknowledging OPEN; the TCP path sends OK
// above. Both transports use exactly the same redirect and reply semantics.
func serveUDPExit(tunnel net.Conn, udp *net.UDPConn, idle time.Duration, redirects redirectRules) {
	defer tunnel.Close()
	defer udp.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var refreshMu sync.Mutex
	refresh := func() {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		deadline := time.Now().Add(idle)
		udp.SetDeadline(deadline)
		tunnel.SetDeadline(deadline)
	}
	refresh()
	runUDPLoops(func() {
		cancel() // Also interrupt an in-flight DNS lookup on tunnel disconnect.
		tunnel.Close()
		udp.Close()
	}, func() {
		buf := make([]byte, 65535)
		cache := make(map[string]*net.UDPAddr)
		firstPacket := true
		for {
			packet, err := readUDPFrame(tunnel, buf)
			if err != nil {
				return
			}
			host, port, payload, err := parseUDPPacket(packet)
			if err != nil {
				continue
			}
			key := net.JoinHostPort(host, strconv.Itoa(port))
			dst := cache[key]
			if dst == nil {
				if target := redirects.rewrite("udp", key); target != key {
					// Parsed rules guarantee a valid host and numeric port.
					var targetPort string
					host, targetPort, _ = net.SplitHostPort(target)
					port, _ = strconv.Atoi(targetPort)
				}
				dst, err = resolveUDPTarget(ctx, host, port)
				if err != nil {
					continue
				}
				if len(cache) >= 256 {
					clear(cache)
				}
				cache[key] = dst
			}
			refresh()
			if _, err := udp.WriteToUDP(payload, dst); err != nil {
				log.Printf("[agent] UDP send to %s: %v", dst, err)
			} else if firstPacket {
				log.Printf("[agent] UDP forwarding: %s -> %s (transport=%s)", udp.LocalAddr(), dst, udpTransportName(tunnel))
				firstPacket = false
			}
		}
	}, func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := appendSOCKSAddress([]byte{0, 0, 0}, src)
			if len(packet)+n > 65535 {
				continue
			}
			packet = append(packet, buf[:n]...)
			refresh()
			if err := writeUDPFrame(tunnel, packet); err != nil {
				return
			}
		}
	})
}

func resolveUDPTarget(ctx context.Context, host string, port int) (*net.UDPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP address for %s", host)
	}
	selected := ips[0]
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			selected = ip
			break
		}
	}
	return &net.UDPAddr{IP: selected.IP, Zone: selected.Zone, Port: port}, nil
}
