package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/netx"
)

type proxyOptions struct {
	config       apps.Socks5uConfig
	udpTimeout   time.Duration
	poolWait     time.Duration
	entryTLS     *tlsPSKConfig
	udpPool      *datagramPool
	udpTransport string
}

func newProxyOptions(serverIP string, idle time.Duration) (*proxyOptions, error) {
	if idle <= 0 {
		return nil, fmt.Errorf("-udp-timeout must be positive")
	}
	if serverIP != "" && net.ParseIP(serverIP) == nil {
		return nil, fmt.Errorf("-socks-server-ip must be an IP address")
	}
	o := &proxyOptions{
		config:     apps.Socks5uConfig{Logger: log.Default(), ServerIP: serverIP},
		udpTimeout: idle,
		poolWait:   30 * time.Second,
	}
	return o, nil
}

// readerConn preserves bytes consumed while detecting the first tunnel request,
// including CloseWrite so TCP clients can half-close and still receive a reply.
type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *readerConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func serveProxyTunnel(c net.Conn, options *proxyOptions, redirects redirectRules) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(c)
	prefix, err := reader.Peek(6)
	if err != nil {
		return
	}
	c = &readerConn{Conn: c, reader: reader}
	if string(prefix) != apps.TUNNEL_REQ_UDP {
		if len(redirects) != 0 && string(prefix) == apps.TUNNEL_REQ_TCP {
			line, err := netx.ReadString(c, '\n', 1024)
			if err != nil {
				return
			}
			original := strings.TrimPrefix(strings.TrimSpace(line), apps.TUNNEL_REQ_TCP)
			target := redirects.rewrite("tcp", original)
			if target != original {
				line = apps.TUNNEL_REQ_TCP + target + "\n"
			}
			// Replay the request for gonc, preserving buffered payload and half-close.
			c = &readerConn{Conn: c, reader: io.MultiReader(strings.NewReader(line), c)}
		}
		apps.ServeTunnelConn(&options.config, c)
		return
	}
	if _, err := netx.ReadString(c, '\n', 1024); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	// Keep UDP lifecycle management local: the pinned gonc UDP handler has an
	// unmatched WaitGroup.Add and cannot finish after its forwarding loops stop.
	serveUDPTunnel(c, options.udpTimeout, redirects)
}

func serveProxyClient(client net.Conn, pool *connPool, options *proxyOptions) {
	defer func() { client.Close() }()
	var key [32]byte
	if options.entryTLS != nil {
		client.SetDeadline(time.Now().Add(20 * time.Second))
		conn, err := negotiateTLSPSK(options.entryTLS, client)
		if err != nil {
			log.Printf("[server] proxy entry TLS handshake failed: %s: %v", client.RemoteAddr(), err)
			return
		}
		log.Printf("[server] proxy entry TLS negotiated: %s (%s)", client.RemoteAddr(), conn.description())
		client, key = conn, conn.KeyingMaterial
	}
	client.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(client)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 5 {
		serveHTTPProxy(client, reader, pool, options)
		return
	}
	client = &readerConn{Conn: client, reader: reader}
	if err := socksAuthenticate(client, options.config.Username, options.config.Password); err != nil {
		return
	}
	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return
	}
	if header[0] != 5 || header[2] != 0 {
		socksReply(client, 1, nil)
		return
	}
	if header[1] != 1 && header[1] != 3 {
		socksReply(client, 7, nil) // CONNECT and UDP ASSOCIATE only
		return
	}
	host, port, err := readSOCKSAddress(client, header[3], header[1] == 3)
	if err != nil {
		socksReply(client, 8, nil)
		return
	}
	// Authenticate and parse before claiming: idle/unauthenticated clients must
	// not reserve agent connections or cause the agent to replenish its pool.
	client.SetDeadline(time.Now().Add(options.poolWait + 30*time.Second))
	var tunnel net.Conn
	if header[1] == 3 {
		tunnel = selectUDPTunnel(context.Background(), pool, options)
	} else {
		tunnel = pool.pick(options.poolWait)
	}
	if tunnel == nil {
		socksReply(client, 1, nil)
		return
	}
	defer tunnel.Close()
	atomic.AddInt64(&relayCount, 1)
	defer atomic.AddInt64(&relayCount, -1)
	if header[1] == 3 {
		serveUDPAssociation(client, tunnel, options, key)
		return
	}
	client.SetDeadline(time.Time{})
	apps.ServeProxyOnTunnel(&options.config, client, key, tunnel, "CONNECT", host, port, nil)
}

func socksAuthenticate(c net.Conn, username, password string) error {
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		return err
	}
	if hello[0] != 5 || hello[1] == 0 {
		return fmt.Errorf("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	method := byte(0)
	if username != "" {
		method = 2
	}
	if !bytes.Contains(methods, []byte{method}) {
		writeAll(c, []byte{5, 255})
		return fmt.Errorf("no acceptable authentication method")
	}
	if err := writeAll(c, []byte{5, method}); err != nil || method == 0 {
		return err
	}
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		return err
	}
	if hello[0] != 1 || hello[1] == 0 {
		writeAll(c, []byte{1, 1})
		return fmt.Errorf("invalid username/password authentication")
	}
	u := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, hello[:1]); err != nil {
		return err
	}
	p := make([]byte, int(hello[0]))
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	uOK := subtle.ConstantTimeCompare(u, []byte(username))
	pOK := subtle.ConstantTimeCompare(p, []byte(password))
	if uOK&pOK != 1 {
		writeAll(c, []byte{1, 1})
		return fmt.Errorf("authentication failed")
	}
	return writeAll(c, []byte{1, 0})
}

func readSOCKSAddress(r io.Reader, atyp byte, allowEmptyDomain bool) (string, int, error) {
	var host string
	switch atyp {
	case 1, 4:
		n := net.IPv4len
		if atyp == 4 {
			n = net.IPv6len
		}
		ip := make(net.IP, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = ip.String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		if (len(name) == 0 && !allowEmptyDomain) || bytes.IndexFunc(name, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 {
			return "", 0, fmt.Errorf("invalid SOCKS5 hostname")
		}
		host = string(name)
		if host == "" {
			// Older gonc clients encode an unspecified UDP ASSOCIATE address
			// as an empty domain. Accept it only for association requests.
			host = "0.0.0.0"
		}
	default:
		return "", 0, fmt.Errorf("unsupported address type")
	}
	var port [2]byte
	_, err := io.ReadFull(r, port[:])
	return host, int(binary.BigEndian.Uint16(port[:])), err
}

func appendSOCKSAddress(b []byte, addr *net.UDPAddr) []byte {
	if ip := addr.IP.To4(); ip != nil {
		b = append(b, 1)
		b = append(b, ip...)
	} else {
		b = append(b, 4)
		b = append(b, addr.IP.To16()...)
	}
	return append(b, byte(addr.Port>>8), byte(addr.Port))
}

func socksReply(c net.Conn, code byte, addr *net.UDPAddr) error {
	if addr == nil {
		addr = &net.UDPAddr{IP: net.IPv4zero}
	}
	return writeAll(c, appendSOCKSAddress([]byte{5, code, 0}, addr))
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
