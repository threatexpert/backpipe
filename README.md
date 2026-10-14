# backpipe

A reverse tunnel with fixed-target TCP forwarding and a server-side SOCKS5 TCP/UDP and HTTP proxy. The **agent** dials out to the **server** and maintains a pool of idle TCP connections. Each session uses its own connection, without mux channels. The agent immediately replenishes the pool when a session starts.

```
client -> server (-listen) <- pooled TCP/TLS connections <- agent -> destination
                     (-accept)                         (-connect)
```

Pool connections enter the idle pool immediately after TCP connection establishment (or TLS authentication when enabled). There is no backpipe registration message or application-level ACK. The first business request activates the agent connection and triggers replenishment. Update both peers together when replacing builds that used the earlier registration exchange.

`-pool` is the desired number of **idle** connections, not a limit on active sessions. Used connections are closed when sessions end; they do not return to the pool.

## SOCKS5 quick start

```sh
# Server: client entry on 1080, agent pool on 10086
backpipe server -listen socks5://:1080 -accept :10086

# Agent: omit -target to serve SOCKS5 TCP/UDP requests
backpipe agent -connect server_host:10086 -pool 20
```

The server authenticates proxy clients and assigns pool connections. The agent resolves domains and connects to destinations. Each SOCKS5 entry automatically accepts SOCKS5 CONNECT/UDP ASSOCIATE, HTTP CONNECT and ordinary HTTP/1.x proxy requests. SOCKS5 BIND is not supported.

Optional SOCKS5 username/password:

```sh
backpipe server -listen "socks5://user:pass@:1080" -accept :10086
```

Without credentials in the URL, the entry permits anonymous SOCKS5 and HTTP proxy access.

## HTTP compatibility on the same port

No extra flag or listener is required. A plain `socks5://` entry accepts ordinary SOCKS5 and HTTP proxies; `socks5s://` accepts both protocols **after** the same TLS+PSK handshake.

```sh
backpipe server -listen "socks5s://:1080?psk=123" -listen "socks5://127.0.0.1:3180" -accept "tls://:10086?psk=456"
backpipe agent -connect "tls://server_host:10086?psk=456" -pool 20

# Local HTTP proxy: ordinary HTTP forwarding and HTTPS through CONNECT
curl -x http://127.0.0.1:3180 http://example.com/
curl -x http://127.0.0.1:3180 https://example.com/

# gonc HTTP CONNECT over the encrypted public entry
gonc -x "https://server_host:1080?psk=123" target_host target_port
```

Clients can select SOCKS5 or HTTP on the same entry. HTTP/HTTPS URL schemes in these examples configure the **client**; server `-listen` schemes remain `socks5://` and `socks5s://` for these combined entries. An ordinary HTTPS-proxy client without gonc-compatible PSK authentication cannot connect to a `socks5s://` entry.

When an entry has `user:password`, HTTP uses Basic `Proxy-Authorization` and returns `407 Proxy Authentication Required` for missing/incorrect credentials before taking a pool connection. For gonc CONNECT compatibility, CONNECT also accepts Basic `Authorization` when `Proxy-Authorization` is absent. Ordinary HTTP preserves `Authorization` for the origin server; proxy credentials are removed before forwarding.

Ordinary HTTP supports streamed request/response bodies, chunked uploads and `Expect: 100-continue`. Each ordinary HTTP transaction uses one pool connection and closes the client connection after the response (no HTTP proxy keep-alive or direct protocol upgrades). CONNECT becomes a bidirectional TCP tunnel, including half-close, and can carry HTTPS. HTTP headers are limited to 64 KiB. UDP continues to use SOCKS5 UDP ASSOCIATE, not HTTP.

## Multiple entries sharing one pool

Repeat `-listen` to expose an encrypted public entry and a plain loopback entry in the same server:

```sh
backpipe server -listen "socks5s://:1080?psk=123" -listen "socks5://127.0.0.1:3180" -accept "tls://:10086?psk=456"
backpipe agent -connect "tls://server_host:10086?psk=456" -pool 20
```

Both entries support TCP and UDP. Public clients use `socks5s://server_host:1080?psk=123`; local applications use ordinary SOCKS5 at `127.0.0.1:3180`. The local entry avoids client-side TLS and UDP encryption while the shared server-agent tunnel remains encrypted.

Add more `-listen` options as needed. Each entry has its own address, username/password and PSK; credentials on one entry do not apply to another. All entries draw from the same idle pool, so `-pool 20` means 20 idle connections in total. Closing a session on one entry does not close sessions on other entries.

Every listening port (including `-accept`) must bind successfully before any traffic is served. If a bind fails, the server releases the ports it already bound and exits with an error identifying the failed entry. Logs include each entry's address and scheme, without its credentials.

`-udp-timeout` and `-socks-server-ip` remain shared server options. By default each UDP association advertises `0.0.0.0`, matching gonc. Compatible clients use the TCP control connection's peer IP, so public and loopback clients use their respective entry addresses. Setting `-socks-server-ip` overrides the advertised IP for **all** entries, including loopback entries.

Multiple `tcp://` entries can also share a fixed-target pool, but mixing `tcp://` with SOCKS5 entries in one server is rejected because their agent modes differ.

## Encryption

Client entry encryption and server-agent tunnel encryption are configured independently:

| Endpoint | Plain | TLS + PSK |
|----------|-------|-----------|
| Client entry (`-listen`) | `socks5://:1080` | `socks5s://:1080?psk=client-key` |
| Pool listener (`-accept`) | `:10086` | `tls://:10086?psk=tunnel-key` |
| Agent connection (`-connect`) | `server_host:10086` | `tls://server_host:10086?psk=tunnel-key` |

Encrypt only the server-agent tunnel, keeping an ordinary SOCKS5 entry:

```sh
backpipe server -listen socks5://:1080 -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

Encrypt both the client entry and the pool:

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

`socks5s` uses gonc-compatible TLS 1.2/1.3 with PSK mutual authentication for the SOCKS control/TCP connection. UDP uses a separate key exported from each TLS session and gonc's encrypted UDP wire format. Both requests and replies are encrypted between the client and server. This entry requires a compatible client, such as gonc:

```sh
# TCP through the encrypted entry
gonc -x "socks5s://server_host:1080?psk=client-key" target_host target_port

# UDP through the same encrypted entry
gonc -x "socks5s://server_host:1080?psk=client-key" -u target_host target_port
```

Entry and pool PSKs may differ. TLS schemes require a nonempty PSK; adding `psk` to a plain scheme is rejected. The compatible UDP format uses AES-CTR with a random IV; it provides encryption but no per-datagram authentication or replay protection. The agent sends ordinary TCP/UDP to the destination unless the application itself encrypts its traffic.

The pool and SOCKS entry share gonc-compatible TLS 1.2/1.3 handshakes and PSK-derived certificate authentication. The same PSK uses the same key derivation on either endpoint. After TLS, the pool speaks the tunnel request protocol and the entry speaks SOCKS5 or HTTP, so these ports are not interchangeable. This is certificate-based mutual TLS, not native TLS external-PSK authentication. TLS 1.3 is negotiated when both peers support it; TLS 1.2-only clients are also supported. TLS 1.0/1.1 are rejected. TLS 1.2 permits only ECDHE-ECDSA with AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305, providing forward secrecy. Successful handshakes log the negotiated version and cipher suite.

Pool TLS is incompatible with older backpipe binaries that used the `backpipe-ecdsa-psk-derive` derivation. Upgrade both server and agent together; there is no fallback to the old handshake. Command syntax is unchanged.

### Credentials and key files

Quote URLs and URL-encode special characters in credentials/query values: for example, `%40` for `@`, `%26` for `&`, `%23` for `#`, `%2B` for a literal `+` in a PSK, and `%20` for a space. Username and password each support 1..255 decoded bytes.

Use `psk=@file` to read a key from a local file's first line (surrounding whitespace is trimmed). Relative paths resolve from the working directory. Empty keys and unreadable files are rejected.

```sh
backpipe server -listen "socks5s://:1080?psk=@client.key" -accept "tls://:10086?psk=@tunnel.key"
backpipe agent -connect "tls://server_host:10086?psk=@tunnel.key" -pool 20
```

Logs and parsing diagnostics omit URL credentials and PSKs. Key files also avoid putting literal keys in the process command line.

## Fixed TCP target

Use a `tcp://` listener and give the agent a target:

```sh
backpipe server -listen tcp://:8080 -accept :10086
backpipe agent -connect server_host:10086 -target 127.0.0.1:80 -pool 20
```

The pool can use `tls://host:port?psk=key` just as in SOCKS5 mode. `-target` accepts `host:port` or `tcp://host:port`. Add `-ppv2` on the server to send a PROXY v2 header to a target that understands it.

Match both peers: SOCKS5 listeners require agents **without** `-target`; TCP listeners require agents **with** `-target`. Use separate server processes/pool ports for these two modes.

## UDP behavior

- Each UDP ASSOCIATE reserves one pool connection and creates an ephemeral UDP relay port on the **server**. The SOCKS reply advertises `0.0.0.0` (or the explicitly configured `-socks-server-ip`) and the allocated UDP port. The socket itself remains bound to the accepted TCP connection's local IP. An association can contact multiple destinations.
- Datagrams are framed over the TCP/TLS pool connection, then sent as UDP by the agent. TCP retransmission can delay datagrams in the same association.
- Keep the SOCKS TCP control connection open. Closing it, losing the tunnel, or reaching the idle timeout closes the association and its UDP sockets.
- Default idle timeout: `2m`. Set `-udp-timeout 5m` on both peers to change it; the shorter timeout takes effect.
- Permit inbound UDP to the allocated ephemeral ports; opening only UDP/1080 is insufficient. Fixed/shared UDP ports and configurable relay port ranges are not implemented.
- For a server behind NAT, clients that support the default `0.0.0.0` reply use the proxy IP they connected to. Set `-socks-server-ip PUBLIC_IP` if an explicit advertised IP is needed. Forward the allocated UDP ports without changing their numbers; this option does not create mappings.
- UDP source IP must match the control TCP peer. The first valid packet pins the actual source port. The address/port in UDP ASSOCIATE is not used for filtering, supporting gonc and clients behind NAT. Fragmented SOCKS5 packets are dropped.

## Options

Run `backpipe server -help` or `backpipe agent -help` for role-specific help.

| Option | Role | Default / purpose |
|--------|------|-------------------|
| `-listen` | server | Required, repeatable: `tcp://`, `socks5://`, or `socks5s://` client entry |
| `-accept` | server | Required: agent pool listener; bare address, `tcp://`, or `tls://` |
| `-connect` | agent | Required: server pool address; bare address, `tcp://`, or `tls://` |
| `-target` | agent | Omit for SOCKS5 exit; set for fixed TCP forwarding |
| `-pool` | agent | `5` idle connections |
| `-allow` | server | Comma-separated agent IP whitelist; empty permits all agent IPs |
| `-ppv2` | server | `false`; PROXY v2 header, TCP listener only |
| `-socks-server-ip` | server | SOCKS UDP advertised IP; defaults to `0.0.0.0` (client uses TCP peer IP) |
| `-udp-timeout` | both | `2m`; SOCKS5 mode only |
| `-version` | global | Print version and exit |

This CLI replaces the old `-mode/-left/-right/-socks5/-proto/-psk/-socks-auth/-left-ppv2` options. Old commands and the agent-side `:s5s` target are no longer accepted. Configure SOCKS5 on the server using `-listen` instead.

## Build and test

```sh
go build -o backpipe .
go test ./...
go vet ./...
```

Requires Go 1.26.8+. The gonc dependency is pinned to commit `41d3f96c03fec9fbcf7ed9524b61792fca61ebee` via `v2.6.11-0.20261013082942-41d3f96c03fe`, without a local `replace`. No additional gonc release is needed.

Tests exercise real server/agent processes, simultaneous plain/encrypted entries sharing a pool, startup rollback on port conflicts, gonc TCP/UDP and HTTP CONNECT clients, HTTP GET/POST and HTTPS forwarding, plain/encrypted pools, PSK rejection, per-session UDP encryption, SOCKS authentication, half-close, idle cleanup, reconnect/replenishment, and fixed-target forwarding. TCP uses gonc's exported tunnel handlers. UDP framing is compatible with gonc, while backpipe owns UDP session cleanup to avoid the pinned handler's wait-group and shared-address issues.

## License

MIT
