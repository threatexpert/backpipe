# backpipe

A lightweight reverse TCP tunnel relay written in Go. The **agent** runs behind NAT and dials out to a public **server**, pre-establishing a pool of idle connections. When a user connects to the server, one idle connection is instantly claimed and bridged to the target service — no firewall rules required on the agent side.

## How it works

```
User → [server:left] ←→ [server:right] ←← agent ←→ target
```

1. Agent pre-dials the server and parks N idle connections in a pool
2. When a user connects to the server's left port, the server claims one idle connection
3. Traffic is relayed bidirectionally between the user and the agent's target

## Quick start

**Server** (public machine):
```sh
backpipe -mode server -left 0.0.0.0:10888 -right 0.0.0.0:10086
```

**Agent** (behind NAT, forwarding to local SSH):
```sh
backpipe -mode agent -left server_host:10086 -right 127.0.0.1:22 -pool 5
```

Now `nc server_host 10888` reaches the agent's `127.0.0.1:22`.

## TLS + PSK mutual authentication

Both sides derive an ECDSA certificate from the same pre-shared key. Connections from agents with a wrong PSK are rejected at the TLS handshake level.

```sh
# server
backpipe -mode server -left 0.0.0.0:10888 -right 0.0.0.0:10086 -proto tls -psk mysecret

# agent
backpipe -mode agent -left server_host:10086 -right 127.0.0.1:22 -pool 5 -proto tls -psk mysecret
```

## Built-in SOCKS5 proxy

Use `:s5s` as the target to run a SOCKS5 proxy on the agent side instead of forwarding to a fixed host:

```sh
# anonymous
backpipe -mode agent -left server_host:10086 -right ":s5s" -pool 5

# with authentication and HTTP CONNECT support
backpipe -mode agent -left server_host:10086 -right ":s5s -auth user:pass -http" -pool 5
```

## IP whitelist

Restrict which agent IPs are allowed to connect to the server's pool port:

```sh
backpipe -mode server -left 0.0.0.0:10888 -right 0.0.0.0:10086 -allow 1.2.3.4,5.6.7.8
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | — | `server` or `agent` |
| `-left` | — | server: user listen addr; agent: server addr to connect |
| `-right` | — | server: agent pool listen addr; agent: target addr |
| `-pool` | `5` | agent: number of pre-established idle connections |
| `-proto` | `plain` | tunnel protocol: `plain` or `tls` |
| `-psk` | — | pre-shared key for TLS mutual auth (required with `-proto tls`) |
| `-allow` | — | server: comma-separated agent IP whitelist |
| `-version` | — | print version and exit |

## Build

```sh
go build -o backpipe .
```

Requires Go 1.24+.

## License

MIT
