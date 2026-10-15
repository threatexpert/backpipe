# backpipe

backpipe 由 server 和 agent 组成。server 提供普通或加密的 SOCKS5/HTTP 代理服务，也支持固定目标 TCP/UDP 端口转发；agent 部署在出口节点，主动连接 server 建立加密隧道，为 server 转发出站流量。server 的代理请求和端口转发通过这些已有连接交给 agent 处理，因此从连接建立方向看，始终是 agent 主动连接 server。

## 加密快速开始

在 server 上同时开启公网加密入口、本地普通入口和加密连接池入口：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" -listen "socks5://127.0.0.1:3180" -accept "tls://:10086?psk=tunnel-key"
```

在 agent 上主动连接 server，维持 20 条空闲加密连接：

```sh
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

将 `server_host` 替换为 server 的地址，`client-key` 和 `tunnel-key` 替换为实际密钥；agent 与 server 的连接池密钥必须一致。

| 地址 | 用途 |
|------|------|
| `server_host:1080` | 公网加密代理入口，客户端使用 gonc 兼容的 TLS+PSK 协议，密钥为 `client-key` |
| `127.0.0.1:3180` | server 本机应用使用的普通 SOCKS5/HTTP 入口，省去本地接入的加密开销 |
| `server_host:10086` | agent 主动连接的加密连接池入口，密钥为 `tunnel-key` |

两个代理入口共享连接池，均支持 SOCKS5 TCP/UDP 和 HTTP。server 到 agent 的业务请求通过加密池连接传输。公网使用 UDP 时，还需允许访问 server 动态分配的 UDP 端口，详见后面的“UDP 行为与公网部署”。

## 工作原理

以通过上游出口节点访问 TCP 目标为例，常规代理链和 backpipe 的区别在于 **server 与出口节点之间，谁主动建立连接**。下图箭头表示 TCP 连接的发起方向，即首个 SYN 的发送方向；三次握手本身是双向交互，不表示数据只能沿箭头单向传输。

```text
常规代理链：由 SOCKS5 server 主动连接上游出口节点

用户客户端 ──→ SOCKS5 server ──→ upstream node ──→ target

backpipe：由上游出口节点 agent 主动连接 server

用户客户端 ──→ backpipe server ←── agent ──→ target
                SOCKS5 入口        出口节点
```

backpipe 中，agent 提前向 server 发起 TCP 连接；启用加密时，再由 agent 作为 TLS 客户端完成 TLS+PSK 双向认证，形成空闲连接池。用户请求到达后，server 从池中取出一条已有连接，将代理请求发送给 agent，由 agent 主动连接 target。server 无需再向 agent 发起 TCP 连接，agent 也无需开放供 server 接入的监听端口。

改变的是中间这一段的**连接发起方向**，业务请求和响应的路径仍然是：

```text
请求：用户客户端 → server → agent → target
响应：用户客户端 ← server ← agent ← target
```

以上握手方向示例针对 TCP 目标。代理 UDP 时，server-agent 之间仍使用 agent 主动建立的 TCP/TLS 池连接，agent 到 target 则发送 UDP 数据报，没有 TCP 握手。

每个会话独占一条连接，不使用 mux 多路复用。TCP 建立成功后（启用 TLS 时则在认证成功后），连接直接进入空闲池，不额外发送 backpipe 注册消息或应用层 ACK。首个业务请求激活连接后，agent 立即建立新连接补充空闲池。

`-pool` 指定的是**空闲连接数**，不是并发会话上限。已使用的连接在会话结束后关闭，不放回池中。

## 普通代理入口与用户名认证

```sh
# server：1080 为客户端入口，10086 为 agent 连接池入口
backpipe server -listen socks5://:1080 -accept :10086

# agent：不指定 -target，即作为 SOCKS5 TCP/UDP 和 HTTP 代理出口
backpipe agent -connect server_host:10086 -pool 20
```

server 负责客户端认证和连接池分配；agent 负责解析目标域名、连接目标服务。每个 SOCKS5 入口同时支持 SOCKS5 CONNECT、UDP ASSOCIATE、HTTP CONNECT 和普通 HTTP/1.x 代理请求。不支持 SOCKS5 BIND。

需要用户名和密码时，在入口 URL 中配置：

```sh
backpipe server -listen "socks5://user:pass@:1080" -accept :10086
```

未配置用户名和密码时，该入口允许匿名 SOCKS5 和 HTTP 代理访问。

## 同端口兼容 HTTP 代理

无需额外参数或监听端口。`socks5://` 入口自动识别 SOCKS5 和 HTTP；`socks5s://` 入口先完成 TLS+PSK 握手，再识别内部的 SOCKS5 或 HTTP 请求。

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" -listen "socks5://127.0.0.1:3180" -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20

# 本地 HTTP 代理：普通 HTTP 转发，以及通过 CONNECT 访问 HTTPS
curl -x http://127.0.0.1:3180 http://example.com/
curl -x http://127.0.0.1:3180 https://example.com/

# gonc 通过公网加密入口使用 HTTP CONNECT
gonc -x "https://server_host:1080?psk=client-key" target_host target_port
```

示例中的 `http://`、`https://` 是**客户端**的代理配置；server 的混合代理入口仍使用 `-listen socks5://...` 或 `-listen socks5s://...`。不支持 gonc PSK 认证的普通 HTTPS 代理客户端，不能直接连接加密入口。

入口配置了 `user:password` 时，HTTP 使用 Basic `Proxy-Authorization` 认证。缺少凭据或认证失败时返回 `407 Proxy Authentication Required`，不占用连接池。为兼容 gonc，CONNECT 请求在没有 `Proxy-Authorization` 时也接受 Basic `Authorization`。普通 HTTP 请求的 `Authorization` 保留给目标网站；代理认证信息在转发前移除。

普通 HTTP 支持请求和响应正文的流式传输、分块上传和 `Expect: 100-continue`。每次普通 HTTP 请求使用一条池连接，响应完成后关闭客户端连接，不支持 HTTP 代理连接复用或直接协议升级。CONNECT 建立双向 TCP 隧道，支持半关闭，可承载 HTTPS。HTTP 请求头上限为 64 KiB。UDP 仍通过 SOCKS5 UDP ASSOCIATE 使用。

## 多个入口共享连接池

重复指定 `-listen`，即可同时提供公网加密入口和本地普通入口：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" -listen "socks5://127.0.0.1:3180" -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

两个入口都支持 TCP 和 UDP。公网客户端连接 `socks5s://server_host:1080?psk=client-key`；本地应用连接 `127.0.0.1:3180`，使用普通 SOCKS5 或 HTTP 代理。本地入口省去客户端到 server 的加密开销，server 到 agent 的连接池仍然加密。

每个 SOCKS5 入口可以独立配置监听地址、用户名、密码和 PSK，不同入口的凭据互不通用。也可以同时添加 `tcp://地址?to=目标` 和 `udp://地址?to=目标` 固定转发入口，详见后文。所有这些入口共享同一个空闲池，`-pool 20` 表示总共维持 20 条空闲连接。关闭某个入口上的会话，不影响其他入口的会话。

所有监听端口（包括 `-accept`）均绑定成功后才开始提供服务。任一端口绑定失败，server 会释放此前已绑定的端口，并报告失败的入口。日志显示入口地址和协议，不输出凭据。

`-udp-timeout` 是所有 UDP 会话共用的 server 参数。`-socks-server-ip` 仅影响 SOCKS5 入口：默认 UDP 回复地址为 `0.0.0.0`，与 gonc 一致。兼容客户端会使用 TCP 控制连接的对端 IP，因此公网和本地客户端分别使用各自连接的入口地址。显式设置 `-socks-server-ip` 会覆盖**所有 SOCKS5 入口**的回复 IP，包括本地入口，不影响固定 UDP 转发。

不带 `to` 的 `tcp://` 入口仍使用 agent `-target` 指定目标。多个这样的入口可以共享连接池，但不能与 SOCKS5 或带 `to` 的转发入口混用。

## 加密与认证

客户端入口和 server-agent 连接池的加密独立配置：

| 位置 | 明文 | TLS+PSK |
|------|------|---------|
| 客户端入口 `-listen` | `socks5://:1080` | `socks5s://:1080?psk=client-key` |
| 连接池监听 `-accept` | `:10086` | `tls://:10086?psk=tunnel-key` |
| agent 连接 `-connect` | `server_host:10086` | `tls://server_host:10086?psk=tunnel-key` |

仅加密连接池，保留普通代理入口：

```sh
backpipe server -listen socks5://:1080 -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

同时加密客户端入口和连接池：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" -accept "tls://:10086?psk=tunnel-key"
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20
```

入口和连接池都使用与 gonc 兼容的 TLS 1.2/1.3 协议，以及 PSK 派生的证书进行双向认证。这是基于证书的双向 TLS，不是 TLS 原生的外部 PSK 认证。相同 PSK 在两种连接上使用相同的密钥派生方式，但 TLS 内部承载的应用协议不同，两个端口不能互换。

双方都支持时优先协商 TLS 1.3，同时兼容仅支持 TLS 1.2 的客户端。拒绝 TLS 1.0/1.1；TLS 1.2 仅允许以下具有前向安全性的套件：

- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

握手成功后，日志会显示实际协商的 TLS 版本和密码套件。

`socks5s` 的控制连接和 TCP 数据通过 TLS 传输。独立 UDP 数据报使用每个 TLS 会话导出的密钥，并采用 gonc 的加密 UDP 格式，客户端到 server 的请求和回复均加密。可使用 gonc 等兼容客户端：

```sh
# 通过加密入口转发 TCP
gonc -x "socks5s://server_host:1080?psk=client-key" target_host target_port

# 通过同一入口转发 UDP
gonc -x "socks5s://server_host:1080?psk=client-key" -u target_host target_port
```

入口与连接池可以使用不同 PSK。加密地址必须配置非空 PSK；明文地址不接受 `psk` 参数。示例中的密钥仅作说明，实际部署请使用高强度随机密钥。

兼容 gonc 的 UDP 格式使用 AES-CTR 和随机 IV，提供加密，但没有逐包消息认证或防重放保护。agent 到目标服务使用普通 TCP/UDP，除非应用协议自身也提供加密。

旧版 backpipe 曾使用 `backpipe-ecdsa-psk-derive` 派生密钥，与当前连接池认证不兼容。升级时请同时更新 server 和 agent。若旧构建包含注册握手，也应同时更新两端；当前不再使用该握手。

### 凭据与密钥文件

包含凭据或查询参数的 URL 应用引号包住。特殊字符需要 URL 编码，例如：`@` 为 `%40`、`&` 为 `%26`、`#` 为 `%23`、PSK 中的加号为 `%2B`、空格为 `%20`。用户名和密码解码后分别支持 1～255 字节。

使用 `psk=@文件路径` 从文件第一行读取密钥，自动去掉首尾空白。支持绝对路径；相对路径以程序启动时的工作目录为基准。空密钥或无法读取的文件会报错。

```sh
backpipe server -listen "socks5s://:1080?psk=@client.key" -accept "tls://:10086?psk=@tunnel.key"
backpipe agent -connect "tls://server_host:10086?psk=@tunnel.key" -pool 20

# Windows 绝对路径示例
backpipe agent -connect "tls://server_host:10086?psk=@D:/keys/tunnel.key" -pool 20
```

URL 的第一个查询参数使用 `?psk=`，已有其他参数时使用 `&psk=`。日志和参数解析错误不输出 URL 中的凭据和 PSK。使用密钥文件也能避免把密钥明文放进进程命令行。

## 固定目标 TCP/UDP 端口转发

在 `-listen` 中通过 `to=host:port` 指定目标，每个入口可以使用不同目标，并与 SOCKS5/HTTP 入口共享连接池。客户端直接连接或发送原始 TCP/UDP 数据，无需使用代理协议：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" \
  -listen "socks5://127.0.0.1:3180" \
  -listen "udp://:500?to=charon:500" \
  -listen "tcp://:8080?to=web:80" \
  -accept "tls://:10086?psk=tunnel-key"

backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20 \
  -redirect "udp://charon:500=10.1.2.3:500" \
  -redirect "tcp://web:80=10.1.2.3:80"
```

| server 入口 | 原目标 | agent 实际访问 |
|-------------|--------|----------------|
| UDP `:500` | `charon:500` | UDP `10.1.2.3:500` |
| TCP `:8080` | `web:80` | TCP `10.1.2.3:80` |

`to` 是**由 agent 访问的目标地址**。server 不解析该域名；agent 先匹配 `-redirect`，命中后访问替换地址，未命中时再按原目标解析、连接。`charon` 和 `web` 因此可以是没有 DNS 记录的逻辑名称，也可以直接使用真实域名或 IP。它们不是 agent 标识；多个 agent 加入同一个连接池时，会话使用池中任意可用连接，所有出口都应能处理这些目标。

此模式下 agent **不指定 `-target`**。TCP 每个客户端连接占用一条池连接，支持双向转发和半关闭。UDP 按“监听入口＋客户端来源 IP、端口”维护会话：首包取用一条池连接，后续包复用；不同客户端及不同入口的会话互相隔离。每条池连接激活后，agent 自动补充空闲池。

UDP 回包从 server 的原监听端口返回原客户端，例如上例始终通过 server 的 UDP 500 端口回复。agent 内部仍按实际回复来源封包，server 解包后只将原始 UDP 数据交给客户端，不需要给 `-redirect` 增加反向地址映射。目标服务看到的是 agent 的出口地址和自动分配的 UDP 源端口，不保留客户端源地址，也不保证源端口为 500。

UDP 默认空闲 `2m` 后释放会话，双向流量都会延长存活时间；可在 server 和 agent 两端设置 `-udp-timeout 5m`。超时或隧道断开后，下一包重新取用池连接，agent 的 UDP 源端口可能变化。每个固定 UDP 入口最多维持 1024 个会话，其中等待 agent 就绪的会话最多 128 个；每会话最多排队 16 个数据报，入口总排队载荷最多 8 MiB。等待 agent 超时或超过这些容量时会丢包。UDP 数据仍封装在连接池的 TCP/TLS 连接中，TCP 重传可能延迟同一会话的后续数据报。

固定转发入口 `tcp://`、`udp://` 本身不提供 TLS+PSK 或代理用户名认证；`-accept/-connect tls://...` 加密的是 server 与 agent 之间的连接。客户端到 server 的加密取决于应用协议自身。固定 UDP 入口只需开放配置的 UDP 监听端口，例如 UDP/500；连接池另需开放 TCP/10086，不使用 SOCKS5 动态分配的 UDP 端口。

`udp://` 必须指定 `to`；`to` 只能用于 TCP/UDP 监听入口，且只能出现一次。目标格式为 `host:port`，端口范围为 1～65535；IPv6 使用方括号，例如 `-listen "tcp://:8080?to=[2001:db8::1]:80"`。每个入口只有一个固定目标，需要多个规则时重复指定 `-listen`。

### agent 指定目标的 TCP 转发

也可以使用不带 `to` 的 `tcp://` 入口，由 agent `-target` 指定统一目标：

```sh
backpipe server -listen tcp://:8080 -accept :10086
backpipe agent -connect server_host:10086 -target 127.0.0.1:80 -pool 20
```

连接池同样支持 `tls://host:port?psk=key`。`-target` 接受 `host:port` 或 `tcp://host:port`。目标服务支持 PROXY v2 时，可在 server 添加 `-ppv2`，向目标发送包含客户端地址的 PROXY v2 头。

两端模式必须匹配：SOCKS5 入口和带 `to` 的 TCP/UDP 入口对应**不带** `-target` 的 agent；不带 `to` 的 TCP 入口对应**带** `-target` 的 agent。两种模式不能共享连接池；需要同时使用时，请分别运行 server 进程并使用不同的连接池端口。`-ppv2` 仅用于这种不带 `to` 的 TCP 模式。

## agent 出站目标重定向

在 agent 上重复指定 `-redirect`，可以在连接目标前改写目标地址和端口。server 和客户端无需修改配置，连接池协议也不变。

```sh
backpipe agent -connect "tls://server_host:10086?psk=@tunnel.key" -pool 20 \
  -redirect "priv-domain:500=1.2.3.4:600" \
  -redirect "tcp://web.internal:443=10.0.0.8:8443" \
  -redirect "udp://dns.internal:53=10.0.0.53:5353"
```

规则格式为 `[tcp://|udp://]原主机:原端口=新主机:新端口`。协议前缀写在等号左侧，右侧只写 `host:port`；不写协议时同时匹配 TCP 和 UDP。重定向不会把 TCP 转换成 UDP，或反过来。IPv6 地址使用方括号，例如 `-redirect "[2001:db8::1]:500=[2001:db8::2]:600"`。

规则精确匹配协议、主机和端口，支持 IP 和 ASCII 域名（国际化域名请使用 Punycode），不支持通配符、正则或网段。域名匹配忽略大小写和末尾的一个点，IP 按标准形式比较。匹配发生在 DNS 解析之前，因此原域名没有 DNS 记录也可以重定向；但如果客户端已经将域名解析成 IP，域名规则不会命中，应改用 IP 规则或让客户端将域名交给代理。

重定向适用于 SOCKS5 TCP、HTTP CONNECT、普通 HTTP、SOCKS5 UDP、`-listen` 的 TCP/UDP `to` 目标，以及 agent 的 `-target`。仅改变实际连接或发送的目标，不修改 HTTP Host、TLS SNI 或应用数据，也不影响 agent 的 `-connect` 连接池地址。

- 未命中规则时，仍访问原目标。
- 命中后只改写一次，不继续用新目标匹配下一条规则。
- 同一协议和原目标不能重复配置；不带协议的规则与相同目标的单协议规则也不能重叠。冲突在启动时报错。
- 实际目标连接或解析失败时，不回退到原目标。
- 规则在 agent 启动时读取；修改参数后需要重启 agent。

**UDP 只改发送目标，不改回复来源。** 例如 `priv-domain:500=1.2.3.4:600`，agent 向 `1.2.3.4:600` 发包，收到它的回复后，SOCKS5 UDP 回复头仍填写实际来源 `1.2.3.4:600`，不会恢复成 `priv-domain:500`。如果客户端要求回复来源必须匹配原目标，可能丢弃该回复。不同原目标映射到同一实际地址时，也不会根据来源地址反向区分原目标。

规则命中时会输出日志：

```text
[agent] redirect tcp: priv-domain:500 -> 1.2.3.4:600
[agent] redirect udp: priv-domain:500 -> 1.2.3.4:600
```

UDP 会缓存会话内已解析的目标，命中缓存时不重复打印重定向日志。

## UDP 行为与公网部署

以下说明针对 SOCKS5 UDP 代理。固定 UDP 入口的会话和回包行为见“固定目标 TCP/UDP 端口转发”。

- 每个 UDP ASSOCIATE 占用一条池连接，并在 **server** 上分配一个临时 UDP 端口；一个会话可以访问多个目标。
- 默认向客户端回复 `0.0.0.0` 和实际分配的端口；显式指定 `-socks-server-ip` 时使用配置 IP。实际 socket 仍绑定在 TCP 控制连接的本机 IP 上。
- 客户端 UDP 包通过 server-agent 的 TCP/TLS 连接封装转发，再由 agent 以 UDP 发往目标。TCP 重传可能延迟同一会话中的后续数据报。
- SOCKS TCP 控制连接必须保持打开。控制连接关闭、隧道断开或空闲超时，都会结束 UDP 会话并关闭相关 socket。
- 默认空闲超时为 `2m`。修改时可在两端都设置 `-udp-timeout 5m`；两端不一致时，较短的超时会先触发。
- 防火墙和安全组需要允许访问动态分配的 UDP 端口，仅开放 UDP/1080 不够。SOCKS5 UDP 代理目前不支持固定或共享 UDP 端口，也不支持配置分配端口范围；固定目标转发可使用 `-listen "udp://:端口?to=目标:端口"`。
- server 位于 NAT 后时，支持 `0.0.0.0` 回退的客户端会使用所连接的代理 IP。需要明确指定回复地址时，可设置 `-socks-server-ip 公网IP`。NAT 仍需将分配的 UDP 端口按同号映射到 server，此参数不会自动创建映射。
- UDP 来源 IP 必须与 TCP 控制连接的对端 IP 一致；首个有效数据包确定实际来源端口。不会拿 UDP ASSOCIATE 请求里的地址和端口过滤数据，兼容 gonc 及 NAT 后的客户端。不支持分片 SOCKS5 UDP 数据报。

排查时可关注这些日志：

| 日志 | 含义 |
|------|------|
| `[server] UDP association: ... via ...` | server 和 agent 已准备好 UDP 会话；`via` 显示实际监听地址，不是回复给客户端的地址 |
| `[server] UDP client bound: ...` | server 收到并接受了首个有效客户端 UDP 包 |
| `[agent] UDP forwarding: ... -> ...` | agent 首次成功将 UDP 包交给本机 socket 发往目标，不代表目标已收到或回复 |
| `[server] UDP association ended: ... (sent=N received=M packets)` | 会话结束；`sent` 为成功写入 agent 隧道的包数，`received` 为从隧道返回并成功写入客户端 UDP socket 的包数 |

## 参数说明

使用 `backpipe server -help` 或 `backpipe agent -help` 查看对应角色的帮助。

| 参数 | 角色 | 默认值与用途 |
|------|------|--------------|
| `-listen` | server | 必填，可重复；代理入口 `socks5://`、`socks5s://`；固定转发 `tcp://地址?to=目标`、`udp://地址?to=目标`；裸 `tcp://` 配合 agent `-target` |
| `-accept` | server | 必填；agent 连接池监听地址，支持裸地址、`tcp://`、`tls://` |
| `-connect` | agent | 必填；server 连接池地址，支持裸地址、`tcp://`、`tls://` |
| `-target` | agent | 省略时处理代理和带 `to` 的 TCP/UDP 转发；指定时仅配合不带 `to` 的 TCP 入口 |
| `-pool` | agent | `5`；要维持的空闲连接数 |
| `-redirect` | agent | 可重复；`[tcp://\|udp://]host:port=host:port`，默认同时匹配 TCP/UDP |
| `-allow` | server | agent IP 白名单，以逗号分隔；留空时不限制 agent IP |
| `-ppv2` | server | `false`；发送 PROXY v2 头，仅支持不带 `to` 的 TCP 入口 |
| `-socks-server-ip` | server | SOCKS5 UDP 回复 IP；默认 `0.0.0.0`，由兼容客户端使用 TCP 对端 IP，不影响固定 UDP 入口 |
| `-udp-timeout` | 两端 | `2m`；SOCKS5 UDP 和固定 UDP 转发的空闲超时 |
| `-version` | 全局 | 输出版本并退出 |

当前命令行已替代旧的 `-mode/-left/-right/-socks5/-proto/-psk/-socks-auth/-left-ppv2` 参数，不兼容旧命令，也不再接受 agent 侧的 `:s5s` 目标。请通过 server 的 `-listen` 配置代理入口。

## 构建与测试

需要 Go 1.26.8 或更高版本。

```sh
go build -o bin/backpipe .
go test ./...
go vet ./...
```

Windows 下可运行 `build.bat` 构建 Windows 和 Linux amd64 程序，产物位于 `bin/`，该目录已由 Git 忽略。

gonc 依赖固定到提交 `41d3f96c03fec9fbcf7ed9524b61792fca61ebee`，对应伪版本 `v2.6.11-0.20261013082942-41d3f96c03fe`。不使用本地 `replace`，也无需额外发布 gonc 版本。

测试覆盖真实 server/agent 进程、普通和加密多入口共享连接池、端口绑定失败回滚、gonc TCP/UDP 及 HTTP CONNECT 兼容、HTTP GET/POST 和 HTTPS 转发、PSK 拒绝、TLS 版本与套件协商、每会话 UDP 加密、SOCKS 认证、半关闭、空闲清理、断线重连、自动补池、固定目标转发，以及出站重定向、HTTP Host 保留和 UDP 实际回复来源。

TCP 转发使用 gonc 导出的隧道处理接口。UDP 帧格式与 gonc 兼容，会话清理由 backpipe 自行管理，以避开所固定依赖版本中的等待组和共享地址问题。

## 许可证

MIT
