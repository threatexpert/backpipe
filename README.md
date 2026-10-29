# backpipe

backpipe 由 server 和 agent 组成。server 提供普通或加密的 SOCKS5/HTTP 代理服务，也支持固定目标 TCP/UDP 端口转发；agent 部署在出口节点，主动连接 server 建立加密隧道，为 server 转发出站流量。server 的代理请求和端口转发通过这些已有连接交给 agent 处理，因此从连接建立方向看，始终是 agent 主动连接 server。

## 加密快速开始

在 server 上同时开启公网加密代理、本地普通代理、UDP 500/4500 和 TCP 8080 端口转发，所有入口共享加密连接池：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" \
  -listen "socks5://127.0.0.1:3180" \
  -listen "udp://:500?to=charon:500" \
  -listen "udp://:4500?to=charon:4500" \
  -listen "tcp://:8080?to=web:80" \
  -accept "tls://:10086?psk=tunnel-key"
```

在 agent 上主动连接 server，维持 20 条空闲加密连接，并将转发目标重定向到实际服务地址：

```sh
backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" -pool 20 \
  -redirect "udp://charon:500=10.1.2.3:500" \
  -redirect "udp://charon:4500=10.1.2.3:4500" \
  -redirect "tcp://web:80=10.1.2.3:80"
```

将 `server_host` 替换为 server 的地址，`client-key` 和 `tunnel-key` 替换为实际密钥；agent 与 server 的连接池密钥必须一致。

将 `10.1.2.3` 替换为 agent 本机或其可访问的目标服务 IP，各条规则可以使用不同 IP。`charon` 和 `web` 是用于匹配重定向规则的逻辑名称，无需配置 DNS。仅使用代理时，省略三个固定转发 `-listen` 和对应的 `-redirect` 即可。

| 地址 | 用途 |
|------|------|
| `server_host:1080` | 公网加密代理入口，客户端使用 gonc 兼容的 TLS+PSK 协议，密钥为 `client-key` |
| `127.0.0.1:3180` | server 本机应用使用的普通 SOCKS5/HTTP 入口，省去本地接入的加密开销 |
| `server_host:500/UDP` | 经 agent 转发到 `10.1.2.3:500/UDP` |
| `server_host:4500/UDP` | 经 agent 转发到 `10.1.2.3:4500/UDP` |
| `server_host:8080/TCP` | 经 agent 转发到 `10.1.2.3:80/TCP` |
| `server_host:10086` | agent 主动连接的加密连接池入口，密钥为 `tunnel-key` |

两个代理入口均支持 SOCKS5 TCP/UDP 和 HTTP，与固定转发入口共用这 20 条空闲连接，使用后自动补池。所有入口的 server-agent 流量均通过加密池连接传输；固定 TCP/UDP 入口不要求客户端使用代理协议，其客户端到 server 的加密由应用协议自身提供。

防火墙按需开放 TCP 1080、8080、10086 和 UDP 500、4500。公网使用 SOCKS5 UDP 代理时，还需允许访问 server 动态分配的 UDP 端口，详见后面的“UDP 行为与公网部署”；固定 UDP 转发只使用配置的监听端口。

### 增加原生 UDP 隧道（v1.4.0）

在前面的 TLS 连接池之外，增加独立的 DTLS 会话池，让 UDP 业务在 server 与 agent 之间也通过 UDP 传输。SOCKS5/HTTP 客户端、固定转发目标和 agent 重定向规则均无需改变：

```sh
backpipe server -listen "socks5s://:1080?psk=client-key" \
  -listen "socks5://127.0.0.1:3180" \
  -listen "udp://:500?to=charon:500" \
  -listen "udp://:4500?to=charon:4500" \
  -listen "tcp://:8080?to=web:80" \
  -accept "tls://:10086?psk=tunnel-key" \
  -accept "dtls://:10086?psk=tunnel-key" \
  -udp-transport udp

backpipe agent -connect "tls://server_host:10086?psk=tunnel-key" \
  -connect "dtls://server_host:10086?psk=tunnel-key" \
  -pool 20 -udp-pool 20 \
  -redirect "udp://charon:500=10.1.2.3:500" \
  -redirect "udp://charon:4500=10.1.2.3:4500" \
  -redirect "tcp://web:80=10.1.2.3:80"
```

TCP/TLS 和 DTLS 可以使用相同的数字端口，分别监听 TCP/10086 与 UDP/10086；防火墙需要额外开放 **UDP/10086**。两种池可以使用不同 PSK，但每种池的 server 与 agent 配置必须匹配。`psk=@文件路径` 同样适用于 DTLS。

`-pool 20` 维持 20 条空闲 TCP/TLS 连接，`-udp-pool 20` 另外维持 20 个空闲 DTLS 会话。每个 UDP 业务会话独占一个 DTLS 会话，agent 使用独立 UDP socket 主动连接 server，不将多个业务会话复用到一条连接内。空闲 DTLS 会话通过保活维持连通性，断线重建，业务激活后自动补池；业务结束后关闭，不放回空闲池。保活不会延长业务的 `-udp-timeout`。

server 的 `-udp-transport` 固定选择 UDP 业务的隧道类型；未指定时，配置了 DTLS 池便使用 `udp`，否则使用 `tcp`。TCP 业务始终使用 TCP/TLS 池：

| 值 | 行为 |
|----|------|
| `udp` | 使用 DTLS 会话；需要配置 DTLS 池，等待可用会话超时或激活失败时结束该业务会话 |
| `tcp` | UDP 继续封装在 TCP/TLS 池连接中，与原有传输方式一致 |

两种方式之间**不自动回退或迁移**。DTLS 握手、就绪检查、激活失败或活动会话断线时，结束对应会话；agent 独立重连、补池，后续新业务仍使用配置的传输方式。不会将已发送的业务数据自动重放到另一条隧道。DTLS 池握手后的就绪检查与业务激活需要确认；已有 TCP/TLS 池仍不增加注册握手。

仅转发固定 UDP 端口时，也可以只使用 DTLS：

```sh
backpipe server -listen "udp://:500?to=charon:500" \
  -listen "udp://:4500?to=charon:4500" \
  -accept "dtls://:10086?psk=tunnel-key" -udp-transport udp

backpipe agent -connect "dtls://server_host:10086?psk=tunnel-key" -udp-pool 20 \
  -redirect "udp://charon:500=10.1.2.3:500" \
  -redirect "udp://charon:4500=10.1.2.3:4500"
```

SOCKS5/HTTP 或 TCP 入口要求配置流式池，确保 TCP 请求可以被处理。流式池可选 TCP/TLS 或下文的 KCP/DTLS。`-accept`、`-connect` 各允许最多一个流式地址和一个原生 DTLS 地址。agent 的 `-target` 模式不支持原生 DTLS；固定 UDP 目标应写在 server 的 `-listen ...?to=...` 中。

DTLS 使用 1.2 版本，通过 PSK 派生证书进行双向认证，使用具有前向安全性的 ECDHE 与 AEAD 加密。认证思路与现有 TLS 池一致，但 DTLS 是独立的 UDP 协议，不能拿 TLS 客户端连接 DTLS 端口。客户端 `socks5s://` 的协议保持不变。

`-udp-mtu` 默认 `1200`，范围 `576..8192`，表示 DTLS 隧道发送时的**外层 UDP 载荷预算**，包含 DTLS 和 backpipe 帧开销，不包含外层 IP/UDP 头。双方协商取配置中的较小值。它不是 strongSwan 的内层 MTU，也不是业务 UDP 包长上限。建议两端配置一致，并按 server-agent 路径 MTU 调整；例如已确认路径 MTU 为 1500 时，还需要为 IPv4/IPv6 和其他网络封装预留头部空间，不能直接设置为 1500。

业务包超出预算时，backpipe 在 **server-agent 的 DTLS 隧道内部**切片，另一端收齐后还原完整 UDP 数据报，再发给目标或客户端。重组有内存和超时限制；缺片则丢弃整包，不重传业务数据，也不保证业务数据报有序。DTLS 握手与会话控制的重试不改变这一点。配置过大的预算仍可能触发 IP 分片或路径丢包；配置过小则增加切片数和处理开销。

server 的状态日志中，`idle` 是空闲 TCP/TLS 连接数，`udp-idle` 是空闲 DTLS 会话数。UDP 代理和固定转发日志显示 `transport=dtls` 或 `transport=tcp`，可确认业务实际使用的隧道类型。

### KCP + DTLS 流式隧道（v1.5.0）

`kcp+dtls://` 使用 UDP 建立 DTLS 加密连接，在 DTLS 内运行 KCP，为 TCP/HTTP 和 UDP 业务提供可靠、有序的流式隧道。可以单独使用，替代 TCP/TLS 连接池：

```sh
backpipe server -listen socks5://:1080 \
  -listen "tcp://:8080?to=web:80" -listen "udp://:500?to=charon:500" \
  -accept "kcp+dtls://:10086?psk=tunnel-key"

backpipe agent -connect "kcp+dtls://server_host:10086?psk=tunnel-key" -pool 20 \
  -redirect "tcp://web:80=10.1.2.3:80" -redirect "udp://charon:500=10.1.2.3:500"
```

此时所有 server-agent 业务均走 KCP/DTLS，只需为池入口开放 **UDP/10086**。客户端入口及目标仍使用其各自的 TCP/UDP 协议。KCP 与 TCP/TLS **互斥**，不能在同一进程中同时指定两种流式池，也没有自动回退。`-pool` 控制空闲 KCP 会话数量；每条业务独占一个会话，激活后补池，结束后关闭。裸 TCP 入口、agent `-target`、`-ppv2` 和 `-redirect` 同样适用。

也可以保留独立的原生 UDP/DTLS 池，让 TCP/HTTP 走 KCP，UDP 业务继续使用不重传的数据报隧道：

```sh
backpipe server -listen socks5://:1080 \
  -accept "kcp+dtls://:10086?psk=tunnel-key" \
  -accept "dtls://:10087?psk=tunnel-key"

backpipe agent -connect "kcp+dtls://server_host:10086?psk=tunnel-key" \
  -connect "dtls://server_host:10087?psk=tunnel-key" -pool 20 -udp-pool 20
```

两种池都使用 UDP，必须配置**不同端口**，并分别开放防火墙。配置了原生 `dtls://` 时，UDP 业务默认选择原生 DTLS；server 添加 `-udp-transport stream` 可明确改为 KCP。旧的 `-udp-transport tcp` 是 `stream` 的兼容别名，表示当前流式池。KCP 承载 UDP 时会保留业务数据报边界，但 KCP 的重传会延迟同一会话中的后续数据报；需要保留 UDP 丢包语义时使用原生 DTLS。日志分别显示 `transport=kcp+dtls`、`transport=dtls`；`idle` 统计所选流式池，`udp-idle` 统计原生 DTLS 池。

连接管理与关闭行为：

- DTLS 双向认证后，双方交换带版本的 KCP 就绪帧，成功后才入池。KCP 数据、心跳和关闭确认均在 DTLS 加密层内；不是 TLS over KCP，也不能直接与 gonc 的 KCP 端口互连。
- TCP 半关闭使用 KCP 内有序传输的 FIN，接收方读完 FIN 前的数据后得到 EOF，反向仍可发送。完整关闭最多等待 5 秒确认已发送的数据和 FIN；超过期限强制回收，不能保证断网时仍送达剩余数据。
- `-kcp-heartbeat` 默认 `10s`，`-kcp-timeout` 默认 `30s`。空闲和活动会话都发送带序号的 ping/pong；连续超时未收到有效回复便关闭载体、解除读写阻塞并移除失效会话。心跳独立于业务读取，接收背压不会被误判成断线；心跳不延长 `-udp-timeout`。
- agent 在空闲连接断开后按退避和抖动重连；活动会话在激活时就已补池。server 重启或网络恢复后，agent 重新建立会话。已中断的业务不会迁移或重放，新业务使用新连接。NAT 地址变化同样需要重建。
- 接收缓存有上限，应用读取落后时由 KCP 流控产生背压。业务读写 deadline 可中断等待，部分接收帧在读超时后保留，避免超时破坏帧边界。

`-kcp-mtu` 默认 `1200`，范围 `576..1400`，表示包含 DTLS 和 KCP 包装开销的外层 UDP 载荷预算，不含 IP/UDP 头；KCP 会进一步预留自己的包头，启用 FEC 时也会预留纠错头及参数标记。双方建议使用一致配置，当前不协商 MTU。`-udp-mtu` 仅控制原生 DTLS 池。`-kcp-*` 参数只在配置了 KCP 池时有效；心跳范围为 `50ms..1h`，超时须至少为心跳的三倍且不超过 `24h`。

`-kcp-sndwnd` 和 `-kcp-rcvwnd` 分别设置本端的发送、接收窗口，单位为 KCP 分段，默认均为 `128`，范围 `128..4096`。例如在 server 和 agent 命令后均添加 `-kcp-sndwnd 1024 -kcp-rcvwnd 1024`。两端可以不同，每个方向受本端发送窗口、对端接收窗口及可选的拥塞控制限制。增大窗口不会启动时就分配全部载荷缓存；高并发、丢包或接收端积压时，内存占用可能增加。未指定参数时保持原来的窗口设置。

从 **v1.6.0** 起，`-kcp-nocwnd` 默认为 `true`，关闭 KCP 拥塞控制，与 gonc 的快速模式一致，避免高延迟、丢包环境下拥塞窗口过小而限制吞吐。快速重传仍启用，接收流控和背压仍有效。设置 `-kcp-nocwnd=false` 可恢复 v1.5.0 的拥塞控制行为。此参数只影响本端发送，两端可以不同；关闭拥塞控制可能增加重传和带宽争用。

`-kcp-fec` 默认 `off`。两端同时添加 `-kcp-fec 10:3` 可启用每 10 个数据分片附加 3 个纠错分片；也支持其他 `数据数:纠错数` 组合，每项范围 `1..32`。满组时，10:3 约增加 30% 分片流量及额外包头、计算开销；组内收到足够分片时可恢复丢失数据，超过纠错能力仍依靠 KCP 重传。低流量时不会为了凑齐 FEC 分组延迟数据发送。

FEC 必须两端配置相同，当前不自动协商或回退。启用 FEC 的数据包携带认证后的参数标记；配置不匹配会在就绪前报告 `KCP FEC mismatch`。启用 FEC 要求双方均为 v1.6.0 或更新版本；旧版不认识 FEC 包，会拒绝会话。FEC 关闭时保留 v1.5.0 的 KCP 包格式，新旧两端可以互通。启动日志显示 `nocwnd` 和 `fec` 实际设置。

所有 TCP 转发路径共用收尾逻辑：正常 EOF 发送半关闭，并给反向数据最多 30 秒排空；复制或半关闭出错则关闭两端。排空超时会中断读写并关闭连接，也覆盖阻塞的写入和半关闭操作，结束前等待转发协程退出。

基础 KCP 模式要求 server、agent 均为 v1.5.0 或更新版本，FEC 模式要求双方均为 v1.6.0 或更新版本。未使用 `kcp+dtls://` 时，TCP/TLS 与原生 DTLS 的线格式、认证、补池路径和默认传输选择保持不变；旧流式池不会增加 KCP 就绪帧、FIN 或心跳。

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

以上握手方向示例针对 TCP 目标。代理 UDP 时，server-agent 之间可以使用 agent 主动建立的 TCP/TLS 池连接，也可以使用独立 DTLS 会话池；agent 到 target 发送 UDP 数据报。DTLS 的握手通过 UDP 完成，没有 TCP SYN。

每个会话独占一条连接，不使用 mux 多路复用。TCP 建立成功后（启用 TLS 时则在认证成功后），连接直接进入空闲池，不额外发送 backpipe 注册消息或应用层 ACK。首个业务请求激活连接后，agent 立即建立新连接补充空闲池。DTLS 池另外执行就绪和激活确认，确保首个业务数据报在双方准备好之后发送。

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

每个 SOCKS5 入口可以独立配置监听地址、用户名、密码和 PSK，不同入口的凭据互不通用。也可以同时添加 `tcp://地址?to=目标` 和 `udp://地址?to=目标` 固定转发入口，详见后文。所有入口共享配置的连接池，`-pool 20` 表示总共维持 20 条空闲 TCP/TLS 连接；配置 DTLS 时，再由 `-udp-pool` 独立控制 UDP 会话池。关闭某个入口上的会话，不影响其他入口的会话。

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

UDP 默认空闲 `2m` 后释放会话，双向流量都会延长存活时间；可在 server 和 agent 两端设置 `-udp-timeout 5m`。超时或隧道断开后，下一包重新取用池连接，agent 的 UDP 源端口可能变化。使用 TCP/TLS 池时，TCP 重传可能延迟同一会话的后续数据报；使用 DTLS 池时，业务数据不重传，丢包由上层应用处理。

每个固定 UDP 入口最多维持 1024 个会话，其中等待 agent 就绪的会话最多 128 个。从 v1.4.1 起，每个会话的待发送队列同时受 **256 个数据报、256 KiB 载荷**两项上限限制；同一入口所有会话的等待载荷合计最多 **8 MiB**。若接收新包会超过任一上限，则丢弃该包。这些预算只统计应用等待队列，不包括已经出队、正在构帧或发送的数据，以及内核 socket 缓冲。等待 agent 超时或会话结束时，未转发的排队数据也会丢弃。

固定转发入口 `tcp://`、`udp://` 本身不提供 TLS+PSK 或代理用户名认证；`-accept/-connect tls://...` 或 `dtls://...` 加密的是 server 与 agent 之间的连接。客户端到 server 的加密取决于应用协议自身。固定 UDP 入口只需开放配置的 UDP 监听端口，例如 UDP/500；连接池另按配置开放 TCP/10086、UDP/10086，不使用 SOCKS5 动态分配的 UDP 端口。

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
- 客户端 UDP 包按 `-udp-transport` 选择 TCP/TLS 或 DTLS 池，再由 agent 以 UDP 发往目标。TCP 重传可能延迟同一会话中的后续数据报；DTLS 业务包不重传、不保证有序。
- SOCKS TCP 控制连接必须保持打开。控制连接关闭、隧道断开或空闲超时，都会结束 UDP 会话并关闭相关 socket。
- 默认空闲超时为 `2m`。修改时可在两端都设置 `-udp-timeout 5m`；两端不一致时，较短的超时会先触发。
- 防火墙和安全组需要允许访问动态分配的 UDP 端口，仅开放 UDP/1080 不够。SOCKS5 UDP 代理目前不支持固定或共享 UDP 端口，也不支持配置分配端口范围；固定目标转发可使用 `-listen "udp://:端口?to=目标:端口"`。
- server 位于 NAT 后时，支持 `0.0.0.0` 回退的客户端会使用所连接的代理 IP。需要明确指定回复地址时，可设置 `-socks-server-ip 公网IP`。NAT 仍需将分配的 UDP 端口按同号映射到 server，此参数不会自动创建映射。
- UDP 来源 IP 必须与 TCP 控制连接的对端 IP 一致；首个有效数据包确定实际来源端口。不会拿 UDP ASSOCIATE 请求里的地址和端口过滤数据，兼容 gonc 及 NAT 后的客户端。不支持客户端发送的分片 SOCKS5 UDP 数据报；DTLS 隧道内部切片不改变 SOCKS5 协议。

server 的 SOCKS5 UDP socket、固定 UDP 监听 socket，以及 agent 的业务 UDP 出口 socket，都会向操作系统请求 **1 MiB 接收缓冲**。操作系统可能按自身限制调整实际大小；设置失败会记录日志，但不终止服务。这些内核缓冲与固定 UDP 入口的应用等待队列分别计量。

agent 的回包处理仍是读取一个业务 UDP 包、写入隧道，再读取下一个包。扩大接收缓冲用于吸收短时突发；持续拥塞仍可能造成写入阻塞和接收丢包。

排查时可关注这些日志：

| 日志 | 含义 |
|------|------|
| `[server] UDP association: ... via ...` | server 和 agent 已准备好 UDP 会话；`via` 显示实际监听地址，不是回复给客户端的地址 |
| `[server] UDP client bound: ...` | server 收到并接受了首个有效客户端 UDP 包 |
| `[agent] UDP forwarding: ... -> ...` | agent 首次成功将 UDP 包交给本机 socket 发往目标，不代表目标已收到或回复 |
| `[server] UDP association ended: ... (sent=N received=M packets)` | 会话结束；`sent` 为成功写入 agent 隧道的包数，`received` 为从隧道返回并成功写入客户端 UDP socket 的包数 |
| `[server] UDP forward stats: ...` | 固定 UDP 入口的会话数、排队量和本地丢弃/写失败汇总；每 10 秒检查，有变化才输出，入口清理结束时输出最终汇总 |
| `[server] UDP forward ended: ...` | 固定 UDP 会话结束时输出 `sent`、`received`、`dropped`、`queue_peak_packets`、`queue_peak_bytes`；未成功激活的会话也会记录 |

固定 UDP 转发统计同时适用于 TCP/TLS 和 DTLS 隧道。入口快照中的 `sessions`、`pending` 分别是当前会话数和等待 agent 就绪的会话数；`queued_packets`、`queued_bytes` 是当前等待队列的包数和载荷字节数，`peak_packets`、`peak_bytes` 是该入口启动以来的峰值。会话结束日志中的 `queue_peak_packets`、`queue_peak_bytes` 只统计该会话的队列峰值。

`dropped` 是下列分类计数之和，每个包按首个命中的原因计一次。入口计数在运行期间累计，会话结束日志则显示该会话的计数：

| 分类 | 含义 |
|------|------|
| `queue_packets` | 新包会使单会话等待包数超过 256 |
| `session_bytes` | 新包会使单会话等待载荷超过 256 KiB |
| `listener_bytes` | 新包会使该入口总等待载荷超过 8 MiB |
| `pending_limit` | 等待 agent 就绪的会话数已达上限，无法创建新会话 |
| `session_limit` | 该入口的会话数已达上限，无法创建新会话 |
| `oversize` | 数据报超过当前转发格式允许的大小 |
| `closing` | 收到包时，入口或会话已经结束 |
| `abandoned` | 会话结束时仍未发送的排队包 |
| `write_error` | 向 agent 隧道或客户端 UDP socket 写入失败 |

这些指标只反映 backpipe **主动丢弃的数据和本地写失败**，不能表示内核接收缓冲或网络链路的总丢包。`write_error` 发生前可能已经发送部分数据，例如 DTLS 包的部分切片，因此也不等于确定未送达的完整数据报数。排查接收缓冲溢出或链路丢包时，还应结合操作系统 UDP 计数和抓包结果。

## 参数说明

使用 `backpipe server -help` 或 `backpipe agent -help` 查看对应角色的帮助。

| 参数 | 角色 | 默认值与用途 |
|------|------|--------------|
| `-listen` | server | 必填，可重复；代理入口 `socks5://`、`socks5s://`；固定转发 `tcp://地址?to=目标`、`udp://地址?to=目标`；裸 `tcp://` 配合 agent `-target` |
| `-accept` | server | 必填，可重复；一个流式池（裸地址/`tcp://`/`tls://`/`kcp+dtls://` 四选一）和可选的原生 `dtls://` 池 |
| `-connect` | agent | 必填，可重复；一个流式池（裸地址/`tcp://`/`tls://`/`kcp+dtls://` 四选一）和可选的原生 `dtls://` 池 |
| `-target` | agent | 省略时处理代理和带 `to` 的 TCP/UDP 转发；指定时仅配合不带 `to` 的 TCP 入口 |
| `-pool` | agent | `5`；要维持的空闲 TCP/TLS 或 KCP/DTLS 流式连接数 |
| `-udp-pool` | agent | `20`；要维持的空闲 DTLS 会话数，显式指定时要求配置 DTLS 池 |
| `-udp-transport` | server | `stream`（旧别名 `tcp`）或 `udp`；未指定时有原生 DTLS 池则为 `udp`，否则使用流式池；无自动回退 |
| `-udp-mtu` | 两端 | `1200`；DTLS 外层 UDP 载荷预算，范围 `576..8192`，显式指定时要求配置 DTLS 池 |
| `-kcp-mtu` | 两端 | `1200`；KCP/DTLS 外层 UDP 载荷预算，范围 `576..1400`；要求 KCP 池 |
| `-kcp-sndwnd` | 两端 | `128`；本端 KCP 发送窗口，范围 `128..4096` 分段；要求 KCP 池 |
| `-kcp-rcvwnd` | 两端 | `128`；本端 KCP 接收窗口，范围 `128..4096` 分段；要求 KCP 池 |
| `-kcp-nocwnd` | 两端 | `true`；默认关闭 KCP 拥塞控制，`-kcp-nocwnd=false` 开启；只影响本端发送；要求 KCP 池 |
| `-kcp-fec` | 两端 | `off`；可设 `10:3` 等 `数据数:纠错数`（每项 `1..32`）；两端必须一致；要求 KCP 池 |
| `-kcp-heartbeat` | 两端 | `10s`；KCP/DTLS 心跳间隔；要求 KCP 池 |
| `-kcp-timeout` | 两端 | `30s`；KCP/DTLS 有效心跳回复超时，至少为心跳的三倍；要求 KCP 池 |
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

KCP 测试另外覆盖丢包、乱序、重复包、尾部数据与半关闭、关闭确认丢失、单向链路失效、背压与动态 deadline、协议错误、真实 DTLS 认证、agent 中断、server 重启补池、KCP 单独运行及与原生 DTLS 共存。可用 `go test -race . -run TestKCP` 执行 KCP 并发检查。

v1.6.0 的测试还覆盖拥塞控制开关的实际发送行为、FEC 恢复计数、数据/纠错包 MTU 上限、FEC 参数不匹配拒绝，以及启用 FEC 的真实进程转发和补池。设置环境变量 `BACKPIPE_LEGACY_KCP_BINARY` 为单独编译的 v1.5.0 可执行文件路径后，运行 `go test -race . -run TestLegacyKCPBinaryCompatibility` 可检查不启用 FEC 时两个升级顺序下的 TCP 半关闭及 UDP 互通。

升级兼容性测试可指定独立构建的 v1.4.2 程序：`BACKPIPE_LEGACY_BINARY=/absolute/path/to/backpipe-v1.4.2 go test . -run TestLegacyBinaryCompatibility`。测试覆盖新旧 server/agent 的两种搭配，以及 TCP、TLS、TLS 加原生 DTLS、仅原生 DTLS 四种配置；未指定旧程序时跳过此项。

TCP 转发由 backpipe 管理读写与收尾，保留与 gonc 兼容的 `tcp://目标地址` 请求及 `OK/ERROR` 响应格式。TCP/TLS 池中的 UDP 帧格式与 gonc 兼容，DTLS 池使用 backpipe 自身的数据报帧、控制消息和切片重组协议。会话清理由 backpipe 自行管理，以避开所固定依赖版本中的等待组和共享地址问题。启用 DTLS 时，server 与 agent 都需要升级到 v1.4.0 或更新版本；未启用 DTLS 的配置沿用已有传输方式。

## 许可证

MIT
