# 原生协议与组合

`MLStream`、`MLDatagram` 与配置校验使用同一份选项映射。下面记录已接入源码并通过独立主机对端测试的组合；ARMv7 编译、完整链接和签名另行检查。编译与主机测试不能代替 iOS 6 真机协议验收，设备结果由主任务的串行验收日志记录。

| 出站 | TCP 组合 | UDP 组合 |
| --- | --- | --- |
| DIRECT / REJECT | 直连 / 明确拒绝 | 直连 / 明确拒绝 |
| HTTP / HTTPS CONNECT | Basic 认证；可选严格验证 TLS | CONNECT 未定义 UDP |
| SOCKS5 | 用户名密码；可选严格验证 TLS | UDP ASSOCIATE；数字 IPv4/IPv6；1–1500 字节。FRAG 非零明确拒绝 |
| VLESS | TCP、TLS、WS、Reality、Vision、gRPC、XHTTP；encryption=none | 普通长度帧、Vision XUDP；数字 IPv4/IPv6；1–1500 字节 |
| VMess AEAD | TCP、TLS、WS、gRPC、XHTTP；alterId=0；AES128-GCM / ChaCha20 | 数字 IPv4/IPv6；1–1500 字节 |
| Trojan | 严格验证 TLS、WS、gRPC、XHTTP | 数字 IPv4/IPv6；1–1500 字节 |
| Shadowsocks AEAD | AES128-GCM / AES256-GCM / ChaCha20-IETF-Poly1305 | 数字 IPv4/IPv6；1–1500 字节 |
| Shadowsocks 2022 | BLAKE3 AES128 / AES256 / ChaCha20；接收最多 65535 字节 chunk | 会话 ID、时间戳、关联校验、8192 包重放窗口；1–1500 字节 |
| Hysteria2 | 严格验证 QUIC、认证、Salamander、显式证书 SHA256 pin | QUIC DATAGRAM 与分片；IPv4 / IPv6 / 域名 |
| TUIC v5 | 严格验证 QUIC、UUID/password TLS exporter 认证；Reno / Cubic / BBR | native DATAGRAM 或可靠单向 stream；分片；IPv4 / IPv6 / 域名；1–1500 字节 |
| AnyTLS | 严格验证 TLS；v2 Settings / SYN / PSH / SYNACK / FIN；padding；空闲 session 复用和过期 | UOTv2 connected UDP；数字 IPv4/IPv6；1–1500 字节 |
| SSH | 强制 host-key；密码或字面量 PEM；加密 PEM passphrase；direct-tcpip | SSH direct-tcpip 为 TCP 传输 |
| WireGuard / AmneziaWG | 完整 Noise 握手和 TCP over IP；独立 lwIP；IPv4 / IPv6；多 Peer 最长前缀选择；续钥 | 真正 UDP over IP、IPv4/IPv6 分片；严格数据认证与重放窗口；1–1500 字节 |

Snell 和 SSR 仍在实现阶段，不能因配置类型已列出而视为启用。

## 选项和组合边界

- Reality 要求 SNI、public-key 和 short-id；Vision 不能与 WS/gRPC/XHTTP 叠加。Reality、Vision、Hysteria2、TUIC、AnyTLS、WireGuard 和 AmneziaWG 只能处于 TCP chain 的第一个物理出站。普通 HTTP、SOCKS5、VLESS、VMess、Trojan、SS、SSH 可按顺序构成 TCP chain。
- 单节点 API 不自行解析 dialer-proxy。由 Core 构造 ordered chain，再调用 MLStreamOpenChain；单节点 API 对未解析 dialer 明确拒绝。
- TLS 校验证书链和 hostname；不会接受 skip-cert-verify=true。SSH 要求非空 host-key 数组，接受明确 SHA256 指纹或公钥 blob。private-key 是字面量 PEM；不从订阅指定路径读取私钥。
- SS2022 接受规范 base64 的单 PSK；扩展 identity-key chain 尚未实现，明确拒绝。AnyTLS FIN 关闭整条 stream，不提供 TCP 半关闭。
- TUIC 支持 alpn、congestion-controller、udp-relay-mode、heartbeat-interval（毫秒）、disable-sni、max-udp-relay-packet-size。disable-sni 仍验证 hostname。0-RTT 未启用，reduce-rtt=true 明确拒绝。
- WireGuard 接受 ip 或 ipv6 至少一个、private-key、单 Peer 或 peers 内的 endpoint/公钥/preshared-key/allowed-ips/reserved。纯 peers 可省略 top-level server/port/public-key。支持 dns 和 remote-dns-resolve；远端 DNS 通过选中的隧道查询。IPv6 MTU 至少为 1280。
- AWG 使用锁定的原生 handshake/tunnel 实现，支持 Jc/Jmin/Jmax、S1–S4、H1–H4、I1–I5、J1–J3、Itime、header protection、content padding、random trailers、cookie 选项及定时续钥参数；未知配置明确拒绝。主机已对独立 Noise responder 验证自定义 H/S、junk、续钥及 header protection；其他扩展仍需对应真实对端验收。

## 共享传输状态

| 组件 | 已验证范围 | 尚待完成 |
| --- | --- | --- |
| TCP / UDP | 统一非阻塞 stream/datagram API；有界缓冲和关闭语义 | 各协议真机对端验收 |
| TLS 1.3 / WebSocket | OpenSSL 严格证书校验、hostname 和 WS framing | 通用客户端 TLS Profile |
| HTTP/2 | gRPC 与 XHTTP 的真正 HTTP/2、HPACK、流控；独立 Xray 对端 | 独立 h2-opts 传输 |
| HTTP/3 / QUIC | Hysteria2 HTTP/3 认证；TUIC QUIC；RFC9250 DoQ | 通用 HTTP/3 代理传输 |
| HTTPUpgrade | 尚未接入 | 升级协商及原始字节传输 |
| Mux / smux | QUIC stream 复用、AnyTLS session framing 和空闲复用各自已验证 | 不能将这些等同于通用 Mux/smux；通用适配尚未实现 |
| 客户端 TLS Profile | Reality 的原生 ClientHello / 握手已与 Xray 验证 | 普通 TLS 的完整 Profile；不能从协议连通推断精确浏览器指纹 |

## DoQ 与物理路径

MLDNSDoQQuery 提供 RFC9250 DoQ：ALPN doq、严格 TLS、两字节 DNS 长度、查询 ID 归零、每查询独立 bidi stream 和双向 FIN；没有 0-RTT。错误 ID、长度、截断、多余消息、缺 FIN、CA、hostname 和 ALPN 均在独立 aioquic 测试中拒绝。DNS owner 恢复原查询 ID。

所有物理 socket 由 MLNetworkBinding 绑定捕获前的出口；服务器 hostname 使用 bootstrap resolver，避免递归进入接管。QUIC 调度器在创建连接后立即发 Initial，再等待回复，并均分总预算尝试全部地址。原 1200ms 测试覆盖坏 IPv6 + 可达 IPv4，以及两个不可达地址 + 第三个可达地址；没有通过延长 deadline 绕过回退错误。

## 构建、证据与许可证

运行 python3 scripts/build-stream.py host 或 ios。iOS 构建使用 ARMv7、iOS 6.0、现有合法 iPhoneOS 7.1 SDK 与 ld-classic。host 使用 MLSTREAM_OPENSSL_PREFIX（默认 /opt/local/libexec/openssl3）。

用 TLS 1.3 Python 运行 tests/protocols.py；MLSTREAM_TEST_PYTHON 可指定该运行时。独立对端包含锁定的 Hysteria、Xray、AnyTLS、TUIC、系统 OpenSSH、aioquic 和独立 Python Noise/IPv4/IPv6 responder。测试覆盖正常传输、认证/证书失败、FIN、大小边界、分片、重放、padding/session 复用和多层连接。测试对端不会打包进客户端。

最新冻结候选是 .build/stream/ios/libmlstream-wg-doq-verified.a，SHA256 c61c398afd996159015595aad8eaaa989f4241fd8274c550611a41483168f069；完整 ARMv7 smoke 已链接和签名。全主机回归证据为 .build/stream/protocol-tests-wg-final.log。后续协议或别名更新会生成新的冻结候选，设备使用哪一版应随验收日志记录。

源码锁位于 third_party/manifest-senko.json、manifest-ssh.json 和测试专用 manifest-protocol-tests.json / manifest-doq-tests.json。锁定依赖包括 Senko、OpenSSL、ngtcp2、nghttp3、sfparse、libssh2；lwIP 与 PQClean notices 保留。原锁定源码不原地修改；本地生成适配明确修正 QUIC Initial/fallback 和 XHTTP 流控，并增加应用协议 framing。WG 的 lwIP 与 AWG 全部全局符号加私有前缀，与设备 capture 的 lwIP 分离。

组合客户端选择 GPLv3；OpenSSL 保留 Apache-2.0，libssh2 和 lwIP 保留 BSD notices。协议源码和许可证必须随源码交付保留。现代 Go 核心因 Go 1.15 移除 darwin/arm，不能直接作为 iOS 6 ARMv7 客户端；本实现使用原生 C/Objective-C，并在主机运行独立现代服务器来验收。
