# 当前兼容性与验收

目标为 rootful 越狱 iOS 6 / ARMv7。已连接的验收设备是 iPod touch 4、iOS 6.1.6、256 MB。源码集成、独立对端互通与设备运行分别记录，正式验收尚未全部通过。

| 范围 | 当前实现与边界 |
|---|---|
| UIKit 与 IPC | 四标签、配置/节点/Provider/DNS/诊断页面已编译；真实界面操作与完整布局验收仍待完成 |
| 本机入口 | IPv4 回环 SOCKS5 CONNECT、HTTP CONNECT；TCP 背压、半关闭、现有连接热更新保留。不开放 LAN 监听或 SOCKS UDP ASSOCIATE |
| 系统接管 | utun 的 TCP/UDP/IPv4/IPv6/DNS 真机转发通过；接管公网默认路由，loopback、LAN、link-local 和更具体系统路由绕过 |
| 恢复与保护 | Core/Supervisor SIGKILL、独立 Guardian、恢复优先/严格阻断、缓存 Fake-IP 重启与受控网关变化有真机证据；真实 Wi-Fi 链路断开/恢复正在补验 |
| 出站协议 | HTTP(S)、SOCKS、SS AEAD/2022、VMess/VLESS/Trojan、Hy2、TUIC、AnyTLS、SSH、WG/AWG 的主机独立互通及 ARM 构建记录见 PROTOCOLS.md；各现代组合真机互通仍逐项进行，Snell/SSR 与剩余传输仍在开发 |
| 策略与规则 | select/url-test/fallback/load-balance、嵌套组、relay/dialer-proxy 链、顺序域名/IP/逻辑/规则集/Geo/进程规则。自动算法与真实 HEAD 测速通过主机整合验收 |
| Provider 与 Geo | HTTPS/私有本地/内联来源，过滤与名称覆盖，原子更新、失败缓存、更新间隔、MRS/zstd、GeoIP/GeoSite protobuf、Country/ASN MMDB；核心代次切换与磁盘故障回滚通过主机测试，设备整合正在验证 |
| 配置导入 | YAML、HTTPS、支持的 URI/Base64、本地文件、照片二维码。Hy2 支持默认 443、认证、SNI 与 Salamander，TLS 验证默认开启。已修正标准 h3 ALPN 和 ./ruleset 路径兼容处理 |
| DNS | UDP/TCP、DoT/DoH/DoQ、Hosts/缓存/策略/fallback、明确指定的代理出口。DoQ 多地址短期限回退通过独立测试；当前 DoQ 只支持 DIRECT 物理 UDP 出口，命名代理 DoQ 明确拒绝 |
| Fake-IP | 双栈映射、ACK 后应答、私有持久化、连接固定、退役地址 300 秒冷却、满池 SERVFAIL，旧 v1 兼容。独立目标 ABI 测试及崩溃后缓存地址转发通过 |
| 安装与后台 | 旧内部包已安装配置，Supervisor 可运行；最新功能使用独立设备目录测试。完整新包升级、launchd 重启、退出 UI 与卸载清理仍待完成 |

细节与证据见 [接管与恢复](CAPTURE.md)、[协议](PROTOCOLS.md)、[策略/Provider/Geo](POLICIES-PROVIDERS.md) 和 [验收](ACCEPTANCE.md)。未支持的字段在配置检查时明确阻断。
