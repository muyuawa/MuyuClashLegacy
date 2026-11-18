# 流量接管与恢复

当前接管后端是 rootful iOS 6 的 `utun`，覆盖进入公网默认路由的 IPv4/IPv6 TCP、UDP 与 DNS。状态明确标为 `scope: public-default-routes`；loopback、LAN、link-local 和更具体的系统路由保留原有路径。严格阻断也仅适用于这一范围，不能据此声称局域网或所有系统路由均已阻断。PF 与 Socket Hook 没有自动启用，完整通路失败时不会静默切成 TCP-only。

## 网络事务

`MLCaptureCoordinator` 由 root Supervisor 持有。准备阶段先检查现有物理默认路由和虚拟地址冲突，创建并配置 utun，然后把接口名称、索引、随机 nonce、物理出口及恢复记录保存到 root 独占的 0700 目录。每个路由变更之前，记录均已写入、fsync、原子替换并同步目录。

Core 借用 utun FD 3，在降为 mobile 后处理数据包；Core 的 FD 4 是独立的生存管道写端。所有对外 Socket 必须绑定记录中的物理接口，以免代理和 DNS 的连接再次进入 utun。Core 确认 TCP、UDP、IPv6 和 DNS 处理器都已启动后，Coordinator 才添加四条 utun 接口路由：`0.0.0.0/1`、`128.0.0.0/1`、`::/1`、`8000::/1`。

安装公网 split 路由前，按物理网关补齐 IPv4/IPv6 的接口限定默认路由。iOS 6 在只有全局物理默认路由时，绑定物理接口的 Socket 可能选择 loopback 源地址并返回 EADDRNOTAVAIL，或在显式绑定地址后返回 EHOSTUNREACH。接口限定默认路由使节点出站使用真实物理地址，不改变未绑定 Socket 的公网接管路径。

已有同范围路由不会被覆盖。已有匹配的物理接口默认路由只复用，不登记为本项目所有。格式 2 的恢复记录最多保存四条 split 路由和两条接口限定物理默认路由，仍兼容格式 1。恢复会核对目标、前缀、接口名称、接口索引、作用域和网关；utun 已消失时，仍清理本项目创建且身份匹配的物理出口。物理路径更新前先清理过期出口，再写入新路径，保留严格模式的 split 阻断。接口被复用或路由被别人替换时，不删除别人的设置。

DNS 只发布 configd 的临时服务 `State:/Network/Service/com.muyu.clashlegacy.capture/DNS`，虚拟 DNS 地址为 `198.18.0.53`。`SupplementalMatchDomains: [""]` 与 `SupplementalMatchOrders: [0]` 让系统域名解析选择这份独立 resolver，不发布 IPv4 Router、DestAddresses 或 OverridePrimary。iOS 6 configd 会根据 IPv4 service 自动生成默认路由，因此不能通过 IPv4 service 争取 DNS 优先级。精确物理 `/0` 的检查只选择 unscoped 记录；真实的全局 `/0` 被改成 utun 时仍会报告变化。

每个 DNS 记录带有本次 nonce，清理只移除 nonce 相同的记录，也保留对旧版本 `/IPv4` entity 的清理。utun 的 `.1` 与 `.2` 是接口/NAT 控制地址，不能分配为 Fake-IP。Core 的 Fake-IP 分配还排除了 `.53`。临时 configd 会话退出后，其服务记录由系统自动撤回。系统 DNS 验收必须使用普通应用 `getaddrinfo` 确认返回 Fake-IP；直接向虚拟 DNS 地址发送查询只能验证监听器。

## 独立守护与重启

`muyu-capture-guardian` 在安装 redirect 路由前启动。它持有 utun 和恢复锁的独立副本，通过一个通道监视 Supervisor，通过 Core 的生存管道识别 Core 是否真正退出。它在 Core 仍存活时不会读取 utun。

网络恢复优先模式下，Supervisor 意外退出后 Guardian 独立恢复路由和 DNS。严格模式下，它保留 utun 和已安装的路由；Core 退出后开始排空数据包，并重新发布带本项目 nonce 的临时 DNS 服务。Guardian 保留事务锁，避免自动启动的 Supervisor 先恢复直连。

新 Supervisor 可以通过 root 独占的 `guardian.sock` 接回孤立 Guardian。Guardian 等到旧 Core 的生存管道 EOF，才通过 SCM_RIGHTS 交回 utun 和锁副本；接回同一个接口后，先准备新 Core，确认通路就绪，复核现有 owned 路由，再恢复转发。Guardian 不向仍运行的 Supervisor 开放替换，也不在接回时删除 redirect 路由。

同一 Supervisor 内的 Core 崩溃采用 `BLOCKING → PREPARED → ACTIVE`。`prepare` 刷新物理出口、地址与原始 DNS；`prepareCoreLifetime` 更新生存管道；已有路由在激活时核验，不能重复添加。Supervisor 在每秒 tick 中调用 `checkPhysicalPathChanged:error:`。该方法只读取精确物理 `/0` 路由、接口地址和物理 configd 服务 DNS，不执行 DNS 查询，不依赖接管 DNS，不修改系统设置。

`status.lastPathCheck` 保留最近一次检查的时间、原始与观察签名、发生变化的字段以及读取错误；即使随后执行恢复，也不会清掉这份诊断。`status.physicalSignature` 是本次准备阶段的基线。它逐一记录 IPv4 和链路本地 IPv6 地址，按接口归并其余 IPv6 地址的网络前缀。同一前缀内的隐私地址轮换不会重启 Core。网关、DNS、接口与 IPv6 前缀变化仍会触发恢复。

Core 每次 spawn 成功或失败后，Supervisor 都须调用 `coreDidStart`，关闭自己持有的管道写端。每次重启 Core 之前，应先确保上一进程已退出，再准备新的生存管道。正常关闭只有在恢复记录已删除后才 disarm Guardian。

## 独立紧急恢复

```sh
/usr/libexec/muyuclash/muyu-network-recover
/usr/libexec/muyuclash/muyu-network-recover --emergency
```

普通恢复遵守事务锁。紧急选项可请求孤立 Guardian 恢复后释放接口和锁；其 Supervisor 仍运行时会拒绝。卸载流程应先停止 Supervisor 和 Core，再执行恢复。恢复程序验证 root 状态目录、锁、journal 和通道权限，拒绝 symlink、异常大小、四条固定 split 路由与已记录物理路径之外的 journal。

## 数据包处理

TCP 使用固定版本 Senko/lwIP 的协议栈与本项目 flow owner，支持 IPv4/IPv6、背压、双向半关闭、超时、代理链、取消和真实流量计数。route、节点配置和 Fake-IP 关联在连接存活期间保留，配置切换不改变已有连接。

UDP 使用独立的有界 Session Manager。IPv4/IPv6 UDP 都支持分片重组与响应分片，最大 payload 为 65507 字节；最多同时重组 8 个数据报，分片 15 秒过期，重叠分片被拒绝。输出队列最多 128 个 MTU 数据包，超过 2 秒的待发包被丢弃。UDP 会话最多 64 个，每会话最多 4 个待发数据报和 65507 字节；空 UDP 数据报也可处理。TCP 最多 24 条，最多 3 个并发建连/DNS worker。

DNS 经同一个 raw-wire 回调处理 UDP 和长度分帧的 TCP，当前查询/答复上限为 4096 字节。较大 UDP 答复可以通过 IP 分片送回；上游 TC 答复的 TCP 重试由 DNS 模块处理。UDP 代理协议和代理链不支持的组合由 datagram factory 显式拒绝，不会默认为 DIRECT。

## Fake-IP 崩溃恢复

`MLFakeIP` 的 pool 上限为 512 条活动映射和 512 对退役地址，JSON 快照不超过 256 KiB。快照保留版本 1、规范化 IPv4/IPv6 range、下一个分配 slot 和按 LRU 排序的 host/address 映射，新增可选 `retired: [{v4, v6?}]`，兼容没有该字段的旧 v1 文件。不保存进程内 pins、壁钟或冷却 deadline。`restoreSnapshot:error:` 在替换整份映射前验证版本、range、两种记录的数量、主机名、活动与退役地址共同唯一性、双栈 slot 对应关系和保留端点；失败不改变现有 pool，恢复后的 pins 从零开始。

被驱逐的地址对从驱逐时刻起按 `mach_absolute_time` 冷却完整 300 秒，覆盖刚刚再次服务的旧 DNS 答复；退役地址不再做 host 反查，也不能分给其他域名。分配先寻找既不活动也未处于冷却的独立空 slot，禁止借用此次 victim 的地址。小地址池没有空 slot、全部映射被 pin、退役记录满时均返回 SERVFAIL，保留当前映射与分配游标。所有持久化退役地址在 Core/设备重启后保守重新冷却 300 秒，避免使用跨启动 deadline 或壁钟变化而提前重用。

Core 必须在开始 DNS 服务前设置 `persistenceHandler`。每次新增映射或逐出旧映射后，handler 将活动与退役记录的完整快照交给 root Supervisor，等待持久化 ACK；ACK 到达后才向 DNS 返回 Fake-IP。到期退役清理与新分配是同一事务，失败或 handler 异常会恢复旧映射、分配游标及整份退役记录，DNS 返回 SERVFAIL。已有映射的 DNS 命中不需要重复写入。快照恢复本身不触发 handler；Supervisor 应在 spawn 新 Core 前提供已保存的快照。磁盘原子写入、权限和目录同步由 Supervisor 承担。

## 经内核确认的进程归属

`MLProcessOwner` 运行于 root Supervisor，通过 iOS 6 的 `__proc_info` 枚举 PID、Socket FD 和 XNU 2050 的 Socket 信息。TCP 使用完整 IPv4/IPv6 四元组；UDP 对同一个本地端点检查所有 Socket，共享本地端点的不同 Socket 即使连接到不同目标也标为歧义。重复 FD 指向同一 PID/Socket 可以接受，不能用应用提交的进程字段冒充内核结果。

读取进程路径后会重新核对 Socket handle、generation 和四元组。枚举有 1024 PID、65536 FD 字节、4096 Socket 行和最多 150 ms 的预算；权限、ABI、截断、超时、Socket 复用或歧义返回 `verified:false`。TCP 缓存最多 250 ms，缓存命中会重新验证 FD，缓存未命中立即重新枚举；UDP 每次重新枚举。只有 `verified:true` 的名称和路径可参与 PROCESS-NAME/PATH 规则。

## 验证

```sh
python3 tests/capture/run.py
python3 scripts/build-capture.py ios
.build/host/test-fake-ip
python3 tests/fake_ip_dns.py
```

主机测试直接驱动真实 packet bridge，连接独立 TCP、UDP 和 DNS peer；覆盖 IPv4/IPv6 TCP 半关闭、UDP、乱序 5000 字节分片往返、TCP/UDP DNS、异常帧、真实计数与 Fake-IP retain/release 平衡。分片单元测试覆盖 65507 字节、乱序、重叠和过期。事务测试覆盖持久化顺序、部分安装回滚、路由替换、接口索引复用、DNS 清理失败和恶意 journal。进程测试覆盖 Supervisor SIGKILL、恢复优先、严格保留、Core 生存管道、紧急恢复、Supervisor 接回及同进程 Core 重启。

`tests/fake_ip.m` 覆盖 DNS 返回前等待 ACK、写入失败完整回滚、SIGKILL 发生在保存快照后返回前的恢复、双栈/pins 清零、满池逐出和恶意快照。退役冷却测试覆盖 `/28` 满池与 slot wrap、最近再次服务旧映射后的完整 TTL、向后测试时钟、到期清理与 ACK 失败共同回滚、真实 fork/SIGKILL 后重新冷却 300 秒，以及最大 253 字节主机名下的 512 活动 + 512 退役记录与 256 KiB 上限。`tests/fake_ip_dns.py` 使用真实 MLDNS wire 答复核对 TTL 为 300 秒，验证资源满或持久化失败返回 SERVFAIL，旧地址在冷却前不重用。该补强已通过主机测试与 ARMv7 模块编译；独立签名的 `muyu-fake-ip-retired-test` 在目标 iPod touch 4 / iOS 6.1.6 上执行上述完整 Fake-IP 测试并输出 PASS，记录为 `.build/ios/device-fake-ip-retired.log`。最新 Fake-IP 源码和冻结协议库构建后的 Core/Supervisor 10 项真机复验也已全部通过，最终路由、DNS、Guardian 与 journal 清理再次确认。其余 PROCESS/路径变化 12 项保留此前通过记录，未在此次补强后重复执行。`tests/capture/process_owner.m` 覆盖四元组、IPv6、未连接 UDP、共享端点歧义、FD generation 复用、权限/ABI 错误和预算。

目标 iPod touch 4 / iOS 6.1.6 的准备预检已通过：真实 utun 创建、IPv4/IPv6 配置、恢复与接口消失均被确认，没有安装 redirect 路由或 DNS。真实 Guardian 生命周期预检的 normal-disarm、Supervisor-crash-recovery、strict-emergency 和 strict-Supervisor-adoption 四阶段均已通过。

以下 ARMv7 预检工具由 build-capture 生成并签名，不装入正式包：

```sh
muyu-capture-preflight
muyu-capture-lifecycle
muyu-process-probe
muyu-process-owner-preflight
```

生命周期预检创建真实 utun 并运行真实 Guardian 逻辑；redirect/DNS 操作使用隔离测试后端，不能当作公网路由/DNS 覆盖验收。

目标 iPod touch 4 / iOS 6.1.6 的真实集成转发已通过：IPv4/IPv6 普通应用 TCP 各 35000 字节与 EOF、UDP 的 1/1400/1500 字节、两族 UDP DNS，以及系统 `getaddrinfo` 返回 IPv4/IPv6 Fake-IP 后的实际 TCP 转发。正常 stop/start 后缓存 Fake-IP 再连接和最后的路由/DNS 清理也已通过。记录位于 `.build/ios/device-capture-result.json`。

真实 PROCESS-NAME 与 PROCESS-PATH 规则已分别覆盖 IPv4/IPv6 TCP/UDP，root Supervisor 返回的内核 PID/path 与正在传输的普通应用 Socket 一致，连接行与实际节点匹配。错误路径负控制、正常停止和最终路由/DNS 清理全部通过。记录位于 `.build/ios/device-capture-lifecycle-process-result.json`。

真实 Core SIGKILL 集成验收已通过：恢复模式释放 redirect/DNS 后可手动启动；严格模式保持 `FAILED/BLOCKING` 并阻断新 TCP，手动启动和自动重连均保留同一 Guardian/utun。三种恢复路径都复用崩溃前已由系统缓存的 IPv4/IPv6 Fake-IP，实际 TCP/UDP 转发和最终清理全部通过。记录位于 `.build/ios/device-capture-lifecycle-core-result.json`。

真实 Supervisor SIGKILL 集成验收已通过：恢复模式下 Guardian 独立清理 redirect/DNS，严格模式下保留原 Guardian 与 utun 并阻断新 TCP；新 Supervisor 自动启动并接回同一 Guardian/接口，缓存 IPv4/IPv6 Fake-IP 的 TCP/UDP 转发恢复，最后清理再次通过。记录位于 `.build/ios/device-capture-lifecycle-supervisor-result.json`。

真实受控物理路径变化验收已通过：唯一临时 configd 测试服务短暂改变物理 en0 的全局 IPv4 gateway，Supervisor 在 `lastPathCheck.changedFields` 准确记录 `default4.gateway` 并进入 `FAILED/STOPPED`。测试服务撤回后，原始物理签名、默认路由和 DNS 完整恢复，重新启动后的缓存双栈 Fake-IP TCP/UDP 与最终清理通过。记录位于 `.build/ios/device-capture-lifecycle-path-result.json`。此结果证明真实 configd/default-route 变化的检测与恢复；实际 Wi-Fi 网络之间的切换或 cellular 接口切换没有在这台 iPod 上执行。

四组真实集成验收共 22 项（PROCESS 9、Core 6、Supervisor 4、路径变化 3）全部通过，每组 `passed` 与 `cleanupPassed` 均为 true。每组的 finally 由独立 root probe 核对原始物理签名与 DNS、四条 owned split 路由消失、capture configd 记录消失、journal/Guardian socket 释放。

Fake-IP 退役冷却补强后，最新 ARMv7 构建重新执行 Core 6 项与 Supervisor 4 项，共 10 项全部通过，包括 restore/strict 手动或自动重启、独立 Guardian 恢复或接回、缓存双栈 Fake-IP TCP/UDP 复用及最终完整清理。复验报告为 `.build/ios/device-capture-lifecycle-core-supervisor-result.json`；原 22 项中的 PROCESS 9 项和受控路径变化 3 项没有重复执行。

`tests/device_capture_lifecycle.py` 默认只打印准备状态，必须显式 `--run` 才执行真机测试。它使用唯一 `/private/var/tmp/muyu-capture-lifecycle-*` binary 目录和 root 私有 state，不使用生产 socket/state。PID 路径与存活检查、信号通过独立 `__proc_info` 工具验证；不依赖设备的 `ps` 或 `nohup`。前台 SSH shell 报告 PID 后 exec Supervisor，重定向 daemon 的标准描述符，保留 SSH session 确认其退出。默认路由、物理 DNS、owned split 路由和 configd DNS 会在 finally 中核验；恢复失败保留 journal 和独占紧急恢复入口。

显式 `--stages link` 的物理 Wi-Fi 接口断开/恢复已在 iPod touch 4 / iOS 6.1.6 上通过 10 项验收，证据为 `.build/ios/device-capture-lifecycle-link-result.json`。默认阶段为 PROCESS/Core/Supervisor/configd-path。`muyu-capture-link-fixture` 只接受 `en*`、AF_LINK Ethernet 类型、原 UP、匹配 IPv4/接口索引的物理接口；保存原 flags 后通过 `SIOCSIFFLAGS` 清除 UP。恢复前再次核对接口索引与 MAC，提交保存的 flags。stdin restore/EOF、TERM/INT/HUP 与最长 30 秒 alarm 均进入同一个恢复分支，driver 在恢复期间保留 helper 的 SSH transport 和 Wi-Fi 偏好。

link 分别验收 restore/manual 与 strict/autoReconnect。两种模式均检查 DOWN 前的双栈 TCP/UDP、真实 IFF_UP=0 与链路丢失诊断、UP 后恢复接管、缓存 IPv4/IPv6 Fake-IP 的实际 TCP/UDP，以及最终 flags、route、DNS、journal 和 Guardian 清理。UP 后核对同一接口和 MAC，以及原始 flags、IPv4、IPv6 前缀、两族默认路由和物理 DNS。证据范围为同一 Wi-Fi 接口的受控断开与恢复。

```sh
python3 tests/capture/build-device-lifecycle.py ios
python3 tests/device_capture_lifecycle.py
python3 tests/device_capture_lifecycle.py --stages link
```

实际执行参数由持有 SSH 连接的主流程提供，可以分别选择 `--stages process`、`core`、`supervisor`、`path` 或显式 `link`。每次结果同时保存为最新报告、所选阶段的独立报告和 `.build/ios/device-capture-lifecycle-runs/<nonce>.json`，后续阶段或失败重试不会覆盖既有 run 证据。路径变化使用唯一临时 configd 测试服务，刻意短暂改变全局默认 gateway；不修改用户 Wi-Fi 配置，临时会话在 finally 释放并核对原始物理默认路由与 DNS。[安装与验收](INSTALL.md) · [验收记录](ACCEPTANCE.md)
