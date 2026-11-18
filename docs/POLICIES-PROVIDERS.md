# 策略组、Provider 与 Geo 数据

行为参照固定为 Mihomo v1.19.34（`0455d0d28c4526937380505153e65a843d8612e8`）。以下是已接入的行为与资源边界；未列出的扩展字段仍由配置检查器明确拒绝。

## 策略组与实际探测

`select` 支持嵌套选择及持久化选择。`url-test` 用通过各成员真实出站请求取得的响应与延迟选择，`tolerance` 保留容差内的当前成员。`fallback` 按成员顺序选择可用出站。`load-balance` 支持 round-robin、consistent-hashing 和 sticky-sessions：哈希使用 Public Suffix List 得到有效主域名，sticky-sessions 同时使用来源地址并保留有界的会话选择。没有测量的成员显示 unknown，失败、超时或无效成员从健康选择中排除。

`relay` 与节点的 `dialer-proxy` 生成有序实际代理链，最多 16 个代理阶段。组、节点以及拨号引用共同检查循环。测速在派发时使用当前选择和测量解析整条链；每条测量保存实际链，链变化或配置代际变化后丢弃旧结果。Hysteria2 的 QUIC 出站不能放在 TCP 代理阶段后，配置检查器会返回 `CHAIN_PROTOCOL_UNAVAILABLE`。

自动组及 Provider 的 health-check 支持 interval、timeout、lazy、url 和 expected-status。一次探测的目标与 URL 共同决定缓存键，同一节点对不同 URL 的测量互不覆盖。自动与手动测速共用最多 3 个并发槽，手动队列最多 24 个目标，自动作业最多 2048 个，测量最多 4096 条。探测进行时 UI 显示 testing 并保留 previousHealth；策略内部继续使用上一次真实结果。

## 规则

顺序匹配支持 AND、OR、NOT、RULE-SET 和 SUB-RULE。子规则检查循环及最大 32 层深度；已检查子树保留高度，共享子树不会绕过总深度检查。`no-resolve` 向逻辑规则、Provider 和子规则继承，已有来源/目标地址保持其用途。GEOIP 和 IP-ASN 的 `src` 选项匹配来源地址。

PROCESS-NAME 与 PROCESS-PATH 只匹配 Core 提供的可靠进程元数据；未知拥有者不会编造进程名称。域名和 Provider 正则使用 iOS Foundation/ICU，表达式必须能在该引擎编译。其语法与 regexp2 不完全相同。过滤和名称替换具有 50 ms 单次正则期限与 2 秒整体操作期限；超出期限返回错误。名称替换从一次有界枚举的匹配生成结果，输出最多 256 字符。

## Provider 来源及展开

Proxy Provider 支持 HTTPS、私有 file 和 inline，载荷为 Clash YAML 节点。Rule Provider 支持 HTTPS、私有 file、inline，载荷可为 YAML/text；domain 与 ipcidr 还支持 MRSv1。MRS 使用锁定的原生 zstd 解码器，并验证帧、大小、LOUDS 表、排序和 IP 区间，不调用外部程序。

Provider 的 filter、exclude-filter、exclude-type 及已校验的 override 应用于节点；组的 use、include-all、include-all-proxies、include-all-providers 合并成员，empty-fallback 处理空结果。名称前后缀和 proxy-name 替换可消除跨 Provider 重名。合并后重名明确拒绝，以免路由到另一份同名凭据。

Provider 文件放在其私有 `local/` 目录，通过 `provider.import` 导入；配置中的 path 为相对路径，可有一个常规的 `./` 前缀，IO 前规范化到私有根目录内。绝对路径、空组件、其余 `.`/`..` 组件、符号链接和非私有文件会被拒绝，源 YAML 不被修改。HTTPS 验证 CA、证书和主机名，下载失败或载荷无效时保留已经验证且来源身份相同的缓存。缓存启动不读取未经验证的更新。定时更新使用 Provider interval，并限制失败后的重试频率。

目前仍明确拒绝 `override-expr`、`headers`、通过命名代理下载、`age-secret-key`，以及 Foundation 无法编译的 regexp2 表达式。这些选项不会被静默忽略。

## Geo 格式和不可变索引

GeoIP.dat 与 GeoSite.dat 由原生代码解析实际 V2Ray protobuf。Country/ASN MMDB 使用锁定的 libmaxminddb，支持常规 Country/ASN、sing-geoip、Meta-geoip0 的字符串/数组数据，以及 IPinfo ASN。仅为配置引用的类别构建索引。GeoSite 支持 plain、regex、root-domain、full-domain、通配标签、属性键及否定；`@attribute` 按键存在匹配，布尔值 false 仍代表存在。GeoIP dat 模式支持 `!` 否定；MMDB 模式遵循字面类别成员语义。IP-ASN 不支持否定，会明确拒绝。GeoIP LAN 包含固定参照中的私有、环回、未指定和多播范围。

私有 Geo `local/` 默认文件名为 `GeoIP.dat`、`GeoSite.dat`、`Country.mmdb`、`ASN.mmdb`。对应 geox-url 未配置时优先使用本地来源；缓存启动优先复用已提交的来源快照。设置 geox-url 后用验证过的 HTTPS 更新。支持 geodata-mode、geo-auto-update、geo-update-interval 及 memconservative/memc loader；standard loader 不在旧设备的资源预算内。

Supervisor 顺序解析来源并为每份来源单独释放临时对象。原始文件复用时以 8 KiB 缓冲验证 SHA-256，避免再次分配完整数据库副本。生成的 Core 索引由 Supervisor 拥有，文件 0444、目录 0755；Core 在映射前检查路径、拥有者、权限、普通文件类型、链接数、大小、哈希与二进制格式。IP 使用排序合并区间及二分查找。公开描述仅含文件路径、哈希、拥有者和大小，不复制原始数据库。

## 存储、资源与提交

配置源上限 512 KiB，展开后的 JSON 代际上限 768 KiB。最多 32 个 Provider、1024 个合并节点和 10000 条 Provider 规则。Provider 缓存上限 64 MiB/256 个快照。Geo 每份原始来源最多 32 MiB，私有原始缓存最多 128 MiB，公开索引缓存最多 96 MiB；每个索引最多 32 MiB、256 类别及 4096 个正则。磁盘预算保留活动与待提交来源；超出预算返回错误。

快照按内容哈希命名。Provider 用 cache-index.json、Geo 用 geo-current.json 原子提交来源指针；提交期间持有文件锁并比较旧指针，拒绝另一进程已经修改的代际。准备成功并不改变活动来源。`captureCheckpoint`/`restoreCheckpoint:error:` 支持协调器在后续组件提交失败时恢复已提交的来源指针和内存状态，且拒绝覆盖另一进程的新提交。已有连接继续持有旧配置。私有来源文件为服务拥有的 0600 普通文件。崩溃遗留的已识别 staging 文件验证拥有者、权限、链接数和大小；一天后才允许清理，较新的文件计入预算。

大于 64 KiB 的 YAML/文本域名规则 Provider 在准备阶段编译为有界的只读磁盘索引。每份来源上限 8 MiB、250,000 条，索引上限 16 MiB。Core 在接收新配置代际时校验索引的文件权限、内容哈希及格式，然后用索引匹配路由和 DNS 规则。缓存提交只发布完整生成的快照，下载或编译失败时继续使用已验证的缓存。

快照和目录同步失败会返回提交失败，包含重命名已完成但目录 `fsync` 失败的情况。管理器保留这次尝试写入的完整指针字节供回滚校验。恢复读取并校验磁盘文件拥有者、权限、字节和哈希；已等于 checkpoint 的指针不再写入目录，仍恢复旧内存代际。只读目录中失败的提交因此不会误停旧 Core。陌生指针或权限变化会明确拒绝覆盖。

来源 YAML 不能注入 `_` 开头的内部字段。准备配置会重新检查完整展开结果；Geo 规则缺少验证过的类别时拒绝活动切换。

## 已执行验证

DNS 的 nameserver-policy 和 fake-ip-filter 支持 `geosite:` 与 `rule-set:`（包括逗号列出的多个类别/Provider）。Classical Provider 在域名匹配中只使用域名规则。源 YAML 的 DNS policy 顺序由源位置保存在内部代际字段；连续普通域名规则按特异度选择，与 Geo/规则集块的原始顺序共同决定选择。Fake-IP 支持 blacklist/whitelist，过滤结果使用已验证的不可变索引与 Provider 快照。

fallback-filter 支持 geoip/geoip-code、geosite、ipcidr 和 domain。域名/GeoSite 命中直接查询 fallback；GeoIP 对主要响应中不属于配置地区的公共地址使用 fallback，LAN 地址保留主要结果，显式 ipcidr 可触发替换。存在 fallback 时 geoip 默认 true、地区默认 CN；因此该配置需要准备 CN 数据库。策略命中的专用上游独立解析。A/AAAA 的解析和原始 DNS 响应均经过过滤，非地址查询按普通策略解析。

DNS 的 exchangeHandler 区分 application/proxy/direct/bootstrap 场景，有 handler 时失败不会直接发送查询。准备时确认 `#Group` 上游引用；respect-rules 要求单独的 proxy-server-nameserver。default-nameserver 与 proxy-server-nameserver 的 `#` 指定只能为 DIRECT，检查器与交换器都会拒绝命名代理，避免代理服务器本身的解析递归。上述逻辑由 `tests/dns_policies.py` 独立构建最新 DNS/路由/Geo 源码，验证 IPv4/IPv6、LAN、过滤、来源顺序、黑白名单及四种场景；传输互通由主集成另行核验。

无 exchangeHandler 的默认解析器支持验证过的 `quic://` DoQ，恢复上游规范化为零的 DNS ID 为原始请求 ID。`#DIRECT` 可显式选择直连；DoQ 的命名代理嵌套由配置检查器拒绝，因为其原生 QUIC 引擎使用直接 UDP IO。

`tests/policies.m` 验证不同策略、容差、链顺序、独立 URL 测量、并发上限和旧代际隔离。`tests/policies_config.m` 验证字段、引用、循环、子树深度和保留内部字段。`tests/providers.m`/`providers_tls.py` 验证本地/inline/HTTPS、名称替换、成员展开、失败更新、Checkpoint、私有路径及缓存修复。

`tests/mrs.py` 独立写入 MRSv1 帧和表，包含截断、尾部、溢出、非法拓扑、IP 重叠/排序及真实 HTTPS 更新。`tests/geo.py` 使用锁定的官方 MMDB 与独立 protobuf 数据，验证 2107 个 Country/ASN IPv4/IPv6 边界地址的正确类别与错误类别、属性/否定、本地和 HTTPS 更新、主机名拒绝、Checkpoint、重启复用、同哈希 inode 复用、损坏 raw 修复与过期 staging 清理。上述模块另通过 ARMv7/iOS 6 的 `-Werror` 编译。主机测试结果不能代替目标设备互通或整机接管验收。

`tests/service_data.py` 使用真实 Supervisor/Core、独立 HTTPS 与 SOCKS 服务验证慢下载期间停止响应、配置源竞争、缓存重启、坏更新回退及实际规则转发。自动组通过真实 HEAD 请求测量延迟，并核验 url-test、fallback、round-robin 的实际出站与热更新中的模式和已有连接。目录只读及真实重命名后目录同步报错均验证旧磁盘指针、旧 Core PID 与旧转发得以保留；故障注入仅在主机私有临时目录与测试进程中启用。

默认 GeoIP 已随包提供 Country.mmdb 与 GeoIP.dat，位于 `/usr/share/muyuclash/geodata`，来源与 SHA-256 记录在同目录 manifest.json。显式 geox-url 和私有 local 目录中的用户文件优先；已有验证缓存继续使用，显式更新可联网更新。相同来源和请求类别恢复时复用经哈希/权限校验的原生只读索引，不重新解析全部数据库。GeoSite 与 ASN 仍按配置和缓存加载。
