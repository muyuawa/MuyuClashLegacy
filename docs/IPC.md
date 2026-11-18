# 本地接口

控制 Socket 为 `/var/run/muyuclash/control.sock`，设备上只接受 root 或 mobile UID。配置存储位于 `/private/var/lib/muyuclash`。控制口没有 TCP 监听。

消息格式为四字节网络字节序长度及 UTF-8 JSON，最大 1 MiB。应答保留相同版本和 ID，包含 `result` 对象或 `error:{code,message}`。服务限制并发。订阅下载期间其余下载返回 `E_BUSY`。

```json
{"version":1,"id":"request-1","method":"service.status","params":{}}
```

| 方法 | 当前行为 |
|---|---|
| `service.status` | 返回状态、配置、模式、监听端口、流量和系统覆盖。本机 TCP 代理工作时状态为 `DEGRADED`。`statistics.outbound` 包含策略组、出口、协议、真实延迟与测速状态；`source=recent` 为最近成功打开的实际出口，`default` 为尚无流量时的默认/MATCH 路径。短连接关闭后保留实际出口，切换配置/模式/节点后失效；当前路径缺少新鲜延迟时仅发起一次有界测速，每路径至少间隔五分钟 |
| `service.start` / `service.stop` | 启停独立本机核心，启动要求有已应用配置 |
| `service.mode` | `{mode}` 为 Rule、Global 或 Direct。新连接使用新模式 |
| `config.check` | `{yaml}` 返回报告，省略原文和凭据 |
| `config.import` / `config.importNodes` | 导入 YAML 或节点链接并保存为候选 |
| `config.importURL` / `config.update` | 验证 HTTPS 后保存新候选，原有配置继续可用 |
| `config.list` / `config.source` | 列出候选元数据，按 ID 显式读取原始 YAML |
| `config.apply` | 应用预检通过的配置。运行中只给新连接分配新配置 |
| `config.metadata` / `config.delete` | 按 ID 更新名称、HTTPS URL 或删除非活动候选 |
| `group.list` / `proxy.list` / `group.select` | 查询与切换选择组，保存每个配置的选择。嵌套组可用 |
| `proxy.test` | 对组内节点发起有界 HTTP 测速，结果通过 `proxy.list` 读取 |
| `connections.list` / `connections.close` | 查询实际活动 TCP 会话，按连接 ID 关闭 |
| `dns.status` / `dns.query` / `dns.cache` / `dns.clear` | 诊断配置上游，查询解析结果和缓存 |
| `logs.list` / `logs.clear` | 读取和清空有界脱敏日志 |
| `settings.get` / `settings.set` | 读写实际设置，包括开机后尝试启动和异常重试 |
| `system.capabilities` / `system.dependencies` / `diagnostics.run` | 报告当前构建能力、依赖与接管探测 |
| `network.restore` | 查询是否有本项目拥有的系统网络改动需要恢复，当前接管未启用 |
