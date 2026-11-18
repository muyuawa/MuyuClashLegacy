# 验收状态

目标设备为 rootful 越狱 iPod touch 4 / iOS 6.1.6。正式版仍未完成；机器可读记录见 [acceptance.json](acceptance.json)。旧内部包已安装，新功能先在独立临时设备目录验证，不使用用户配置或生产状态。

已通过的设备证据：

- tests/device_capture.py：普通应用套接字经过 utun、独立 Xray 对端的双栈 TCP 35000 字节与半关闭、UDP、原始 DNS、系统 getaddrinfo 和缓存 Fake-IP 再连接。证据 .build/ios/device-capture-result.json。
- tests/device_capture_lifecycle.py：PROCESS-NAME/PATH、Core/Supervisor SIGKILL、恢复优先/严格阻断、Guardian 独立恢复、重启采用缓存地址、真实 configd 网关变化共 22 项。每项完成后检查路由、DNS、journal 和 Guardian 清理。
- Fake-IP 冷却补强后的新构建再次通过 Core/Supervisor 10 项，证据 .build/ios/device-capture-lifecycle-core-supervisor-result.json。其余 12 项保留原记录，未重复。
- 独立 ARMv7 Fake-IP 测试在目标设备 exit 0，覆盖 ACK 回滚、300 秒退役冷却、满池、旧 v1、fork/SIGKILL 和双栈，证据 .build/ios/device-fake-ip-retired.log。

主机整合验证包含真实自动组探测与转发、模式保留、慢下载期间状态/停止响应、配置 CAS、Provider/Geo 提交故障与 rename 后 fsync 故障回滚。独立 TLS/QUIC 对端验证 DNS 与现代协议；Mach-O 检查独立核对 ARMv7/iOS6、签名、动态依赖和本次实际链接的冻结协议库哈希。

尚待完成：全部必需协议组合的目标设备互通、新包完整升级/重启、真实 UI 操作与退出后后台、Wi-Fi 链路断开/恢复、真实订阅与 Provider/Geo/自动组整合，以及卸载清理。已有局部证据不会代替剩余验收，也不会开启正式发布门禁。
