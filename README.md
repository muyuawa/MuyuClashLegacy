<p align="center"><img src="assets/AppIcon.png" width="128" alt="MuyuClash 图标"></p>

# MuyuClash Legacy

面向 **rootful 越狱 iOS 6 / ARMv7** 的原生代理客户端。

> **当前为测试版（Beta），尚未经过充分验证，不是稳定版。**
> 目前仅在 iPod touch 4 / iOS 6.1.6 上做过有限的实机验证。其他设备、系统版本、协议组合、长期运行、升级和卸载流程没有得到完整验证，可能出现连接失败、界面异常或网络恢复问题。请备份配置并保留 SSH 等恢复途径，勿作为唯一联网工具。

## 当前功能

- 原生 UIKit 界面：配置导入、节点与策略组选择、连接状态、流量和 DNS 设置。
- 本机 Core / Supervisor 与 utun 接管，支持 TCP、UDP 和系统 DNS；恢复机制仍需更多实机验证。
- YAML、HTTPS 订阅、支持的节点链接、文件及图片二维码导入。**项目和安装包不附带订阅、账号或可用节点。**
- 顺序规则、策略组、Provider，以及随包提供的离线 GeoIP MMDB / DAT。内置数据减少首次准备对网络下载的依赖，不保证代理速度或节点延迟变快。
- 首页显示当前策略组、出口节点、协议及延迟；无实际流量时将默认路径标为“待使用”。当前出口的有限测速不代表所有节点都已测试。
- 已修复已应用配置仍提示重新应用、主页轮询闪动、连接中按钮文字不清晰等问题。

协议名称出现在源码或通过主机互通检查，**不表示全部选项都兼容，也不表示已在 iOS 6 上充分验证**。详细范围见 [兼容性](docs/COMPATIBILITY.md)、[协议边界](docs/PROTOCOLS.md) 和 [验收清单](docs/ACCEPTANCE.md)。

## 下载与安装

从本仓库的 [Releases](https://github.com/muyuawa/MuyuClashLegacy/releases) 下载标记为 **Pre-release** 的测试包；同时提供对应源码和 SHA-256 校验文件。

要求：rootful 越狱、ARMv7、iOS 6；当前实机范围仅为 iOS 6.1.6 / iPod touch 4。安装前备份自己的配置；用户数据位于 `/private/var/lib/muyuclash/`，该目录含私密信息，勿上传到 Issue。

在设备 root shell 执行：

~~~sh
dpkg -i MuyuClash-Legacy-0.1.0-beta.1-iphoneos-arm.deb
~~~

打开 MuyuClash，导入自己的配置，检查并应用后连接。遇到错误请阅读 [配置说明](docs/CONFIG.md)。安装位置、网络恢复和移除步骤见 [安装说明](docs/INSTALL.md)。

### 图标与 iOS 6 阴影

应用使用蓝色猫咪图标，并关闭系统额外高光。桌面外阴影另提供可选的 **MuyuClash Icon No Shadow** 组件：

~~~sh
dpkg -i MuyuClash-Icon-No-Shadow-0.1.0-beta.1-iphoneos-arm.deb
~~~

该组件需要 **Cydia Substrate / MobileSubstrate**，仅在 **iOS 6.1.6** 启用，只针对 MuyuClash 的桌面和 Dock 图标。安装或移除后需重新启动 SpringBoard（respring）。它使用私有接口，属于同样未充分验证的测试组件。主应用不依赖它。说明及单独移除命令见 [图标组件](icon-shadow/README.md)。

## 已知限制与反馈

- 不是官方 Clash / Mihomo 客户端，不保证完整配置语义兼容；Snell、SSR 及部分传输组合仍在开发。
- 现代 TLS、QUIC 和加密协议在老硬件上可能占用较多 CPU / 内存。
- 完整设备与协议矩阵、长时间运行、真实 Wi-Fi 切换、升级和卸载仍待补充验证；当前状态以 [验收记录](docs/ACCEPTANCE.md) 为准。
- 断开异常时先在应用内停止连接；仍无法恢复可在 root 下执行 `/usr/libexec/muyuclash/muyu-network-recover --emergency`，详见 [安装与恢复](docs/INSTALL.md)。

提交 Issue 时请提供系统版本、设备型号、重现步骤和脱敏错误。**不要上传订阅链接、节点名称/地址、密码、UUID、密钥、完整 YAML、诊断原件或设备备份。** 日志和截图也请自行复查。

## 开发构建

需要 macOS、Apple clang、Python 3、CMake、支持 ARMv7 的 ld-classic，以及合法取得的旧版 iOS SDK。依赖归档通过 SHA-256 锁定；iOS SDK 不随项目分发。

~~~sh
python3 scripts/bootstrap.py
export IOS_SDK=/absolute/path/iPhoneOS7.1.sdk
bash scripts/build-deps.sh
python3 scripts/build.py --target ios
python3 scripts/verify-ios.py
python3 scripts/package-beta.py
~~~

测试版打包命令输出到 `dist/0.1.0-beta.1/`，不会修改正式版验收状态。`python3 scripts/release.py` 仍受原有门禁约束，未通过时拒绝生成正式包。主机开发与按需检查见 [构建说明](docs/BUILD.md)。

## 许可与来源

新增源码采用 [GPL-3.0-or-later](LICENSE)。第三方组件保留各自许可，见 [依赖列表](docs/DEPENDENCIES.md)、[第三方许可](third_party/licenses) 和 [GeoIP 来源](resources/geodata/UPSTREAM.md)。发布包附带许可文件，并提供包含锁定依赖归档的对应源码。
