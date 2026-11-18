# Rootful 安装与移除

目标为 iOS 6 / ARMv7 rootful 越狱设备。包标识为 `com.muyu.clashlegacy`，dpkg 架构为 `iphoneos-arm`。**当前仅提供测试包，尚未经过充分验证，不是稳定版；有限实机范围为 iPod touch 4 / iOS 6.1.6。** 正式版验收仍未完成。[验收记录](ACCEPTANCE.md)

## 公开测试包

从仓库 Releases 下载标记为 Pre-release 的安装包和 SHA256SUMS，校验后使用 root shell 安装。安装或升级前备份 `/private/var/lib/muyuclash/`；其中含私密配置，不要上传。

```sh
dpkg -i MuyuClash-Legacy-0.1.0-beta.1-iphoneos-arm.deb
```

可选去阴影包只支持 iOS 6.1.6，要求 Substrate，安装后需要 respring；见 [图标组件](../icon-shadow/README.md)。测试包与正式包使用相同应用标识，旧内部版本安装测试版时 dpkg 可能提示版本回退；正常安装保留用户数据。完整升级和卸载流程仍需更多实机验证。

## 打包

依照构建说明完成签名的 ARMv7 应用和命令行组件后，在开发机执行以下命令。只有产品、核心、接管和设备验收门禁都通过，命令才生成 `dist/MuyuClash-Legacy.deb`。[构建说明](BUILD.md)

```sh
python3 scripts/release.py
```

包采用 Debian 2.0 的 `ar` 格式，控制文件和数据文件使用 gzip 压缩的 tar。主机测试解包检查权限、部署路径和 launchd 配置，并在 `.build/` 中演练升级、移除和清除数据。[Debian 包格式](https://manpages.debian.org/bookworm/dpkg-dev/deb.5.en.html)

```sh
python3 tests/release_gate.py
```

## 安装和升级

通过设备上的 Cydia 安装正式包，或者在设备的 root shell 执行以下命令。升级沿用相同命令。

```sh
dpkg -i MuyuClash-Legacy.deb
```

| 路径 | 内容 |
| --- | --- |
| `/Applications/MuyuClash.app` | 原生应用 |
| `/Library/LaunchDaemons/com.muyu.clashlegacy.supervisor.plist` | Supervisor 的 launchd 配置 |
| `/usr/libexec/muyuclash/` | Supervisor、Core、控制 CLI、配置检查和接管探测工具 |
| `/usr/share/muyuclash/` | CA 证书束和可导入的默认配置 |
| `/usr/share/muyuclash/geodata/` | 内置离线 GeoIP、来源、许可与校验清单 |
| `/usr/share/doc/com.muyu.clashlegacy/` | 许可证和依赖版本记录 |
| `/private/var/lib/muyuclash/` | 用户配置、订阅、设置和历史，由 Supervisor 管理 |
| `/var/run/muyuclash/control.sock` | Supervisor 的本地控制 Socket |

安装脚本以 `0700` 权限准备数据目录，加载 Supervisor 并检查 IPC 应答。Supervisor 根据保留的设置决定是否自动启动代理。默认 YAML 仅供导入。[launchctl 手册](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchctl.1)

```sh
launchctl list com.muyu.clashlegacy.supervisor
/usr/libexec/muyuclash/muyu-cli /var/run/muyuclash/control.sock service.status
```

## 异常恢复

先在应用内断开。若应用不可用，通过 root shell 调用本项目恢复工具；该操作仅尝试恢复本项目记录的网络状态，不能保证修复其他插件造成的问题。

```sh
/usr/libexec/muyuclash/muyu-network-recover --emergency
```

## 移除和清除

如果装过可选图标组件，先单独移除并 respring：`dpkg -r com.muyu.clashlegacy.icon-no-shadow`。

升级和移除会卸载本项目的 launchd 作业。若 Supervisor 正在运行且控制 Socket 可用，脚本先通过该 Socket 请求恢复本项目管理的网络状态。确认作业已停止后，脚本清理本项目的运行 Socket。普通移除保留用户数据。网络恢复的设备验证详见验收记录。[验收记录](ACCEPTANCE.md)

```sh
dpkg -r com.muyu.clashlegacy
```

显式清除同时删除 `/private/var/lib/muyuclash/` 内的用户配置、订阅、选择历史及设置。

```sh
dpkg --purge com.muyu.clashlegacy
```
