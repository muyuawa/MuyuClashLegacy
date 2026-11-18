# 构建与内部运行

所有命令在本目录执行。**当前为尚未充分验证的测试版。** 构建不需要任何个人订阅、节点或设备登录凭据。

## 主机构建

```sh
python3 scripts/bootstrap.py
bash scripts/test.sh
```

`bootstrap.py` 从 SHA-256 锁定的归档取得 libyaml、curl 和 Mbed TLS。相邻已下载归档只作为缓存，仍核对完整哈希。主机测试使用 macOS Foundation、系统 libcurl 与 OpenSSL 3 静态库。设置 `MLSTREAM_OPENSSL_PREFIX` 可指定 OpenSSL 安装目录，默认使用 `/opt/local/libexec/openssl3`。主机测试通过独立的回环服务验证数据转发、协议、TLS 和 DNS。

内部 daemon 可在私有临时目录运行：

```sh
mkdir -m 700 /tmp/muyuclash-local
.build/host/muyu-supervisor --development --socket /tmp/muyuclash-local/control.sock --state-dir /private/tmp/muyuclash-local/state
```

另一个终端查询：

```sh
.build/host/muyu-cli /tmp/muyuclash-local/control.sock service.status
.build/host/muyu-cli /tmp/muyuclash-local/control.sock system.capabilities
```

按 Ctrl-C 正常关闭服务并清理其控制 Socket。主机开发服务不会操作网络路由、系统 DNS 或防火墙。

## iOS 内部产物

设置 `IOS_SDK` 为合法取得的、支持 ARMv7 的 SDK 路径。已有环境默认取相邻 `.deps/sdk71/iPhoneOS7.1.sdk`。构建使用 `armv7-apple-ios6.0`、Apple clang 和 `/Library/Developer/CommandLineTools/usr/bin/ld-classic`。

```sh
bash scripts/build-deps.sh
python3 scripts/build.py --target ios
python3 scripts/verify-ios.py
bash scripts/build-senko.sh
```

内部产物位于 `.build/ios/`，包含签名的 UIKit `.app`、Supervisor、`muyu-core`、控制 CLI、配置检查器与接管探测器。Supervisor 通过私有 Socket 向 `muyu-core` 传配置。独立 Senko 候选位于 `.build/senko/`，核心复用锁定的部分协议源码和 OpenSSL 静态库。

`scripts/build-senko.sh` 会额外取得已锁定的 Senko、OpenSSL、ngtcp2、nghttp3 和 sfparse 源码；可用 `SENKO_JOBS` 调整构建并发。相应许可证副本和检查证据在 `.build/senko/licenses/`、`.build/senko/inspection.json`。

CA 数据在 `resources/cacert.pem`，为 Mozilla 证书束，原始说明和 MPL-2.0 许可保留。SHA-256：`796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`。安装包将其安装到 `/usr/share/muyuclash/cacert.pem`。

## 测试版打包

```sh
python3 scripts/package-beta.py
```

输出主应用测试包、可选去阴影测试包、包含锁定依赖归档的对应源码及 SHA256SUMS。此入口明确标记 Beta，不改变正式版验收清单或 `releaseReady`。图标 PNG 已随源码提供，无需图片工具即可构建；可选 Substrate 组件由 iOS 构建一起编译，也可用 `python3 scripts/build-icon-shadow.py` 单独编译。

## 发布门禁

```sh
python3 scripts/release.py
```

当前应拒绝发布并返回状态 2。`docs/acceptance.json` 按证据逐项记录；已有整机接管和崩溃恢复设备证据，完整协议与安装/界面/卸载验收仍待完成。`.deb` 归档与维护脚本已通过主机测试。

并行开发时可用 `--reuse-dependencies --stream-archive ARCHIVE` 链接经过独立验证的冻结协议库。`build-status.json` 保存实际库路径与 SHA-256；`verify-ios.py` 检查该库。QUIC Python 对端需使用与锁定 fixture 依赖匹配的 Python 3.12，可通过 `MLSTREAM_TEST_PYTHON` 指定。
