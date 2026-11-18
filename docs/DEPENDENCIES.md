# 依赖与许可

本目录新增代码选用 GPL-3.0-or-later。与相邻 MIT 暮雨音乐工程保持源代码边界；没有将其业务代码复制进来。

| 依赖 | 来源/版本 | 使用情况 | 许可 |
|---|---|---|---|
| libyaml | [0.2.5 / 2c891fc](https://github.com/yaml/libyaml/tree/2c891fc7a770e8ba2fec34fc6b545c672beb37e6) | 配置解析 | MIT |
| curl | [8.23.0](https://curl.se/download.html) | HTTPS 订阅下载 | curl license |
| Mbed TLS | [3.6.7](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7) | iOS 订阅 TLS 静态依赖 | Apache-2.0 或 GPL-2.0-or-later |
| Mozilla CA | [CA 提取说明](https://curl.se/docs/caextract.html) | 证书验证 | MPL-2.0 |
| Senko / OpenSSL | [协议构建证据](PROTOCOLS.md) | 锁定部分协议源码与 TLS 静态库 | 见该文与锁文件 |
| ngtcp2 / nghttp3 / sfparse | [协议构建证据](PROTOCOLS.md) | 独立 QUIC 移植候选 | MIT |
| ZBar | [Senko 内置移植版](https://github.com/sqmrak/senko/tree/b9f7e6ab9c369f9acf753b00b49143269ed15ca8/app/third_party/zbar) | 本机二维码解码 | LGPL 原文见构建归档 |
| Mihomo | [v1.19.34 / 0455d0d](https://github.com/MetaCubeX/mihomo/tree/0455d0d28c4526937380505153e65a843d8612e8) | 固定行为目标，未链接或复制源码 | GPL-3.0 |
| Public Suffix List | [锁定列表](https://publicsuffix.org/list/public_suffix_list.dat)，SHA-256 `809adae1a2cb1621b70165c11e0d14412d3f104f40a4ebed9a99e23c54f78d71` | 自动策略组的有效主域名；生成了 IDNA 别名 | MPL-2.0 |
| zstd | [1.5.7](https://github.com/facebook/zstd/tree/v1.5.7) | 原生有界 MRSv1 解压；锁见 providers/manifest-zstd.json | BSD-3-Clause（双许可中选择） |
| libmaxminddb | [1.14.1 / 4a3d17a](https://github.com/maxmind/libmaxminddb/tree/4a3d17a621c0ebcb81498fd34d313f67fd940ab5) | Country/ASN MMDB 原生读取；锁见 providers/manifest-maxminddb.json | Apache-2.0 |
| MaxMind-DB 测试数据 | [dc32db5](https://github.com/maxmind/MaxMind-DB/tree/dc32db5525f9c42ab7006ab3f13c69330b814dd1) | 官方 Country/ASN MMDB 与对应 JSON，哈希见 tests/fixtures/geo/manifest.json | MIT（双许可中选择；两份原文均保留） |
| Apple SDK / clang / ld-classic | 本机开发环境 | 构建工具 | 不随本项目再分发 |

精确归档 URL 与 SHA-256 见 `third_party/manifest*.json`、`providers/manifest-*.json` 和测试数据的 manifest。许可与版权通知副本位于 `third_party/licenses/`；Senko 组合的全部原始通知在其源码及构建收集目录保留。PSL 对应源码在 routing/public_suffix_list.dat，重建时用 routing/update-public-suffix.py 检查来源哈希。第三方的版本/编译成功不代表其协议已完成互通验收。
