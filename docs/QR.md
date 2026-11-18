# 二维码导入

从配置页选择二维码导入后，可拍摄一张照片或选择一张现有照片。只有一个来源可用时会直接打开该来源。取消会返回配置页。解码在本机后台进行，解码得到的文本交给现有配置导入流程。

解码器接受一张独立二维码和有效的 UTF-8 文本。图片长边最多缩放至 1280 像素，输入图像超过 16,777,216 像素时提示先裁剪。解码在灰度位图上进行。

构建使用 Senko 已锁定归档中的 ZBar QR-only 源码。`scripts/build-qr.py` 生成 `.build/qr/ios/libmuyuqr.a`。许可证与 Senko 的修改说明随正式包安装到 `/usr/share/doc/com.muyu.clashlegacy/licenses/zbar/`。对应源码及构建说明应随正式版一同分发，以便重新链接修改后的 ZBar。[ZBar 源码](https://github.com/mchehab/zbar/tree/2ea2ca585b10a07e528af08ddf8890756e059b5b) · [Senko 的 ZBar 修改说明](https://github.com/sqmrak/senko/blob/b9f7e6ab9c369f9acf753b00b49143269ed15ca8/app/third_party/zbar/README.senko)

```sh
python3 scripts/build-qr.py
python3 tests/qr.py
```

主机测试覆盖缩放和 UTF-8 解码，以及无二维码、多张二维码、无效 UTF-8 和嵌入空字符。iOS 6 的相机及照片选择交互仍待设备验收。[验收记录](ACCEPTANCE.md)
