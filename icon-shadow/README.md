# MuyuClash Icon No Shadow（测试组件）

**尚未经过充分验证。** 独立、可选的 rootful Substrate 扩展，主应用不依赖它。仅在 iOS 6.1.6 的 SpringBoard 中启用，要求预期的私有方法签名和 `_shadow` 对象字段均存在。其他系统或接口不匹配时保持不启用。

应用的 `UIPrerenderedIcon` 关闭额外高光；外阴影由 SpringBoard 单独绘制。本组件只对 bundle ID 为 `com.muyu.clashlegacy`、位于桌面或 Dock 的图标返回同尺寸透明阴影图像。视图复用和位置变化时恢复正常图像，不更换全局阴影资源。

## 安装与移除

需要已安装 Cydia Substrate / MobileSubstrate。安装主应用后执行：

~~~sh
dpkg -i MuyuClash-Icon-No-Shadow-0.1.0-beta.1-iphoneos-arm.deb
~~~

单独移除：

~~~sh
dpkg -r com.muyu.clashlegacy.icon-no-shadow
~~~

安装和移除后均需 respring。包不主动重启设备。保留 Safe Mode / SSH 恢复途径；恢复时也可删除以下两个文件再 respring：

- `/Library/MobileSubstrate/DynamicLibraries/MuyuClashIconNoShadow.dylib`
- `/Library/MobileSubstrate/DynamicLibraries/MuyuClashIconNoShadow.plist`

## 构建与范围

设置支持 ARMv7 的 `IOS_SDK` 后执行 `python3 scripts/build-icon-shadow.py`。输出位于 `.build/ios/icon-shadow/`，采用兼容 iOS 6 的 SHA-1 主签名。`scripts/package-beta.py` 生成独立测试包，源码随主项目的对应源码归档提供。

运行时保护不能证明所有主题或扩展组合都兼容。目前不声称支持其他 iOS 6 小版本，也不声称完成 SpringBoard 全面回归验证。

组件加载时仅写入一份激活状态缓存：`/var/mobile/Library/Caches/com.muyu.clashlegacy.icon-no-shadow.plist`，包含状态、进程号和时间，不包含配置、订阅或节点。移除组件后可一并删除该缓存。

## 接口参考

- [Apple UIPrerenderedIcon](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html)
- [iOS 6 SBIconView](https://github.com/caughtinflux/iOS-6-SpringBoard-Headers/blob/master/SBIconView.h)
- [iOS 6 SBIcon](https://github.com/caughtinflux/iOS-6-SpringBoard-Headers/blob/master/SBIcon.h)
- [Substrate MSHookMessageEx](https://www.cydiasubstrate.com/api/c/MSHookMessageEx/)
- [Substrate 扩展部署](https://www.cydiasubstrate.com/inject/darwin/)
