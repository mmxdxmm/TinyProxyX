# TinyProxy X

一个轻量的 Android 代理客户端：内置 **Xray 内核**，支持多协议、多跳链路、分流规则和两种运行方式（VPN / 热点 root）。
界面全部用代码绘制，没有第三方 UI 框架；构建同样不依赖 Gradle，`aapt2 + javac + d8 + apksigner` 一条脚本出包。

- 包名：`com.lcs.tproxy`
- 最低系统：Android 8.0（API 26），目标 API 34
- 架构：`arm64-v8a`
- 当前版本：**2.0.3**（versionCode 60）

## 功能

| 分类 | 说明 |
| --- | --- |
| 协议 | VLESS、VMess、Trojan、Shadowsocks、SOCKS5、HTTP，支持把多个节点串成一条链（多跳） |
| 协议参数 | 编辑页覆盖 v2rayNG 的常用字段：VLESS `encryption`、KCP `seed/mtu/tti`、gRPC `multi`、XHTTP `mode/extra`、TLS ECH / 证书 pin、REALITY `mldsa65Verify`、`finalmask`、TCP HTTP 伪装 |
| 注入 | 独立的首跳类型：自定义 HTTP 首行与请求头模板，可只填 https 槽由 443 接管 80，也可 http/https 分槽处理 |
| 运行方式 | **VPN 模式**：`VpnService` + 内置 hev-socks5-tunnel，无需 root；**热点模式**：root 下用 TPROXY，可把代理共享给热点设备 |
| 路由 | 全局 / 绕过大陆 / 绕过局域网 / 自定义规则，支持分应用代理（白名单、黑名单） |
| 策略 | UDP、QUIC(443)、DNS(53)、IPv6 分别可选 代理 / 直连 / 拦截 |
| DNS | 远程与国内 DNS 可分开设置，支持 DoH、Bootstrap 解析 |
| 订阅 | 多个订阅地址，一次更新整包追加；兼容分享链接、完整 xray/v2ray JSON、旧版 ini |
| 其他 | 延迟测试、运行日志、xray 配置预览、内核与 geoip/geosite 更新、本地端口可改 |

## 下载

- 最新版本：[Releases](https://github.com/mmxdxmm/TinyProxyX/releases/latest)
- 仓库内副本：[`release/TinyProxyX-2.0.3.apk`](release/TinyProxyX-2.0.3.apk)（16 MB）
- SHA-256：`c5f6cad9be222bccfd4ba72455b5a7f1042916e60f5e1f1453da9d411628478a`
- 签名证书 SHA-256：`f8766faafdb62fdf43be18f2ffe83d53647887508aefb8e0a00524943d5aa504`
  （与 1.5.6 起各版本同一张证书，可直接覆盖安装）

> 只提供 arm64-v8a。32 位设备、x86 模拟器装不上。

## 使用

1. 安装 APK，首次启动允许通知权限。
2. 主页 **＋ 新建配置**，或 **导入链接 / 配置** 粘贴分享链接、订阅内容、完整 JSON。
3. 需要订阅的话，到 **设置 → 订阅** 填地址，回来点更新。
4. 选中配置 → **启 动**。VPN 模式首次会弹系统授权；热点模式需要 root。
5. 主页可切 **VPN / 热点**、看运行日志、预览生成的 xray 配置；配置卡片里能改路由、测速、分享、删除。

本地默认端口：SOCKS5 `10808`、HTTP `10809`、TPROXY `12345`，都可以在设置里改。

## 构建

需要：JDK 11+、Android SDK Platform 34、Build-Tools 34.0.0、Python 3（打包时往 APK 里塞 dex 和 so）。

```bash
export ANDROID_SDK_ROOT=/path/to/android-sdk   # 目录下要有 platforms/android-34 和 build-tools/34.0.0
bash build.sh
# 产物：build/TinyProxyX-2.0.3.apk
```

Windows 用 `build.ps1`（同一套流程，工具链路径按本机改，可用 `TPX_WORKSPACE` / `TPX_STAGE` 覆盖）。

跑单元与并发测试：

```bash
bash test/run.sh
```

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/com/lcs/tproxy/core` | 进程控制、端口、内核安装与更新、通知 |
| `src/com/lcs/tproxy/xray` | 由配置生成 xray config.json |
| `src/com/lcs/tproxy/inject` | 注入模式：ini 解析、HTTP 改写、连接分派 |
| `src/com/lcs/tproxy/link` | 分享链接 / JSON / ini 的导入导出 |
| `src/com/lcs/tproxy/model` | 节点、配置、规则、存储 |
| `src/com/lcs/tproxy/ui` | 全部界面（纯代码布局） |
| `src/com/lcs/tproxy/vpn` | VPN 服务与 root 服务 |
| `src/hev/htproxy` | hev-socks5-tunnel 的 JNI 入口 |
| `jniLibs/arm64-v8a` | 预编译的 `libxray.so`、`libhev-socks5-tunnel.so` |
| `assets` | `geoip.dat`、`geosite.dat`、`Country.mmdb` |
| `test` | JVM 侧回归测试（Refactor / Concurrency）与 android 桩类 |
| `tools` | 打包、分支统计、对拍脚本 |

## 版本与更新日志

见 [`说明.txt`](说明.txt)，按版本从新到旧记录每个改动的现象、根因和验证方式。

2.0.3 把 Xray 协议配置项补齐到与 v2rayNG 一致：VLESS `encryption`、KCP `seed/mtu/tti`、gRPC `multi`、XHTTP `mode/extra`、TLS ECH / 证书 pin、REALITY `mldsa65Verify`、`finalmask`、TCP HTTP 伪装；主界面右上角「热点」按钮同时改名「高级」。

2.0.2 修的是注入模式「80 端口交给 https 槽接管」时全部超时的问题：分派表 `PATH[0][1][1]` 漏填，导致该走 CONNECT 的连接走了直连隧道。

## 签名

仓库**不包含**签名私钥。`build.sh` 第一次运行会在 `sign/signing/` 下生成一个自用 keystore（已被 `.gitignore` 排除），
所以自己构建出来的 APK 和 Releases 里的不是同一张证书，不能覆盖安装，需要先卸载旧版。

## 已知限制

- 只编译了 arm64-v8a。
- 热点模式依赖 root 与 iptables/TPROXY，部分定制系统可能不兼容。
- 注入模式需要服务端配合，模板写错会直接握手失败，日志里能看到具体阶段。
- 内核与 geo 数据从 GitHub 更新，网络不通时需要自备文件导入。

## 致谢

[Xray-core](https://github.com/XTLS/Xray-core)、[hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel)、
[v2fly/geoip](https://github.com/v2fly/geoip)、[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)、
[org.json](https://github.com/stleary/JSON-java)。

## 免责声明

本项目仅供学习与研究网络协议、Android 系统机制使用。请遵守当地法律法规以及你所使用网络服务商的条款，
不要用于任何未经授权的用途。使用本软件产生的一切后果由使用者自行承担。
