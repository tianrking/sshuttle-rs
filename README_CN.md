# sshuttle-rs

[English](README.md)

这是一个基于 Rust 的透明代理编排器，可以把上游代理转换成“全局流量接管”能力，并通过 Linux/Windows 后端落地。

## 核心能力

- 上游代理类型：`socks5`、`socks4`、`http`（CONNECT）
- Linux 透明后端：`iptables/ip6tables` + `nft` 选择器
- Linux 进程绕过：`--bypass-uid`、`--bypass-gid`
- Windows 模式：
  - `system-proxy`（WinINET 注册表）
  - `transparent`（内置 native worker 最小版 + 外部 worker 覆盖）
- DNS 捕获：可选（`--dns-capture`），支持 SOCKS5 UDP 路径
- 运维命令：`doctor`、`cleanup`

## 快速开始

```bash
cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --listen 127.0.0.1:18080
```

Linux 下的 UDP 非 DNS 捕获示例：

```bash
sudo cargo run -- run \
  --mode transparent \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --udp-capture \
  --udp-listen 127.0.0.1:19090 \
  --udp-port 443 \
  --udp-port 3478
```

## 任意程序绕过

Linux（内核 owner 规则，稳定可靠）：

```bash
sudo cargo run -- run \
  --mode transparent \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --bypass-uid 1001 \
  --bypass-gid 1001
```

Windows（透明模式下传给 worker/native 后端）：

```powershell
cargo run -- run `
  --mode transparent `
  --platform windows `
  --proxy 127.0.0.1:1080 `
  --proxy-type socks5 `
  --bypass-process "program-a.exe" `
  --bypass-process "program-b.exe"
```

## 常用命令

Dry-run：

```bash
cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --dry-run
```

Doctor：

```bash
cargo run -- doctor --mode transparent --platform auto --linux-backend auto --dns-capture
```

Cleanup：

```bash
cargo run -- cleanup --mode transparent --platform auto --listen 127.0.0.1:18080
```

## 能力矩阵

| 能力 | Linux | Windows |
|---|---|---|
| 透明 TCP 重定向 | 支持 | 支持（内置 worker 最小版 / 外部 worker） |
| 按程序绕过 | 支持（uid/gid） | 支持（transparent 模式 `--bypass-process`） |
| DNS 捕获 | 支持 | 取决于 transparent worker/native dataplane |
| UDP 捕获（非 DNS） | Linux 首版可用（socks5 上游 + 指定 UDP 端口） | 计划在 WinDivert/WFP native dataplane 中实现 |
| 上游 socks5/socks4/http | 支持 | 支持 |

## CI / Release

CI 执行：
- `cargo check`
- `cargo test`
- `cargo clippy -D warnings`

Release 采用 tag (`v*`) 触发多架构构建。

当前构建矩阵：
- Linux AMD64：`x86_64-unknown-linux-gnu`
- Linux ARM64：`aarch64-unknown-linux-gnu`
- Linux ARM32：`armv7-unknown-linux-gnueabihf`
- Windows AMD64：`x86_64-pc-windows-msvc`
- Windows ARM64：`aarch64-pc-windows-msvc`
- Windows 32-bit x86：`i686-pc-windows-msvc`

## 架构文档

- [Architecture (English)](docs/ARCHITECTURE_EN.md)
- [架构说明（中文）](docs/ARCHITECTURE_CN.md)
