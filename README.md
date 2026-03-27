# sshuttle-rs

[中文说明](README_CN.md)

A Rust-based transparent proxy orchestrator that can convert an upstream proxy into system-wide routing, with platform backends for Linux and Windows.

## Highlights

- Upstream proxy types: `socks5`, `socks4`, `http` (CONNECT)
- Linux transparent backend: `iptables/ip6tables` and `nft` selector
- Linux bypass controls: `--bypass-uid`, `--bypass-gid`
- Windows modes:
  - `system-proxy` (WinINET registry)
  - `transparent` (built-in native worker minimal + external worker override)
- DNS capture: optional (`--dns-capture`), SOCKS5 UDP path supported
- Operations helpers: `doctor`, `cleanup`

## Quick Start

```bash
cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --listen 127.0.0.1:18080
```

UDP capture (non-DNS) example on Linux:

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

## Process Bypass (Any Program)

Linux (kernel-level owner match):

```bash
sudo cargo run -- run \
  --mode transparent \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --bypass-uid 1001 \
  --bypass-gid 1001
```

Windows (transparent mode; passed to worker/native backend):

```powershell
cargo run -- run `
  --mode transparent `
  --platform windows `
  --proxy 127.0.0.1:1080 `
  --proxy-type socks5 `
  --bypass-process "program-a.exe" `
  --bypass-process "program-b.exe"
```

## Command Examples

Dry-run:

```bash
cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --dry-run
```

Doctor:

```bash
cargo run -- doctor --mode transparent --platform auto --linux-backend auto --dns-capture
```

Cleanup:

```bash
cargo run -- cleanup --mode transparent --platform auto --listen 127.0.0.1:18080
```

## Capability Matrix

| Capability | Linux | Windows |
|---|---|---|
| Transparent TCP redirect | Yes | Yes (native worker minimal / external worker) |
| Per-process bypass | Yes (`uid/gid`) | Yes (`--bypass-process` in transparent mode) |
| DNS capture | Yes | Depends on transparent backend worker/native dataplane |
| UDP capture (non-DNS) | Linux first version (SOCKS5 upstream + selected UDP ports) | Planned in native WinDivert/WFP dataplane |
| Upstream socks5/socks4/http | Yes | Yes |

## CI / Release

CI runs:
- `cargo check`
- `cargo test`
- `cargo clippy -D warnings`

Release is tag-driven (`v*`) with multi-arch artifacts.

Build matrix:
- Linux AMD64: `x86_64-unknown-linux-gnu`
- Linux ARM64: `aarch64-unknown-linux-gnu`
- Linux ARM32: `armv7-unknown-linux-gnueabihf`
- Windows AMD64: `x86_64-pc-windows-msvc`
- Windows ARM64: `aarch64-pc-windows-msvc`
- Windows 32-bit x86: `i686-pc-windows-msvc`

## Architecture

- [Architecture (English)](docs/ARCHITECTURE_EN.md)
- [架构说明（中文）](docs/ARCHITECTURE_CN.md)
