# sshuttle-rs

Rust rewrite draft focused on a practical objective:

- turn an existing upstream proxy into a system-wide transparent TCP proxy backend,
- with a clean cross-platform architecture.

Supported upstream proxy types:
- `socks5`
- `socks4`
- `http` (CONNECT)

## Run (dry-run)

```bash
cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --listen 127.0.0.1:18080 --dry-run
```

`--socks5` is still accepted as an alias of `--proxy` for compatibility.

## Doctor (dependency preflight)

```bash
cargo run -- doctor --mode transparent --platform auto --linux-backend auto --dns-capture
```

## Cleanup (manual recover)

```bash
cargo run -- cleanup --mode transparent --platform auto --listen 127.0.0.1:18080
```

## Linux transparent mode (apply rules)

```bash
sudo cargo run -- run --mode transparent --proxy 127.0.0.1:1080 --proxy-type socks5 --listen 127.0.0.1:18080
```

Bypass specific process identities (critical for avoiding proxy-loop of your upstream proxy program itself):

```bash
sudo cargo run -- run \
  --mode transparent \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --bypass-uid 1001 \
  --bypass-gid 1001
```

Recommended pattern:
- Run your upstream proxy daemon under a dedicated Linux user (for example `proxydaemon`).
- Pass that UID/GID to `--bypass-uid/--bypass-gid`.
- Then all other processes are transparently forwarded, but that daemon itself is bypassed safely.

Use backend selection when needed:

```bash
sudo cargo run -- run --mode transparent --linux-backend nft
```

## Linux transparent mode with built-in SSH dynamic tunnel

```bash
sudo cargo run -- run \
  --mode transparent \
  --ssh-remote user@example.com \
  --ssh-cmd ssh \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --listen 127.0.0.1:18080
```

## Linux transparent mode with DNS capture

```bash
sudo cargo run -- run \
  --mode transparent \
  --proxy 127.0.0.1:1080 \
  --proxy-type socks5 \
  --listen 127.0.0.1:18080 \
  --dns-capture \
  --dns-listen 127.0.0.1:15353 \
  --dns-upstream 1.1.1.1:53 \
  --dns-via-socks true
```

Note: DNS via proxy (`--dns-via-socks`) currently requires `--proxy-type socks5`.

## Windows system-proxy mode

```powershell
cargo run -- run --mode system-proxy --platform windows --proxy 127.0.0.1:1080 --proxy-type socks5
```

Stop with Ctrl+C; cleanup restores registry proxy settings.

## Windows transparent mode (worker command bridge)

```powershell
cargo run -- run `
  --mode transparent `
  --platform windows `
  --proxy 127.0.0.1:1080 `
  --proxy-type socks5 `
  --bypass-process "my-proxy.exe" `
  --bypass-process "another-daemon.exe"
```

Default behavior now uses built-in native worker (`win-native-worker` hidden subcommand).
You can still override with external worker command via `--win-transparent-cmd`.

Supported placeholders in command templates:
- `{listen_port}`
- `{proxy_host}`
- `{proxy_port}`
- `{proxy_addr}`
- `{bypass_processes_csv}`
- `{bypass_processes_semicolon}`
- `{socks_host}` / `{socks_port}` / `{socks_addr}` (compat aliases)

## Status

- Linux backend: dual-stack (`iptables` + `ip6tables`) and `nft` selector.
- Linux per-process bypass: supported via `--bypass-uid` / `--bypass-gid`.
- Transparent TCP relay to upstream proxy: socks5/socks4/http supported.
- Optional SSH dynamic tunnel bootstrap (`ssh -N -D`): implemented.
- DNS capture (Linux): implemented (`udp/53` redirect + local DNS forwarder).
- Windows backend:
  - system-proxy mode: implemented (registry-based WinINET proxy toggle).
  - transparent mode: built-in native worker (minimal) + optional external worker override; WinDivert/WFP dataplane is next.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architecture and roadmap.

CI runs `cargo check`, `cargo test`, and `cargo clippy -D warnings` on push/PR.

## Build Matrix

- Linux AMD64: `x86_64-unknown-linux-gnu`
- Linux ARM64: `aarch64-unknown-linux-gnu`
- Linux ARM32: `armv7-unknown-linux-gnueabihf`
- Windows AMD64: `x86_64-pc-windows-msvc`
- Windows ARM64: `aarch64-pc-windows-msvc`
- Windows ARM32 (experimental): `thumbv7a-pc-windows-msvc`

Tagging `v*` triggers release artifact builds for the matrix above.
