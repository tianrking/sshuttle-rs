# sshuttle-rs

Rust rewrite draft focused on a practical objective:

- turn an existing SOCKS5 proxy into a system-wide transparent TCP proxy backend,
- with a clean cross-platform architecture (Linux implemented first, Windows planned).

## Run (dry-run)

```bash
cargo run -- run --mode transparent --socks5 127.0.0.1:1080 --listen 127.0.0.1:18080 --dry-run
```

## Linux transparent mode (apply iptables rules)

```bash
sudo cargo run -- run --mode transparent --socks5 127.0.0.1:1080 --listen 127.0.0.1:18080
```

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
  --socks5 127.0.0.1:1080 \
  --listen 127.0.0.1:18080
```

## Linux transparent mode with DNS capture

```bash
sudo cargo run -- run \
  --mode transparent \
  --socks5 127.0.0.1:1080 \
  --listen 127.0.0.1:18080 \
  --dns-capture \
  --dns-listen 127.0.0.1:15353 \
  --dns-upstream 1.1.1.1:53 \
  --dns-via-socks true
```

## Windows system-proxy mode (MVP)

```powershell
cargo run -- run --mode system-proxy --platform windows --socks5 127.0.0.1:1080
```

Stop with Ctrl+C; cleanup will restore registry proxy settings.
The app now snapshots previous `ProxyEnable/ProxyServer` and restores them on exit.

## Windows transparent mode (worker command bridge)

```powershell
cargo run -- run `
  --mode transparent `
  --platform windows `
  --socks5 127.0.0.1:1080 `
  --win-transparent-cmd "my-windivert-worker.exe --listen {listen_port} --socks {socks_addr}"
```

Supported placeholders in command templates:
- `{listen_port}`
- `{socks_host}`
- `{socks_port}`
- `{socks_addr}`

## Status

- Linux backend: implemented (iptables OUTPUT redirect chain).
- Linux backend: dual-stack rule engine (`iptables` + `ip6tables`).
- Linux backend selector: `auto | iptables | nft`.
- Transparent TCP relay to SOCKS5: implemented.
- Optional SSH dynamic tunnel bootstrap (`ssh -N -D`): implemented.
- DNS capture (Linux): implemented (`udp/53` redirect + local DNS forwarder).
- Windows backend:
  - system-proxy mode: implemented (registry-based WinINET proxy toggle).
  - transparent mode: worker-command bridge implemented; native WinDivert/WFP backend is next.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architecture and roadmap.
