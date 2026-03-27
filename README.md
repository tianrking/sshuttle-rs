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

## Windows system-proxy mode (MVP)

```powershell
cargo run -- run --mode system-proxy --platform windows --socks5 127.0.0.1:1080
```

Stop with Ctrl+C; cleanup will restore registry proxy settings.

## Status

- Linux backend: implemented (iptables OUTPUT redirect chain).
- Transparent TCP relay to SOCKS5: implemented.
- Windows backend:
  - system-proxy mode: implemented (registry-based WinINET proxy toggle).
  - transparent mode: planned (WinDivert/WFP).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architecture and roadmap.
