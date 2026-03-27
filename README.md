# sshuttle-rs

Rust rewrite draft focused on a practical objective:

- turn an existing SOCKS5 proxy into a system-wide transparent TCP proxy backend,
- with a clean cross-platform architecture (Linux implemented first, Windows planned).

## Run (dry-run)

```bash
cargo run -- run --socks5 127.0.0.1:1080 --listen 127.0.0.1:18080 --dry-run
```

## Run (apply Linux iptables rules)

```bash
sudo cargo run -- run --socks5 127.0.0.1:1080 --listen 127.0.0.1:18080
```

Stop with Ctrl+C; cleanup will try to remove inserted rules.

## Status

- Linux backend: implemented (iptables OUTPUT redirect chain).
- Transparent TCP relay to SOCKS5: implemented.
- Windows backend: planned (interface exists, implementation pending).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architecture and roadmap.