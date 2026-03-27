# sshuttle-rs Architecture Draft

## 1. Why rewrite in Rust

Conclusion: **worth it**, if目标是“长期可维护 + 跨平台 + 高并发低开销”的通用透明代理内核。

Reasons:
- Existing sshuttle is Python and mature, but platform firewall backends are fragmented; Windows support is still experimental.
- A Rust core can make transport path (accept/connect/relay/protocol parse) predictable and efficient.
- Strong typing and ownership model reduce long-running daemon failure modes (resource leak, race, half-close edge cases).
- A pluggable backend architecture can preserve sshuttle philosophy while enabling Windows/Linux parity over time.

Not worth rewriting if:
- You only need current Linux/macOS workflows and can tolerate Python runtime and existing operational model.

## 2. Existing sshuttle (Python) architecture summary

Core split in upstream `sshuttle`:
- `client.py`: local listeners, ssh transport bootstrap, firewall coordination.
- `firewall.py`: privileged process, apply/cleanup firewall rules.
- `server.py`: remote side socket proxy and DNS/UDP handlers.
- `ssnet.py`: mux protocol and channel state machine.
- `methods/*`: OS-specific transparent redirect backends.

Backend capability snapshot:
- Linux `nat/nft`: TCP + DNS (+ IPv6, no UDP for nat/nft).
- Linux `tproxy`: TCP + UDP + DNS (+ IPv6).
- BSD/macOS `pf`: TCP + DNS (+ IPv6).
- Windows `windivert`: **experimental**, currently TCP/IPv4 only (no UDP/DNS/IPv6).

## 3. sshuttle-rs target architecture

### 3.1 Layering

- `control plane`
  - CLI/config validation
  - lifecycle orchestration (apply rules, run, cleanup)
- `data plane`
  - transparent TCP listener
  - SOCKS5 upstream dial/connect
  - bidirectional relay + graceful shutdown
- `platform backends`
  - Linux redirect backend (iptables now; nft/tproxy later)
  - Windows backend (`system-proxy` now, transparent with WinDivert/WFP later)

### 3.2 Key design choices

- Keep transport core platform-agnostic; isolate privileged/network-stack specifics in backend traits.
- Start with `SOCKS5 as upstream` mode; this directly addresses “convert local socks5 into global proxy”.
- Build with explicit `apply/cleanup` rule lifecycle and dry-run mode for safe rollout.

## 4. Implemented in this phase

- Rust project scaffold with modular layout.
- CLI `run` mode with two modes: `transparent` / `system-proxy`.
- Linux backend (`iptables` chain orchestration in nat/OUTPUT).
- Transparent TCP listener.
- Linux original destination extraction (`SO_ORIGINAL_DST`).
- SOCKS5 CONNECT handshake + relay.
- Windows system-proxy MVP (WinINET registry toggle with cleanup).
- Ctrl+C graceful cleanup path.

## 5. Current limitations

- Linux data plane currently supports TCP transparent redirect (IPv4 path validated by implementation strategy).
- DNS/UDP not implemented in Rust phase-1.
- Windows transparent backend is still planned (WinDivert/WFP).
- No remote embedded server/mux protocol yet (current mode relies on existing SOCKS5 upstream).

## 6. Roadmap

- Milestone A (done): Linux TCP transparent-to-SOCKS5 MVP.
- Milestone B (in progress): Windows system-proxy MVP for practical daily usage.
- Milestone C: nftables backend + IPv6 original-dst path.
- Milestone D: UDP/DNS interception strategy (TPROXY/WFP-compatible abstraction).
- Milestone E: Windows transparent backend (WinDivert/WFP) with connection tracking.
- Milestone F: optional SSH transport mode for sshuttle compatibility (client/server mux in Rust).

## 7. Recommended product direction

If your business goal is a reusable “global proxy conversion engine”:
- Prioritize Linux+Windows parity over cloning all sshuttle flags first.
- Keep first stable product focused: TCP global redirect + robust bypass rules + observability.
- Add DNS/UDP as second phase with explicit user expectations.
