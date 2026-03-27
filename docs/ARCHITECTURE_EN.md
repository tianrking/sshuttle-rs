# Architecture (English)

## Goals

- Convert upstream proxy capability into global traffic steering with minimal operational friction.
- Keep control plane and data plane decoupled for portability and long-term maintainability.
- Support production workflows: preflight checks, safe cleanup, release pipeline, architecture matrix.

## Layered Design

- Control Plane
  - CLI parsing and validation
  - mode selection (`transparent` / `system-proxy`)
  - lifecycle orchestration (apply/start/cleanup)
- Data Plane
  - transparent TCP accept/connect/relay
  - protocol adapters (`socks5`, `socks4`, `http CONNECT`)
  - DNS capture forwarding path
  - policy evaluator runtime hooks (decision + stats)
- Platform Plane
  - Linux backend (`iptables/ip6tables` + `nft`)
  - Windows backend (`system-proxy`, transparent native WinDivert dataplane path)

## Reliability Principles

- Loop safety first
  - Linux: bypass by `uid/gid`
  - Windows: bypass process list in transparent mode
- Explicit cleanup path
  - `cleanup` command for crash/recovery workflows
- Dependency visibility
  - `doctor` command for preflight diagnostics
  - policy validation (`doctor --policy-file`, optional `--policy-strict`)

## Extensibility

- Add new upstream proxy protocols by implementing adapter modules under `src/proxy/`.
- Add platform packet engines behind current Windows/Linux backend interfaces.
- Keep policy expression in CLI/config and compile into `RulePlan` for backend execution.
- Policy supports JSON/YAML, priority ordering, conflict diagnostics, and hot-reload hooks on Windows worker.

## Current Scope

- Global TCP steering via platform redirect rules.
- Upstream types: socks5/socks4/http.
- DNS capture on Linux (with SOCKS5 UDP path).
- Windows native transparent dataplane for TCP + DNS/selected UDP redirect path.
- CI + release matrix with multi-arch artifacts.

## Next Focus

- Windows transparent dataplane from minimal worker to full WinDivert/WFP engine.
- Broader UDP transparent forwarding (beyond DNS).
- Integration and stress tests for release confidence.
