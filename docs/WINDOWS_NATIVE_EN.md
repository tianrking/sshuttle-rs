# Windows Native Dataplane (English)

[中文](WINDOWS_NATIVE_CN.md)

## Scope

This worker path provides in-process WinDivert packet interception and redirect behavior for transparent mode.

## Required Files

- `WinDivert.dll`
- matching driver file, usually `WinDivert64.sys` on x64

Put these files beside `sshuttle-rs.exe` (or use `WINDIVERT_PATH` during build/runtime setup).

## Runtime Requirements

- Run with Administrator privileges.
- Transparent mode enabled (`--mode transparent --platform windows`).

## Current Behavior

- TCP outbound packets: redirected to `--listen`.
- UDP DNS packets (`dst:53`) when `--dns-capture`: redirected to `--dns-listen`.
- UDP selected ports when `--udp-capture --udp-port ...`: redirected to `--udp-listen`.
- Policy and bypass-process list are evaluated before redirect.
- Policy reload is supported when policy file mtime changes.

## Notes

- Native dataplane currently focuses on IPv4 network layer interception.
- External `sshuttle-rs-windivert.exe` remains a fallback path.
- Linux remains first-class and uses iptables/nft redirection with the same policy validation semantics.
