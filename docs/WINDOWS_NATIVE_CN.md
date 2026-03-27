# Windows 原生数据面说明（中文）

[English](WINDOWS_NATIVE_EN.md)

## 范围

该 worker 路径在进程内使用 WinDivert 做透明模式的抓包与重定向。

## 必需文件

- `WinDivert.dll`
- 对应驱动文件，x64 一般为 `WinDivert64.sys`

建议和 `sshuttle-rs.exe` 放同一目录（或通过 `WINDIVERT_PATH` 完成构建/运行配置）。

## 运行要求

- 必须管理员权限运行。
- 使用透明模式（`--mode transparent --platform windows`）。

## 当前行为

- TCP 出站包：重定向到 `--listen`。
- 开启 `--dns-capture` 时，目的端口 53 的 UDP 重定向到 `--dns-listen`。
- 开启 `--udp-capture --udp-port ...` 时，对指定 UDP 端口重定向到 `--udp-listen`。
- 重定向前会执行 policy 与 `--bypass-process` 判断。
- policy 文件修改后支持热重载。

## 说明

- 当前原生数据面重点覆盖 IPv4 network layer。
- 外部 `sshuttle-rs-windivert.exe` 仍可作为回退路径。
- Linux 仍是一等支持，走 iptables/nft 重定向，policy 校验语义保持一致。
