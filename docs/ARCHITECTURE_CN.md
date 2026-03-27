# 架构说明（中文）

## 目标

- 把“上游代理能力”转换成“全局流量接管能力”，并降低运维复杂度。
- 控制面与数据面解耦，保证跨平台和长期可维护性。
- 面向生产：可诊断、可清理、可发布、可多架构构建。

## 分层设计

- 控制面（Control Plane）
  - CLI 参数解析与校验
  - 模式选择（`transparent` / `system-proxy`）
  - 生命周期编排（apply/start/cleanup）
- 数据面（Data Plane）
  - 透明 TCP 接入/连接/转发
  - 协议适配器（`socks5`、`socks4`、`http CONNECT`）
  - DNS 捕获与转发路径
  - 策略评估运行时钩子（决策 + 统计）
- 平台面（Platform Plane）
  - Linux 后端（`iptables/ip6tables` + `nft`）
  - Windows 后端（`system-proxy`、transparent 原生 WinDivert 数据面路径）

## 可靠性原则

- 优先保证“防环路”
  - Linux：`uid/gid` 绕过
  - Windows：transparent 模式按进程绕过
- 显式清理能力
  - `cleanup` 命令用于异常退出后的恢复
- 依赖可见化
  - `doctor` 命令用于启动前检查
  - policy 校验（`doctor --policy-file`，可选 `--policy-strict`）

## 可扩展性

- 新增上游协议：在 `src/proxy/` 下增加适配模块。
- 新增平台包转发引擎：复用现有 Linux/Windows 后端接口。
- 策略统一在 CLI/config 表达，再编译成 `RulePlan` 下发执行。
- policy 支持 JSON/YAML、优先级排序、冲突诊断，以及 Windows worker 的热重载钩子。

## 当前范围

- 基于平台重定向规则的全局 TCP 接管。
- 上游协议：socks5/socks4/http。
- Linux DNS 捕获（含 SOCKS5 UDP 路径）。
- Windows 原生透明数据面支持 TCP + DNS/指定 UDP 重定向路径。
- 多架构 CI + Release 发布流水线。

## 下一阶段

- Windows transparent 数据面：从最小 worker 迭代到 WinDivert/WFP 完整引擎。
- UDP 透明转发泛化（不止 DNS）。
- 集成测试与压力测试，提升发布信心。
