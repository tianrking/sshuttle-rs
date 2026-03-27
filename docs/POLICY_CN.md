# Policy 规范（中文）

[English](POLICY_EN.md)

## 目标

用一份策略文件统一决定流量动作，并保证匹配结果可预测。

## 匹配顺序

1. `priority` 越高越先匹配。
2. 同优先级按文件声明顺序（从上到下）。
3. 首条命中即生效。
4. 未命中时走 `defaults.action`。

## 动作

- `proxy`: 走上游代理路径。
- `bypass`: 绕过透明代理路径。
- `direct`: 预留给显式直连策略。
- `drop`: 预留给显式拒绝策略。

## Schema

```yaml
version: 1
defaults:
  action: proxy
rules:
  - name: "rule-name"
    action: bypass
    priority: 10
    enabled: true
    process:
      name: ["foo.exe", "bar.exe"]     # 可为字符串或数组
      path: "C:\\Program Files\\App\\a.exe"  # 可为字符串或数组
    destination:
      cidrs: ["10.0.0.0/8"]            # 可为字符串或数组
      ports: [443, 8443]               # 可为数字或数组
      proto: tcp                       # tcp / udp
```

## 校验

`doctor --policy-file ...` 会检查：

- 规则名重复
- CIDR 格式非法
- 同优先级且匹配范围重叠但动作不同（警告）

可用 `--policy-strict` 把警告提升为失败。

## 运行时说明

- `run --policy-file` 会先校验策略，再应用规则。
- Windows worker 支持按文件修改时间热重载策略。
- Windows 内置引擎当前还是最小分类/runtime 壳层；完整内置 WinDivert dataplane 是下一阶段目标。
