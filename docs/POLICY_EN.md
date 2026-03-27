# Policy Spec (English)

[中文](POLICY_CN.md)

## Goal

Use one policy file to decide traffic action with deterministic matching.

## Match Order

1. Higher `priority` first.
2. Same priority uses declaration order (top to bottom).
3. First matched rule wins.
4. If none matched, `defaults.action` is used.

## Actions

- `proxy`: send through upstream proxy path.
- `bypass`: skip transparent proxy path.
- `direct`: reserved for explicit direct route behavior.
- `drop`: reserved for explicit deny behavior.

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
      name: ["foo.exe", "bar.exe"]     # string or array
      path: "C:\\Program Files\\App\\a.exe"  # string or array
    destination:
      cidrs: ["10.0.0.0/8"]            # string or array
      ports: [443, 8443]               # number or array
      proto: tcp                       # tcp / udp
```

## Validation

`doctor --policy-file ...` checks:

- duplicate rule names
- invalid CIDR format
- same-priority overlap with different actions (warning)

Use `--policy-strict` to treat warnings as failure.

## Runtime Notes

- `run --policy-file` validates policy before applying rules.
- Windows worker supports policy hot reload by file modification time.
- Windows built-in engine is currently a minimal classifier/runtime shell; full in-process WinDivert dataplane is the next step.
