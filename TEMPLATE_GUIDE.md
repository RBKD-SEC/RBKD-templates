# 模板编写指南

## 1. 每个模板必须包含的字段

```yaml
id: unique-template-id

info:
  name: Human Readable Name
  author: original-author, team-name
  severity: info | low | medium | high | critical
  description: |
    一句话说明检测目标。
    若为改造模板，说明改造点。
  metadata:
    max-request: 1
  tags: protocol,service,risk-type,internal-audit,safe|optional
```

## 2. id 与文件名规范

- `id` 全局唯一，使用小写连字符。
- 文件名与 `id` 基本一致，例如 `id: redis-no-auth` → `redis-no-auth.yaml`。
- 弱口令模板命名示例：`ssh-mini-brute`、`ftp-mini-brute`。

## 3. 指纹模板规范

- `severity: info`。
- tags 必须包含 `fingerprint`、协议名、服务名、`internal-audit`。
- matcher 至少包含一个强信号（header、title、favicon hash、banner、协议响应码、固定关键词组合）。
- 只做识别，不执行风险验证。

## 4. 风险模板规范

- 优先只读请求，不使用 destructive payload。
- matcher 不少于 2 个条件（除非官方模板已有强 matcher）。
- 若引用外部 payload 文件，路径以模板自身位置为基点，使用相对路径。
- 引用 payload 的模板落地后必须实测 `nuclei -t .` 与 `nuclei -t workflows/x.yaml` 两种入口都能正确解析路径。

## 5. 弱口令模板额外要求

```yaml
attack: pitchfork
stop-at-first-match: true
threads: 1
payloads:
  username:
    - admin
    - root
  password:
    - admin
    - admin123
```

- 必须在 tags 中包含 `optional`。
- 必须包含 `metadata.max-request`。
- `info.description` 中写明 MAX N ATTEMPTS。

## 6. 来源注释

复制官方模板时，在文件顶部添加：

```yaml
# Source: https://github.com/projectdiscovery/nuclei-templates/blob/<commit>/path/to/template.yaml
# Modified: 降低请求量、补充国产设备指纹、收敛 matcher
```

## 7. 新增模板 checklist

- [ ] `nuclei -validate -t <文件>` 通过。
- [ ] `id` 未与现有模板冲突。
- [ ] tags 包含 `safe` 或 `optional`。
- [ ] 若为弱口令模板，确认 `stop-at-first-match: true` 和 `threads: 1`。
- [ ] 若引用 payload，双入口实测路径解析。
- [ ] 不硬编码客户信息、真实密码、真实 IP。
