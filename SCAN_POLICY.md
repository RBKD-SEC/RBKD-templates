# 扫描政策

本文档定义本仓库模板的扫描安全边界。所有模板和 workflow 必须遵守。

## 1. 安全分级

模板分为两类：

- **safe**：只读、无登录失败计数、不触发服务端告警。
  - 暴露检测、未授权访问、匿名访问、敏感文件、只读型错误配置。
  - 可默认进入 `internal-full-safe.yaml`。
- **optional**：有锁定风险、有登录失败日志、可能触发告警。
  - 默认登录、mini brute、任何登录尝试型模板。
  - 只在服务专项 workflow 中显式触发，不进入默认 safe 链路。

每个非指纹模板必须在 `tags` 中标记 `safe` 或 `optional`，不可省略。

## 2. 弱口令与默认登录限制

- 使用**极小字典**：最多 2 用户名 × 2 密码（4 次尝试）。
- 必须设置 `stop-at-first-match: true`。
- 必须设置 `threads: 1` 或低并发。
- 必须在 `info.description` 和 `metadata.max-request` 中声明最大尝试次数。
- **不引入**外部大字典（如 rockyou、top1000）。
- 若服务有账号锁定机制，默认不加入 `internal-full-safe.yaml`。

## 3. 禁止项

- 破坏性 payload（写入、删除、flush、set、eval、exec、upload）。
- 批量爆破、大字典、高并发压力测试。
- 需要 OAST/Interactsh 的模板放入 safe workflow。
- 可导致 RCE 或破坏性管理访问的模板放入 safe workflow。
- 硬编码客户环境信息、真实账号密码、真实内网 IP、真实扫描结果。

## 4. 指纹与风险分离

- 指纹模板只做识别，`severity: info`。
- 风险模板只做验证，不叠加识别逻辑。
- workflow 负责串联：先指纹，再触发对应风险。

## 5. 来源与版权

- 复制官方 nuclei-templates 时保留原作者、来源 URL + commit hash、原始语义。
- 内网化改造后在 `info.author` 追加本团队署名，在 `info.description` 或 `metadata` 中说明改造点。
- 禁止伪装官方模板为自研。
