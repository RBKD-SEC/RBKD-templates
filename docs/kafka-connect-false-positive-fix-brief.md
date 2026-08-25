# Kafka Connect REST API 误报修复任务书

**Category:** bug  
**Status:** ready-for-agent; implementation change card required

## Outcome

收紧 `kafka-connect-exposed`：只有同时证明目标是 Kafka Connect worker 且 `/connectors` 枚举接口无需认证时才命中，普通 HTTP 200、JSON 数组或含方括号的页面不得命中。

## Entry condition

- 阅读仓库 `AGENTS.md`、`TEMPLATE_GUIDE.md`、`SCAN_POLICY.md` 和现有 Kafka workflow。
- 先检查官方 nuclei-templates 是否已有等价 Kafka Connect exposure 模板；若已覆盖，按仓库铁律评估删除自有重复模板，而不是继续维护重叠实现。
- 写入前输出本仓独立 change card；实施者不是独自在仓库中工作，不得回退 `.dsh/` 或其他用户修改。

## Owned paths

- `http/exposures/kafka-connect-exposed.yaml`
- `workflows/kafka.yaml`（仅调用方式确需调整时）
- 最小正反例 fixture/harness 或仓库现有模板测试位置
- 必要的模板说明/能力 catalog（按仓库既有生成流程）

## Evidence contract

- 第一条证据识别 Kafka Connect worker：请求 `/` 返回 HTTP 200 JSON object，并同时包含 Connect root response 的稳定字段 `version`、`commit`、`kafka_cluster_id`。
- 第二条证据确认枚举暴露：请求 `/connectors` 返回 HTTP 200、JSON Content-Type、根值为 array；空数组仍可表示未配置 connector 的可访问 API。
- 两条证据必须属于同一 BaseURL，且全部满足才命中；名称明确为“Kafka Connect REST API 未授权可访问”，不把它提升为 RCE。
- metadata `verified` 只有在真实 Kafka Connect 正例和至少三个反例实测后才能为 true，否则保持 false。

## Required negative cases

1. 任意返回 `200 []` 的普通 REST endpoint。
2. HTML/JavaScript 页面正文含 `[` 与 `]`。
3. Kafka UI、Kafka broker 探测页或其他产品的 `/connectors` 路由。
4. Kafka Connect root 可识别但 `/connectors` 返回 401/403。
5. `/connectors` 返回 JSON object、字符串或畸形 JSON，而不是 array。

## TDD and verification

1. 先用 fixture/harness 证明当前模板命中普通 `200 []` 反例。
2. 实现两阶段证据链，观察反例转绿、真实 Connect 正例仍命中。
3. `nuclei -validate -t http/exposures/kafka-connect-exposed.yaml`
4. 运行仓库全量 `nuclei -validate -t .` 与 `bash scripts/lint-ids.sh`。
5. 对真实或容器化 Kafka Connect 运行模板，记录目标版本、命令和结果；不把 fake server 写成实测。
6. `git diff --check`。

## Dependencies and unlock

- Blocked by: None.
- 完成并形成已批准 revision 后，解锁 Pentest-Playbook 的新 bundle refresh brief。
- 不直接修改 Pentest-Playbook 历史 bundle，也不在本任务中 commit/push。
