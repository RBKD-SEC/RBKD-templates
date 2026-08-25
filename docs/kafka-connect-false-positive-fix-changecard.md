# Change Card：kafka-connect-exposed 两阶段证据链收紧

**关联任务书**：`docs/kafka-connect-false-positive-fix-brief.md`
**状态**：已完成（待编排方 review/commit）
**日期**：2026-08-25

## 变更对象

`http/exposures/kafka-connect-exposed.yaml`（仅此文件 + 测试 fixture；workflow 调用方式不变，无需改动 `workflows/kafka.yaml`）。

## 现状与差距

当前实现为 f2ecdf2（08-25 13:22）第一轮收紧后的**单请求**版本：`GET /` 命中
`version`+`commit`+`kafka_cluster_id` 指纹即报警。任务书（08-25 20:25，晚于
f2ecdf2）要求**两阶段 AND 证据链**。实质差距在任务书反例 4：

> Kafka Connect root 可识别但 `/connectors` 返回 401/403

当前版本在此场景**误报**（未验证枚举接口是否真的无需认证），本变更消除。

任务书 TDD 第 1 条要求"证明当前模板命中普通 `200 []` 反例"——该写法针对
f2ecdf2 之前的旧版本（裸 `[`/`]` body 特征）。裸方括号误报已在 f2ecdf2 消除；
本轮 harness 以反例 4 为"当前真实误报"复现红，其余反例一并纳入回归矩阵。

## 设计

两个 http 请求块顺序执行（nuclei 多请求链式语义：前一请求 matcher 失败即
中止、整体不命中），全部属于同一 `{{BaseURL}}`：

1. **Stage 1 — 识别 Kafka Connect worker**：`GET {{BaseURL}}/`，
   `status 200` AND `Content-Type 含 application/json` AND body 正则
   `^\s*\{` + `"version":"..."` + `"commit":"..."` + `"kafka_cluster_id"`
   （根为 JSON object 且含 Connect 根响应三稳定字段）。
2. **Stage 2 — 确认枚举暴露**：`GET {{BaseURL}}/connectors`，
   `status 200` AND `Content-Type 含 application/json` AND body 正则
   `^\s*\[` AND `\]\s*$`（根值为 array，空数组 `[]` 亦命中）。

其他调整：

- `info.name` 按任务书明确为"未授权可访问"语义（不提升为 RCE），
  `description` 同步；`severity: medium` 不变。
- `metadata.max-request: 2`（两阶段共 2 个 GET）。
- **移除 `stop-at-first-match`**：多请求模板中该标志存在第一阶段命中即中止
  链式执行的风险（会重新引入反例 4 误报）；本模板非弱口令，无铁律强制，
  由 harness 实证取舍。
- `metadata.verified` 维持 `false`，除非容器化 Connect 正例 + 反例实测通过。
- regex 仅用 ASCII 字节（≤0x7f），规避高字节 UTF-8 码点陷阱。

## 测试矩阵（tests/fixtures/kafka-connect-harness.py）

| 场景 | `/` | `/connectors` | 预期 |
|---|---|---|---|
| positive（有 connector） | Connect 根指纹 | `["file-source"]` | 命中 |
| positive-empty | Connect 根指纹 | `[]` | 命中 |
| neg-401（任务书反例4） | Connect 根指纹 | 401 JSON | 不命中（当前版误报点） |
| neg-plain-rest（反例1） | `200 []` | 404 | 不命中 |
| neg-html（反例2） | HTML 含 `[` `]` | — | 不命中 |
| neg-other-product（反例3） | 其他产品 JSON 指纹 | `["a"]` | 不命中 |
| neg-object / neg-string / neg-malformed（反例5） | Connect 根指纹 | JSON object / 字符串 / 畸形 | 不命中 |

harness 用 Python 标准库起多端口 fixture 服务，逐场景跑 nuclei 断言命中与否，
任一不符 exit 1。

## 已知缺口（如实记录）

- 任务书 Entry condition 所列 `TEMPLATE_GUIDE.md`、`SCAN_POLICY.md` 在本仓
  不存在（全仓 find 确认），以 `AGENTS.md` + `README.md` 约定代替。
- 任务书验证步骤所列 `scripts/lint-ids.sh` 不存在；等价门禁为
  `python scripts/validate_templates.py`（含 duplicate-id 检查），
  另跑 `test_template_gates.py`。
- capability catalog 仅收 provenance `accepted` 模板，当前全 `held`、catalog
  为空，本变更不触及生成流程产物。

## 查重结论

官方 nuclei-templates 无 Kafka Connect REST API 本体暴露检测：
`exposed-panels/kafka-connect-ui.yaml` 仅匹配 UI 面板 `<title>`；
CVE-2023-25194 等为漏洞利用模板。本仓模板是有效补充，保留并收紧。

## 不做的事

- 不改 `workflows/kafka.yaml`（模板 id/路径不变）。
- 不动 `.dsh/` 及其他用户未跟踪修改。
- 本任务内不执行任何 git 提交/推送。

## 实施结果与实测记录（2026-08-25）

### 实现要点（与设计的差异）

设计稿的"中间请求 internal matcher 作门"在 nuclei v3.11.0 实测**不成立**：
多请求模板为逐请求独立评估——中间 matcher 通过即独立报 match（OR 输出），
失败也不会中止后续请求。最终实现改为**internal extractor 变量传递**：

- Stage 1 `GET /` 用三个 internal regex extractor 提取
  `version`/`commit`/`kafka_cluster_id` 为动态变量（不放 matcher）；
- Stage 2 `GET /connectors` 的 matcher 组（status + Content-Type + 根值
  array 正则）追加 DSL 断言三个变量全部提取成功，`matchers-condition: and`
  汇总两阶段证据。

两个 nuclei 语义陷阱（均已 harness 实证并规避）：

1. dsl matcher 内多表达式默认 OR——必须显式 `condition: and`，否则任一
   变量提取成功即放行（neg-other-product 曾因此漏防）。
2. 变量未提取时 `{{name}}` 的展开行为不确定（字面量保留或空串）——DSL
   同时断言 `len>0` 与 `!contains('{{')`，两种实现下均判 false。

### TDD 结果

`python3 tests/fixtures/kafka-connect-harness.py`（9 场景，nuclei 实跑断言）：

- 红阶段（修复前单请求版）：neg-401 / neg-json-object / neg-json-string /
  neg-malformed 共 4 场景误报；
- 绿阶段（本实现）：**9/9 通过**（2 正例命中、7 反例不命中，覆盖任务书
  5 类必测反例；反例 4/5 无法用现成真实软件构造，由受控 fixture 承担）。

### 门禁

- `nuclei -validate -t http/exposures/kafka-connect-exposed.yaml` 通过。
- `nuclei -validate -t http -t network -t javascript -t workflows` 通过
  （全仓口径；裸 `-t .` 会因 `.dsh/worktrees/` 用户工作树内重复 id 报错，
  与 `validate_templates.py` 门禁口径一致地排除）。
- `uv run python scripts/validate_templates.py` 通过；
  `uv run python scripts/test_template_gates.py` 2/2；
  `python3 scripts/test_safety_invariants.py` ok。

### 真实靶机实测（verified: true 依据）

- 环境：confluentinc/cp-kafka-connect:**7.6.0-ccs**（commit
  1991cb733c81d6791626f88253a042b2ec835ab8）+ cp-kafka:7.6.0 KRaft 单节点，
  docker 29.7.2 / macOS arm64；REST 端口 127.0.0.1:18083。
- `GET /` → `{"version":"7.6.0-ccs","commit":"...","kafka_cluster_id":"MkU3..."}`
  （200, application/json）；`GET /connectors` → `[]`（200, application/json）。
- 命令：`nuclei -t http/exposures/kafka-connect-exposed.yaml -u http://127.0.0.1:18083`
  → 输出 `[kafka-connect-exposed] [http] [medium] http://127.0.0.1:18083/connectors`。
- 真实反例（本机既有 lab 容器，模板仅发 2 个无副作用 GET）：
  nginx(18080)、tomcat(18081)、grafana(18082) → 全部未命中。
- 实测容器 kc-broker/kc-connect 与 kcnet 网络已清理，用户 lab-* 容器未动。

依据仓库铁律 3（真实靶场正例 + ≥3 反例实测），`metadata.verified` 置 true。
