# Change Card：smb-null-session 删除 + smb-detect 结构化收紧

**关联任务书**：`docs/smb-null-session-echo-false-positive-fix-brief.md`
**状态**：已完成（待编排方 review/commit）
**日期**：2026-08-26

## 变更对象

- `network/misconfig/smb-null-session.yaml` —— **删除**
- `network/detection/smb-detect.yaml` —— 重写（双请求 + binary 锚点）
- `workflows/smb.yaml` —— 去掉 null-session 子模板线，仅保留 detect
- `tests/fixtures/smb-harness.py` —— 新增（5 场景红绿 harness）

不触及：`.dsh/`、`capabilities/rights/provenance.json`（沿用 kafka 任务先例：全仓
provenance 均 held、catalog 为空，删除/修改模板不触碰生成流程产物；provenance 中
smb-null-session 条目成为悬挂记录，无害）。

## 红阶段（修复前固化）

纯 TCP echo（127.0.0.1:14455）上 nuclei 实跑：

- 旧 smb-detect：`[smb-detect] [tcp] [info]` 命中（word "SMB"/"NT LM" 均在请求字节中）
- 旧 smb-null-session：`[smb-null-session] [tcp] [medium]` 命中（run1 误报源复现）

## 设计与实现

smb-detect 重写为两个独立 tcp 请求（各自独立评估，任一命中即报），全部锚点走
`type: binary` + **显式 `part: raw`**：

1. **请求 1（多协议探针，73B，flags2=0x01c8 无扩展安全位）**：方言 NT LM 0.12 /
   SMB 2.002 / SMB 2.???。SMB2+ 服务器回 `\xfeSMB` 帧 negotiate 响应，锚点
   `fe534d424000`（协议 ID FE 'S' 'M' 'B' + StructureSize 0x0040）。
2. **请求 2（SMB1 方言表探针，137B，flags2=0x53c8 扩展安全位）**：SMB1 能力开启的
   服务器回 NT LM 0.12 选中响应，锚点 AND 联立：`ff534d427200000000`（SMB1
   negotiate 响应帧头；echo 也含此串，故必须联立）+ `110500`（WordCount=0x11 +
   DialectIndex=0x0005，固定方言表决定，请求与回显中均不存在）。

实施期新发现（均实测 nuclei v3.11.1，已写进模板注释）：

- **network 模板 binary matcher 必须显式 `part: raw`**，否则不参与匹配（默认 part
  不含原始响应）。无 part 的官方 `dionaea-smb-honeypot-detect.yaml` 的 binary
  matcher 实际不生效——名存实亡再添一例。
- 两种探针标志位互斥：扩展安全位 + SMB2 过渡方言 → Samba 4.19 直接 RST（任务书
  E10 已记）；SMB1 选中只能走扩展安全位探针。
- `server max protocol = NT1` 的 Samba 4.19 对两种探针都回"无方言"41B 拒绝帧
  （WordCount=1 + DialectIndex=0xFFFF）——纯 SMB1-only 老栈（Win2000/XP 时代）
  本环境无法构造正例，属已知未覆盖缺口（模板注释已记）。
- tcp 多请求确认为逐请求独立评估（与 http 一致）：NT1 靶机上两个请求各报一次 match。
- harness replay 常量必须程序化写入（两次人工转抄 hex 各错 4/15 字节，均被长度
  断言拦截）。

## 测试矩阵

### tests/fixtures/smb-harness.py（fixture，宿主直连 listener，E13 口径）

| 场景 | 期望 | 结果 |
|---|---|---|
| echo（run1 误报源） | 不命中 | PASS |
| 445 上 HTTP（正文含 "SMB" 字样） | 不命中 | PASS |
| 非 SMB 二进制应答 | 不命中 | PASS |
| smb2-only-replay（请求1 路径，206B 真实字节） | 命中 | PASS |
| smb1-capable-replay（请求2 路径，163B 真实字节） | 命中 | PASS |

replay 字节为 2026-08-26 Samba 4.19.9（Alpine 3.20）实测抓包原样字节，按到达
探针分发（模拟服务器类别）。

### 真实靶机（nuclei 容器 → 靶机容器网络直连）

| 目标 | 结果 |
|---|---|
| 自建 Samba 4.19.9 默认配置（min SMB2） | 命中 1 次（请求1 路径，206B 帧） |
| 自建 Samba 4.19.9 NT1 开放（min NT1） | 命中 2 次（双路径各一次） |
| 本机既有 `lab-samba`（dperson/samba 镜像，异构部署） | 命中 1 次 |
| `lab-nginx`（:80） | 不命中 |
| `lab-tomcat`（:8080） | 不命中 |
| `lab-grafana`（:3000） | 不命中 |

依据铁律 3（3 台真实 Samba 正例 + 3 个真实非 SMB 反例 + fixture 反例），
`metadata.verified: true`。任务书 E13 的"容器路径读不到"在健康 daemon 靶机 +
`part: raw` 后未复现（此前失败包含无 part 的 matcher 因素）。

## 门禁

- `nuclei -validate -t network/detection/smb-detect.yaml` 通过。
- `nuclei -validate -t <repo>/http -t <repo>/network -t <repo>/javascript` 通过。
- workflows 口径：临时按 README 安装模型建符号链接后
  `nuclei -validate -t RBKD-templates/workflows`，除 **既有问题** 外通过：
  `workflows/tomcat.yaml` 引用的官方模板 `http/exposed-panels/apache/public-tomcat-manager.yaml`
  在官方仓库 v10.4.8 已不存在（路径挪位）。该文件本任务未触碰，属遗留缺口，建议
  编排方另开小票修路径。校验后符号链接已移除（环境还原）。
- `uv run python scripts/validate_templates.py` 通过；
  `uv run python scripts/test_template_gates.py` 2/2；
  `python3 scripts/test_safety_invariants.py` ok；
  `git diff --check` 干净。

## 不做的事

- 不修 `workflows/tomcat.yaml`（超出本任务 owned paths，见上）。
- 不动 provenance.json/catalog 生成产物与 `.dsh/`。
- 不向 projectdiscovery 上游报修（任务书列为编排方可选项；本次新发现的
  dionaea binary matcher 无 part 不生效可一并上报）。
- 本任务内不执行任何 git 提交/推送。

## 清理

自建靶机容器 rbkd-smb-t4/t5/t6 已删除；临时文件 /tmp/smb-* 已清理；用户 lab-*
容器仅只读探测，未改动。
