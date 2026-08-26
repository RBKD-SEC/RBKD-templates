# SMB 模板回显误报修复任务书（smb-null-session 删除 + smb-detect 收紧）

**Category:** bug
**Status:** ready-for-agent; implementation change card required
**日期:** 2026-08-26（实证会话）

## Outcome

消除 run1 中 echo 端口命中 SMB 模板的误报源：

1. **删除** `network/misconfig/smb-null-session.yaml`——该模板只发 SMB1 negotiate，matcher
   匹配的 "NT LM" 字符串只存在于请求自身（回显唯一命中路径），对真实 SMB 结构性漏报，
   且不具备空会话判定语义；nuclei 可达的"未认证/guest 共享枚举"语义官方
   `smb-shares` 已实际覆盖（铁律 1：不建重复）。
2. **收紧** `network/detection/smb-detect.yaml`——同根因回显误报（word "SMB" OR "NT LM"
   均为请求自带字节），改为真实 SMB 协商响应的结构指纹（binary matcher + 响应独有锚点）。
3. `workflows/smb.yaml` 去掉 null-session 子模板线（该文件唯一引用点，
   `workflows/smb.yaml:13`）。

## 实证记录（2026-08-26，nuclei v3.11.1 / 官方模板 v10.4.8 / Samba 4.19.9 Alpine 3.20）

| # | 结论 | 手段与结果 |
|---|---|---|
| E1 | 本仓 smb-null-session 回显误报 | 本机 14455 纯 TCP echo 服务 + nuclei 实跑 → `[tcp][medium]` 命中（run1 现象复现） |
| E2 | 本仓 smb-detect 同根因回显误报 | 同上 → `[tcp][info]` 命中（matcher 显式 `condition: or`，"SMB"/"NT LM" 均在请求字节中） |
| E3 | 修复范式对照组 | mms-detect（f2ecdf2 后版本）对同一 echo 不命中 |
| E4 | 真实 SMB1 协商响应不含 "NT LM" | 137B 原探针 vs Samba（NT1 开放）→ 163B 响应：WordCount=0x11、DialectIndex=5——方言以**索引**返回，字符串锚点结构性漏报 |
| E5 | 现代 SMB2-only 栈对纯 SMB1 方言表不回可用指纹 | 同探针 vs 默认配置 Samba → 41B SMB1 帧错误响应（无方言选中）；早期对未改配置容器为 RST |
| E6 | 语义空洞 | 模板仅发 SMB_COM_NEGOTIATE(0x72)，无 SessionSetupAndX(0x73)——任何 SMB 实现无论 guest 策略都应答 negotiate，判不了空会话 |
| E7 | 官方 `smb-anonymous-access` 名存实亡 | 健康靶机 `-debug`：`User: " "` 命中库限制 `SMB login failed: Anonymous account is not supported yet`，success=false；matcher 另要求 response 含 IPC$ 亦不可达 |
| E8 | 官方 `smb-shares` 实际可用 | 开放靶机（map to guest=Bad User）命中 `["[IPC$ public]"]`（administrator+空密码经 guest 映射枚举成功）；收紧靶机（map to guest=Never + restrict anonymous=2）全组合不命中。判别信号为 `response != "[]"` |
| E9 | JS 库 success 标志不可单独作判据 | 收紧靶机上所有失败登录仍返回 success=true、response="[]" |
| E10 | detect 收紧设计预验 | dionaea 式探针（flags2=0x01c8 无扩展安全位，方言 NT LM 0.12 + SMB 2.002 + SMB 2.???）对三台异构 Samba（自制开放/收紧靶机 + 本机既有 `lab-samba`）统一回 206B SMB2 协商响应，帧头锚点 `fe 53 4d 42 40 00` 成立且请求/回显中不存在。注意：**带扩展安全位（flags2 0x4000）的过渡方言探针被 Samba 4.19 一致 RST，勿用**；CLEAN 探针对 lab-samba（默认禁 SMB1）只得 41B SMB1 帧错误响应 |
| E11 | 地面真值 | 容器内 smbclient：开放靶机 guest% 成功列出 public+IPC$；收紧靶机 NT_STATUS_LOGON_FAILURE |
| E12 | matcher 与传输层切分 | 将真实 163B SMB1 响应字节经本机 replay fixture 原样回放（保持连接或 FIN）→ smb-detect 均命中：word matcher 对真实响应内容本身有效；真实 smbd 路径上的不命中属传输层问题（E13），不是 matcher 问题 |
| E13 | nuclei tcp read 语义与环境矩阵（实施者必读） | 实测语义：`read: N` 等满 N 字节 **或** 对端 FIN **或** 超时截止；截止时已收部分数据仍会进 matcher（echo 137B 与 replay 163B 均在 ~5s 截止后命中），对端 FIN 则毫秒级返回。读取成败矩阵：宿主直连真实监听（python echo/replay）✓；经 Docker Desktop 端口转发（宿主 445 与 1445）✗（"could not read response"/i/o timeout，即使 python 同时可读）；nuclei 容器跨桥接 → 靶机容器：未读到数据（无报错不命中），而同路径 python 容器可读、官方 JS 模板（自管 socket）可完整会话。**含义：harness 的红绿断言用宿主直连 listener + replay fixture 承担；真实靶机验收需先解决/绕开 nuclei tcp read 与 Docker 网络的兼容性（例如可通信的 Linux 主机上直跑，或调整 read 尺寸/请求-响应节奏后复测）** |

环境陷阱（实施者必读，E13 有完整矩阵）：

- Docker Desktop 宿主端口转发对 nuclei 的 tcp 协议层读取不可靠（445 与非 445 均受影响；
  445 还会吞原始字节，见早期双向往返失败）；跨容器桥接同样读不到。harness 用宿主直连
  listener + replay fixture 做红绿断言；真实靶机验收注意环境。
- Alpine `smbd -i` 是单连接交互模式，每条连接消耗一个实例——靶机必须 `--daemon` 常驻；
  两个容器同时冷启动 `apk add` 可能网络竞态失败，需重试。
- nuclei v3.11 拒载未签名 javascript 模板（本仓 javascript/ 模板沿用既有签名/运行流程，
  本任务不新增 JS 模板）。
- 对端 FIN 会让 `read: N` 立即返回部分数据；保持连接则等满或截止。SMB 服务器答完
  negotiate 通常不主动关连接——detect 新版的 read 尺寸与命中时延要在 fixture 里实测取舍。

## Entry condition

- 阅读仓库 `AGENTS.md`、`README.md`。
- 查重已由本任务书实证节完成：官方对"未认证/guest 共享枚举"的**可用**覆盖是
  `javascript/misconfiguration/smb/smb-shares.yaml`（E8）；名义上的
  `smb-anonymous-access.yaml` 实际不可用（E7）。处理为**删除自有重复模板**，
  可选向 projectdiscovery 上游报修 smb-anonymous-access（由编排方决定，不阻塞本任务）。
- 写入前输出本仓独立 change card；实施者不是独自在仓库中工作，不得回退 `.dsh/`
  或其他用户修改。

## Owned paths

- `network/misconfig/smb-null-session.yaml`（删除）
- `network/detection/smb-detect.yaml`（收紧）
- `workflows/smb.yaml`（仅去子模板线）
- 最小正反例 fixture/harness（echo + HTTP 反例，建议 `tests/fixtures/smb-harness.py`，
  对齐 kafka-connect-harness 范式）
- 必要的模板说明/能力 catalog 与 provenance（按仓库既有生成流程处理删除与更新）

## Evidence contract（detect 新版）

- 单请求：dionaea 式 negotiate 探针（`type: hex`，flags2=0x01c8，方言
  NT LM 0.12 / SMB 2.002 / SMB 2.???）。
- 命中当且仅当响应为真实 SMB 协商响应：SMB2 家族帧头 `fe534d424000`
  （binary matcher）或 SMB1 NT LM 0.12 选中结构（WordCount=0x11 的 0x72 响应，
  锚点必须为响应独有字节）。二进制锚点一律走 `type: binary`（hex 直配，
  规避 regex/word 的 \xNN 高字节 UTF-8 码点陷阱）。
- 请求字节与任何回显服务返回内容中不得出现任一锚点（方言串 "SMB 2.002" 含空格，
  与帧头锚点天然不冲突；以 echo fixture 断言）。
- 检测与 guest 策略无关：开放与收紧两类真实 SMB 都必须命中。

## Required negative cases

1. 纯 TCP echo 服务（run1 误报源，红→绿的主断言）。
2. 445 端口上的 HTTP 服务（响应含任意 ASCII，不得命中）。
3. 非 SMB 二进制服务（可复用本仓其他 ICS 探针的误配响应 fixture）。
4. 阳性对照：SMB2-only Samba（收紧配置）与 SMB1 开放 Samba 均须命中。

## TDD and verification

1. 红：harness 证明现行 smb-detect 命中 echo 反例（E1/E2 已人工复现，固化进 fixture）。
2. 绿：新版对反例 1-3 不命中；SMB2 协商响应用 206B replay fixture 断言命中（真实
   206B 响应字节已在实证中取得），真实 Samba 靶机按 E13 环境注意事项复测。
3. `nuclei -validate -t network/detection/smb-detect.yaml`。
4. 全仓口径校验 + `python scripts/validate_templates.py` +
   `python scripts/test_template_gates.py` + `python scripts/test_safety_invariants.py`。
5. 真实靶机实测记录（容器命令、Samba 版本、nuclei 输出），补齐 `metadata.verified`
   并按铁律 3 如实标注（正例 + ≥3 反例实测通过才可 true）；若受 E13 环境限制
   无法完成 nuclei 级真靶验收，`verified` 必须保持 `false` 并在 change card 记录缺口。
6. `git diff --check`。

## Dependencies and unlock

- Blocked by: None.
- 删除模板后若 Pentest-Playbook 历史 bundle 引用了 smb-null-session，按 kafka 任务书
  先例解锁后续 bundle refresh brief；本任务不直接修改历史 bundle。
- 本任务内不执行任何 git 提交/推送。
