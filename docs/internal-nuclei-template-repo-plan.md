# Internal Nuclei Template Repository Implementation Plan

本文档面向后续实现者，例如 Claude。目标是把当前仓库建设成一个适合内网安全风险发现的 nuclei 自定义模板仓库：先通过指纹识别服务，再通过 workflow 精准触发对应风险模板，覆盖常见 Web 与非 Web 服务的默认登录、空口令、弱密码、未授权访问、敏感暴露和基础错误配置。

## 1. 建设原则

### 1.1 允许复用官方模板

不是所有模板都需要从零编写。实现时优先按以下顺序处理：

1. 直接引用或复制 ProjectDiscovery 官方 nuclei-templates 中成熟模板。
2. 基于官方模板做内网化改造，例如降低请求量、收敛 matcher、补充内网常见产品指纹。
3. 对官方缺失或不适合内网 workflow 编排的场景自研模板。

复制官方模板时必须保留原作者、来源注释和原始语义，不要伪装成自研模板。具体要求：

- 模板文件顶部用注释保留来源 URL + commit hash，例如 `# Source: https://github.com/projectdiscovery/nuclei-templates/blob/<commit>/<path>.yaml`。
- `info.author` 字段保留原作者，内网化改造可追加本团队署名。
- 若模板被大幅改造，在 `info.description` 或 `metadata` 中说明改造点。

### 1.2 内网优先

模板目标不是互联网漏洞大而全，而是内网资产快速识别和低风险验证：

- 优先覆盖高频资产：中间件、数据库、DevOps 平台、运维面板、网络设备、摄像头、Windows/AD 相关服务。
- 优先验证低噪声风险：未授权访问、匿名访问、默认口令、空口令、暴露面板、敏感文件、危险调试端点。
- 避免破坏性 payload、批量爆破、大字典、写入型验证和高并发压力测试。

### 1.3 指纹先行

每个服务族应尽量具备：

- 一个或多个轻量指纹模板，放在 `fingerprints/`。
- 对应风险模板，放在 `http/`、`network/` 或 `javascript/`。
- workflow 入口，命中指纹后再触发风险模板。

不要把所有检查都堆到一个大模板里。指纹、风险验证、workflow 编排应保持分离。

### 1.4 弱口令控制

弱口令模板必须默认安全：

- 使用极小字典。
- 默认最多 4 到 6 次尝试。
- 使用 `stop-at-first-match: true`。
- 设置 `threads: 1` 或低并发。
- 在描述中明确最大尝试次数。
- 不引入外部大字典。

## 2. 目标目录结构

第一阶段实现以下目录。空目录可用 `.gitkeep` 保留。

```text
.
├── workflows/
│   ├── internal-full-safe.yaml
│   ├── web-services.yaml
│   ├── network-services.yaml
│   ├── databases.yaml
│   ├── middleware.yaml
│   ├── devops.yaml
│   └── network-devices.yaml
├── fingerprints/
│   ├── http/
│   │   ├── panels/
│   │   ├── middleware/
│   │   ├── devops/
│   │   ├── network-devices/
│   │   └── cameras/
│   ├── network/
│   └── ssl/
├── http/
│   ├── default-logins/
│   ├── exposures/
│   ├── misconfig/
│   ├── panels/
│   └── sensitive-files/
├── network/
│   ├── default-logins/
│   ├── anonymous-access/
│   ├── no-auth/
│   └── misconfig/
├── javascript/
│   ├── default-logins/
│   ├── no-auth/
│   └── protocol-checks/
├── dns/
├── payloads/
│   ├── users-mini.txt
│   ├── passwords-mini.txt
│   └── service-defaults/
├── metadata/
│   ├── service-map.yaml
│   ├── template-index.yaml
│   └── severity-policy.yaml
├── scripts/
│   ├── validate.sh
│   ├── lint-ids.sh
│   └── run-safe-scan.sh
├── tests/
│   ├── lab/
│   └── expected-results/
├── .github/workflows/
│   └── validate-nuclei-templates.yml
├── CONTRIBUTING.md
├── SCAN_POLICY.md
├── TEMPLATE_GUIDE.md
└── README.md
```

同时将 `network/default-login/` 重命名为 `network/default-logins/`，保持与现有 HTTP 和 JavaScript 目录一致。

## 3. 官方模板复用策略

### 3.1 直接复制候选

优先从官方 nuclei-templates 复用以下类型，通常只需要调整标签、描述、路径和 workflow：

- 常见 Web 面板识别。
- `.git`、`.svn`、备份文件、配置文件、目录列表等敏感暴露。
- Swagger/OpenAPI、Actuator、Jolokia、Druid、phpinfo、server-status 等暴露检测。
- Grafana、Kibana、Prometheus、Alertmanager、Docker Registry、Harbor、Nexus、Jenkins、GitLab 等未授权或默认配置检测。
- DNS zone transfer、递归解析、常见 TLS 弱配置。
- 常见 CVE 类模板中适合内网资产识别的非破坏性版本。

### 3.2 需要改造后复制的候选

以下模板通常需要改造后使用：

- 默认登录模板：收敛 payload 数量，降低尝试次数，增加锁定风险说明。
- 通用面板模板：减少误报 matcher，补充中文厂商、内网设备、版本页面路径。
- 中间件风险模板：避免写入型、命令执行型验证，优先使用只读探测。
- 需要公网域名、互联网回连、Interactsh 的模板：默认不要放入 safe workflow。

### 3.3 自研候选

以下更适合自研：

- 内网国产网络设备、堡垒机、OA、摄像头、门禁、打印机的指纹模板。
- 特定单位常见资产的默认账号组合。
- 非 Web 协议的空口令、匿名访问和 banner 判断。
- 内网 workflow 连接逻辑，例如命中特定指纹后只触发 2 到 3 个安全验证模板。

## 4. 第一阶段任务

### 4.1 仓库骨架

创建目标目录结构，并补齐以下文档：

- `SCAN_POLICY.md`
- `TEMPLATE_GUIDE.md`
- `CONTRIBUTING.md`
- `metadata/severity-policy.yaml`
- `metadata/service-map.yaml`

验收标准：

- 所有目录存在。
- 旧目录 `network/default-login/` 已迁移到 `network/default-logins/`。
- README 中的示例路径同步更新。
- `nuclei -validate -t .` 可执行，且不因路径迁移失败。

### 4.2 基础 payload

新增极小字典：

```text
payloads/users-mini.txt
payloads/passwords-mini.txt
payloads/service-defaults/ftp.txt
payloads/service-defaults/ssh.txt
payloads/service-defaults/network-device.txt
payloads/service-defaults/tomcat.txt
payloads/service-defaults/jenkins.txt
payloads/service-defaults/redis.txt
payloads/service-defaults/mysql.txt
payloads/service-defaults/postgres.txt
payloads/service-defaults/camera.txt
```

要求：

- 每个文件 2 到 6 行。
- 不放常见大字典。
- 不放客户真实密码。
- 模板引用 payload 文件时保持相对路径清晰。
- 字典路径以模板自身位置为基点。第一个引用字典的模板落地后必须实测 `nuclei -t .` 与 `nuclei -t workflows/x.yaml` 两种入口都能正确解析路径，避免后续大批量模板因路径问题失败。

### 4.3 基础指纹模板

新增第一批轻量指纹模板。

复用基调：本批 90% 应基于官方 nuclei-templates 复制并做内网化改造（收敛 matcher、降低请求量、补充国产/内网产品的路径或关键词），自研只用于国产网络设备、堡垒机、摄像头、OA、门禁、打印机等官方未覆盖的场景。从零写指纹会引入大量误报，避免这条路径。

HTTP 指纹：

- `fingerprints/http/middleware/tomcat-detect.yaml`
- `fingerprints/http/middleware/nginx-detect.yaml`
- `fingerprints/http/middleware/apache-detect.yaml`
- `fingerprints/http/middleware/spring-boot-detect.yaml`
- `fingerprints/http/devops/jenkins-detect.yaml`
- `fingerprints/http/devops/gitlab-detect.yaml`
- `fingerprints/http/devops/nexus-detect.yaml`
- `fingerprints/http/devops/harbor-detect.yaml`
- `fingerprints/http/panels/grafana-detect.yaml`
- `fingerprints/http/panels/kibana-detect.yaml`
- `fingerprints/http/panels/prometheus-detect.yaml`
- `fingerprints/http/network-devices/generic-network-device-login-detect.yaml`
- `fingerprints/http/cameras/generic-camera-login-detect.yaml`

Network 指纹：

- `fingerprints/network/ssh-detect.yaml`
- `fingerprints/network/ftp-detect.yaml`
- `fingerprints/network/telnet-detect.yaml`
- `fingerprints/network/smb-detect.yaml`
- `fingerprints/network/rdp-detect.yaml`
- `fingerprints/network/redis-detect.yaml`
- `fingerprints/network/mysql-detect.yaml`
- `fingerprints/network/postgres-detect.yaml`
- `fingerprints/network/mssql-detect.yaml`
- `fingerprints/network/mongodb-detect.yaml`
- `fingerprints/network/elasticsearch-detect.yaml`
- `fingerprints/network/zookeeper-detect.yaml`
- `fingerprints/network/memcached-detect.yaml`
- `fingerprints/network/rsync-detect.yaml`
- `fingerprints/network/snmp-detect.yaml`

验收标准：

- 每个指纹模板只做识别。
- `severity` 使用 `info`。
- tags 包含 `fingerprint`、协议、服务名和 `internal-audit`。
- matcher 至少包含一个强信号，例如 header、title、favicon hash、banner、协议响应码或固定关键词组合。

## 5. 第二阶段任务

### 5.1 Web 暴露与错误配置

优先从官方模板复制或改造：

- `http/exposures/spring-boot-actuator-exposed.yaml`
- `http/exposures/swagger-ui-exposed.yaml`
- `http/exposures/openapi-json-exposed.yaml`
- `http/exposures/jolokia-exposed.yaml`
- `http/exposures/druid-monitor-exposed.yaml`
- `http/exposures/phpinfo-exposed.yaml`
- `http/exposures/apache-server-status-exposed.yaml`
- `http/exposures/prometheus-metrics-exposed.yaml`
- `http/exposures/git-config-exposed.yaml`
- `http/exposures/svn-entries-exposed.yaml`
- `http/exposures/directory-listing.yaml`
- `http/misconfig/http-put-enabled.yaml`
- `http/misconfig/webdav-enabled.yaml`
- `http/misconfig/cors-wildcard-with-credentials.yaml`

验收标准：

- 优先只读请求。
- 不使用 destructive payload。
- 每个模板误报 matcher 不少于 2 个条件，除非官方模板已有强 matcher。

### 5.2 Web 默认登录与未授权

**本轮延后，留作第二轮完成。**

原因：内网 web 表单登录类目标（Tomcat Manager / Jenkins / Nexus / Harbor / Grafana / Kibana / Prometheus / MinIO / Nacos / Druid / phpMyAdmin / Adminer 等）大多会触发账号锁定或登录失败告警，即便 mini 字典 ROI 也偏低。这些目标的"未授权访问 / 匿名访问 / 暴露面板"维度先由 §5.1 的暴露与错误配置模板覆盖（如 Jenkins 匿名访问、Grafana 匿名访问、Prometheus 未授权 metrics、Druid 监控暴露）。Web 表单登录爆破本轮不做，第二轮根据实际需求补充 mini-brute 版本，且仅进入 optional 工作流。

HTTP Basic Auth 类（网络设备 / 摄像头）沿用现有 `http/default-logins/network-device-mini-brute.yaml`，本轮暂不扩展。非 Web 协议默认登录见 §6.2。

## 6. 第三阶段任务

### 6.1 非 Web 未授权与匿名访问

新增或复制改造：

- `network/anonymous-access/ftp-anonymous-login.yaml`
- `network/anonymous-access/rsync-anonymous-list.yaml`
- `network/anonymous-access/nfs-export-readable.yaml`
- `network/no-auth/redis-no-auth.yaml`
- `network/no-auth/mongodb-no-auth.yaml`
- `network/no-auth/elasticsearch-no-auth.yaml`
- `network/no-auth/zookeeper-unauth.yaml`
- `network/no-auth/memcached-unauth.yaml`
- `network/no-auth/docker-api-unauth.yaml`
- `network/no-auth/kubernetes-api-unauth.yaml`
- `network/misconfig/snmp-public-community.yaml`
- `network/misconfig/smb-null-session.yaml`

验收标准：

- 只执行读操作，例如 INFO、list、version、status、枚举 share。
- 不执行写入、删除、flush、set、eval、exec、upload。
- 对 UDP 服务说明误报风险。

### 6.2 非 Web 默认登录

扩展当前模板：

- 迁移 `network/default-login/ftp-mini-brute.yaml` 到 `network/default-logins/ftp-mini-brute.yaml`。
- 保留并修正 `javascript/default-logins/ssh-mini-brute.yaml`。
- 新增 MySQL、PostgreSQL、MSSQL、MongoDB、Redis ACL、Telnet、SNMP community mini 检查。

要求：

- 优先使用 nuclei 官方已有协议能力或 JavaScript 协议。
- 所有登录型模板设置低尝试次数。
- 如果服务常见账号锁定风险高，默认不加入 `internal-full-safe.yaml`，只在服务专项 workflow 中引用。

## 7. Workflow 设计

### 7.1 顶层 workflow

`workflows/internal-full-safe.yaml` 是默认入口，只包含低风险检查：

- 指纹识别。
- 未授权访问。
- 匿名访问。
- 敏感暴露。

不包含登录爆破类（含 HTTP Basic）。需要默认登录验证时，使用服务专项 workflow 显式触发，不进入 safe 链路。

不要默认包含：

- 大字典弱口令。
- 高风险 CVE 验证。
- 写入型验证。
- 需要 OAST/Interactsh 的模板。
- 可能导致账号锁定的表单登录模板。

### 7.2 服务专项 workflow

建议文件：

- `workflows/web-services.yaml`
- `workflows/network-services.yaml`
- `workflows/databases.yaml`
- `workflows/middleware.yaml`
- `workflows/devops.yaml`
- `workflows/network-devices.yaml`

每个 workflow 的逻辑：

1. 先运行对应 `fingerprints/` 模板。
2. 根据 tag 或 template id 命中对应服务。
3. 触发少量精准检查模板。

### 7.3 Workflow 验收

- 每个 workflow 能独立运行。
- workflow 不引用不存在的模板。
- workflow 中引用的模板 tags 和 id 稳定。
- README 提供每个 workflow 的推荐命令。

## 8. Metadata 设计

### 8.1 service-map.yaml

维护服务与模板关系，示例：

```yaml
redis:
  ports: [6379]
  fingerprint:
    - fingerprints/network/redis-detect.yaml
  checks:
    safe:
      - network/no-auth/redis-no-auth.yaml
    optional:
      - javascript/default-logins/redis-acl-mini-brute.yaml
  tags: [database, cache, no-auth]

jenkins:
  ports: [8080, 8081]
  fingerprint:
    - fingerprints/http/devops/jenkins-detect.yaml
  checks:
    safe:
      - http/exposures/jenkins-anonymous-access.yaml
    optional: []
  tags: [devops, ci, web]
```

### 8.2 severity-policy.yaml

建议分级：

```yaml
info:
  usage: service fingerprint, version disclosure, non-sensitive banner
low:
  usage: weak misconfiguration without direct sensitive access
medium:
  usage: sensitive exposure, anonymous read-only access, risky debug endpoint
high:
  usage: confirmed default credential, unauthenticated sensitive data, database no-auth
critical:
  usage: confirmed unauthenticated code execution or destructive administrative access
```

## 9. 模板规范

每个模板必须具备：

- 稳定唯一 `id`。
- 清晰 `info.name`。
- `author`。
- 合理 `severity`。
- `description`。
- `tags`，至少包含协议、服务、风险类型、`internal-audit`。
- `metadata.max-request`，如能估算。
- 强 matcher，避免单关键词误报。

推荐 tag：

```text
fingerprint
default-login
weak-password
anonymous
no-auth
exposure
misconfig
internal-audit
safe
optional
web
network
database
middleware
devops
network-device
camera
```

### 9.1 safe 与 optional 划线

每个非 fingerprint 模板必须在 tags 中二选一：

- `safe`：只读、无登录失败计数、不触发服务端告警。包括暴露检测、未授权访问、匿名访问、敏感文件、错误配置（只读型）。
- `optional`：有锁定风险、有登录失败日志、可能触发告警。包括默认登录、mini brute、任何登录尝试型模板。

`metadata/service-map.yaml` 的 `checks` 字段必须按 `safe` / `optional` 分组。`workflows/internal-full-safe.yaml` 只引用 safe 模板，optional 模板只在服务专项 workflow 中显式触发。

## 10. CI 与本地校验

### 10.1 scripts/validate.sh

实现：

```bash
#!/usr/bin/env bash
set -euo pipefail

nuclei -validate -t .
```

### 10.2 scripts/lint-ids.sh

检查：

- 模板 id 唯一。
- 文件名与 id 基本一致。
- 不存在 `network/default-login/` 旧目录。
- 弱口令模板必须包含 `stop-at-first-match: true`。
- 弱口令模板必须声明 `metadata.max-request`。

### 10.3 GitHub Actions

`.github/workflows/validate-nuclei-templates.yml` 应执行：

1. 安装 nuclei。
2. 运行 `nuclei -validate -t .`。
3. 运行 `scripts/lint-ids.sh`。

### 10.4 CI 范围限制

CI 只保证三件事：YAML 语法、模板 schema 合法、模板 id 唯一性 + 弱口令必备字段。模板的检测逻辑、matcher 是否能正确命中目标、是否会误报，**全部不在 CI 范围**，靠人工 review 或后期 lab 环境验证。新增模板时必须本地手动跑一次 `nuclei -validate -t <文件>` 并在测试机上至少打一发请求确认 matcher 行为，再提交 PR。

## 11. README 更新要求

README 应补充：

- 仓库定位：内网安全风险发现，不是通用漏洞库。
- 推荐扫描命令。
- workflow 使用方式。
- safe 与 optional 模板区别。
- 弱口令尝试次数政策。
- 如何新增模板。
- 如何从官方模板同步。

建议命令：

```bash
nuclei -l targets.txt -t workflows/internal-full-safe.yaml -j -o results/internal-safe.json
nuclei -l web-targets.txt -t workflows/web-services.yaml -j -o results/web-services.json
nuclei -l db-targets.txt -t workflows/databases.yaml -j -o results/databases.json
nuclei -l network-targets.txt -t workflows/network-services.yaml -j -o results/network-services.json
```

## 12. 分批提交建议

建议拆成 5 个 PR，每个 PR 独立可 review、独立可回滚：

1. `docs: add internal nuclei template repo plan` — 本计划文档（已完成）。
2. `chore: 仓库骨架 + 政策文档 + CI` — 全部目录 + `.gitkeep`、`SCAN_POLICY.md` / `TEMPLATE_GUIDE.md` / `CONTRIBUTING.md`、`metadata/severity-policy.yaml` 与 `metadata/service-map.yaml` 骨架、`scripts/validate.sh` 与 `scripts/lint-ids.sh`、GitHub Actions、`network/default-login/` → `network/default-logins/` 重命名同步改 README。验收：`nuclei -validate -t .` 通过，CI 绿。
3. `feat: MVP 模板 — 10 指纹 + 10 风险 + payload mini 字典` — 第 13 节列出的 10 指纹 + 10 风险（全部只读），payload mini 字典，模板在 service-map.yaml 中按 safe/optional 分组编入。
4. `feat: MVP workflow` — `internal-full-safe.yaml` / `web-services.yaml` / `network-services.yaml`，在测试机跑通整链路（指纹命中 → 触发对应风险）。
5. `feat: 服务族铺量` — 每个服务族单独 1 个 PR：DevOps（Jenkins / GitLab / Nexus / Harbor）、中间件（Tomcat / Nginx / Apache / Spring Boot）、数据库（MySQL / Postgres / MSSQL / Mongo / Redis / ES）、网络设备、摄像头。每族指纹 + 风险 + 加入对应 workflow + 更新 service-map.yaml。
6. `docs: README 整合更新` — workflow 用法、safe vs optional 政策、官方模板同步流程、新增模板的 checklist。

PR 之间约束：

- PR 2 不依赖任何模板内容，纯骨架。
- PR 3 必须实测 payload 字典路径解析（见 §4.2）。
- PR 4 之前不要把 optional 模板加入 `internal-full-safe.yaml`。
- PR 5 每族独立合并，不要把多族塞进一个 PR。

## 13. 第一轮最小可交付范围

如果只做一个最小可用版本，优先完成：

- 目录骨架。
- `SCAN_POLICY.md`、`TEMPLATE_GUIDE.md`、`metadata/service-map.yaml`。
- 修正 `network/default-login/` 目录命名。
- 10 个指纹模板（推荐：Tomcat / Spring Boot / Jenkins / Grafana / Kibana / Redis / MySQL / SSH / FTP / SMB）。
- 10 个低风险只读验证模板（推荐：Spring Actuator 暴露 / Swagger 暴露 / .git 暴露 / Druid 监控暴露 / phpinfo 暴露 / Redis 未授权 / MongoDB 未授权 / Elasticsearch 未授权 / FTP 匿名登录 / SMB null session）。
- 3 个 workflow：`internal-full-safe.yaml`、`web-services.yaml`、`network-services.yaml`。
- CI 校验。
- README 更新。

挑选规则：

- 10 个指纹覆盖三类协议（HTTP / Network / 公共服务），保证 workflow 在不同协议下都能跑通。
- 10 个风险全部 `safe` 标签、全部只读、全部官方有现成模板可改造。第一批不写默认登录、不写写入型探测。
- 指纹和风险一一对应（10 指纹至少能触发 10 风险中的一项），验证"指纹 → 触发风险"的链路。

最小版本的目标不是覆盖所有服务，而是验证仓库模式：指纹命中后精准触发风险模板，并且所有模板可校验、可维护、可安全运行。

## 14. 实现注意事项

- 不要引入破坏性验证。
- 不要把官方大规模 CVE 模板整包复制进来。
- 不要默认运行高风险弱口令模板。
- 不要在模板里硬编码客户环境信息。
- 不要把真实扫描结果、真实账号密码、真实内网 IP 提交到仓库。
- 新增模板后必须运行 `nuclei -validate -t .`。
- 修改 workflow 后必须检查引用路径是否存在。
- 从官方复制模板时保留版权和来源信息。

## 15. 参考来源

- ProjectDiscovery nuclei 官方文档：`https://docs.projectdiscovery.io/tools/nuclei/overview`
- nuclei 模板结构文档：`https://docs.projectdiscovery.io/templates/structure`
- nuclei workflow 文档：`https://docs.projectdiscovery.io/templates/workflows/overview`
- ProjectDiscovery 官方模板仓库：`https://github.com/projectdiscovery/nuclei-templates`
