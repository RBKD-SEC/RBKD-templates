# Nuclei Custom Templates

本仓库存放团队自定义的 Nuclei YAML 模板，用于**内网安全风险发现**，不是通用互联网漏洞库。

核心模式：**先指纹识别服务，再精准触发对应低风险验证模板**。所有模板分为 `safe`（只读、无告警）与 `optional`（有登录尝试、可能触发锁定）两类，默认仅运行 `safe`。

## 仓库结构

目录结构遵循 [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 官方推荐规范：

```text
.
├── workflows/               # 工作流入口
│   ├── internal-full-safe.yaml
│   ├── web-services.yaml
│   └── network-services.yaml
├── fingerprints/            # 指纹识别模板
│   ├── http/
│   └── network/
├── http/                    # HTTP 协议风险模板
│   ├── exposures/           # 敏感暴露
│   ├── misconfig/           # 错误配置
│   ├── panels/              # 面板检测
│   ├── sensitive-files/     # 敏感文件
│   └── default-logins/      # 默认口令（optional）
├── network/                 # 网络协议模板
│   ├── anonymous-access/    # 匿名访问
│   ├── no-auth/             # 未授权访问
│   ├── misconfig/           # 错误配置
│   └── default-logins/      # 默认口令（optional）
├── javascript/              # JavaScript 协议模板
│   ├── default-logins/
│   ├── no-auth/
│   └── protocol-checks/
├── payloads/                # 极小字典
│   ├── users-mini.txt
│   ├── passwords-mini.txt
│   └── service-defaults/
├── metadata/                # 元数据
│   ├── service-map.yml      # 服务-模板映射
│   └── severity-policy.yml  # 严重等级策略
├── scripts/                 # 本地校验脚本
│   ├── validate.sh
│   └── lint-ids.sh
├── .github/workflows/       # CI
│   └── validate-nuclei-templates.yml
├── SCAN_POLICY.md           # 扫描安全政策
├── TEMPLATE_GUIDE.md        # 模板编写指南
├── CONTRIBUTING.md          # 贡献指南
└── README.md
```

## 设计原则

- **指纹先行**：每个服务族尽量具备指纹模板 + 风险模板 + workflow 串联。
- **极小字典**：弱口令模板严格限制为 2 用户名 × 2 密码，最多 4 次尝试。
- **命中即停**：所有 brute 模板均设置 `stop-at-first-match: true`、`threads: 1`。
- **safe / optional 分离**：
  - `safe`：只读、无登录失败计数、不触发服务端告警。可进入默认工作流。
  - `optional`：有锁定风险、有登录失败日志。仅在服务专项工作流中显式触发。
- **结果可审计**：建议所有扫描命令附加 `-o result.json -j`。
- **90% 复用官方**：优先复制/改造 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 官方模板，自研仅用于国产设备/摄像头/OA/门禁等官方未覆盖场景。

## 快速开始

### 推荐扫描命令

```bash
# 默认 safe 扫描（推荐首次使用）
nuclei -l targets.txt -t workflows/internal-full-safe.yaml -j -o results/safe.json

# Web 服务专项
nuclei -l web-targets.txt -t workflows/web-services.yaml -j -o results/web.json

# 网络服务专项
nuclei -l network-targets.txt -t workflows/network-services.yaml -j -o results/network.json

# 验证全部模板语法
nuclei -validate -t .
```

### 单模板使用

```bash
# SSH 弱口令检测（optional，需显式指定）
nuclei -t ./javascript/default-logins/ssh-mini-brute.yaml -u <target>:22 -o ssh_weak.json -j

# FTP 弱口令检测（optional）
nuclei -t ./network/default-logins/ftp-mini-brute.yaml -u <target> -o ftp_weak.json -j

# Redis 未授权检测（safe）
nuclei -t ./network/no-auth/redis-no-auth.yaml -u <target>:6379 -o redis_unauth.json -j
```

## 模板清单

完整的服务-模板映射见 [`metadata/service-map.yml`](metadata/service-map.yml)。当前覆盖的主要服务：

| 服务族 | 指纹 | Safe 风险 | Optional 风险 |
|--------|------|-----------|---------------|
| 中间件 | Tomcat, Spring Boot, Nginx, Apache | Actuator, Swagger, .git, Server Status, Directory Listing | — |
| DevOps | Jenkins, GitLab, Nexus, Harbor | Swagger, Jolokia | — |
| 监控面板 | Grafana, Kibana, Prometheus | Prometheus Metrics | — |
| 数据库 | Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch, MSSQL, ZooKeeper, Memcached | 未授权、匿名访问 | — |
| 网络协议 | SSH, FTP, SMB, Telnet, RDP, Rsync, SNMP | 匿名登录、Null Session、Public Community | Mini Brute |
| Web 通用 | Druid, PHP | 监控暴露、phpinfo | — |

> Web 表单登录爆破（Tomcat Manager / Jenkins / Grafana 等）**本轮延后**，第二轮根据实际需求补充 mini-brute 版本，且仅进入 optional 工作流。

## 扫描政策

见 [`SCAN_POLICY.md`](SCAN_POLICY.md)。核心要求：

1. 默认工作流 `internal-full-safe.yaml` **绝不包含** login brute、CVE 验证、写入型探测、Interactsh 依赖模板。
2. 弱口令模板默认最多 **4 次尝试**，必须声明 `metadata.max-request`。
3. 禁止硬编码客户环境信息、真实密码、真实内网 IP、真实扫描结果。

## 如何新增模板

1. 阅读 [`TEMPLATE_GUIDE.md`](TEMPLATE_GUIDE.md)。
2. 在对应协议目录下创建 `.yaml` 文件。
3. 本地运行 `nuclei -validate -t <文件>` 通过。
4. 若引用 `payloads/` 字典，实测 `nuclei -t .` 与 `nuclei -t workflows/x.yaml` 两种入口路径解析正确。
5. 更新 `metadata/service-map.yml`。
6. 提交 PR。

## 本地校验

```bash
# 验证全部模板语法与 schema
bash scripts/validate.sh

# 检查 id 唯一性、弱口令字段、旧目录残留
bash scripts/lint-ids.sh
```

## CI

GitHub Actions 在每次 push/PR 时自动执行：

1. `nuclei -validate -t .`
2. `scripts/lint-ids.sh`

CI 范围：**YAML 语法、schema 合法、id 唯一性、弱口令必备字段**。检测逻辑正确性不在 CI 范围，需人工 review 或 lab 环境验证。

## 参考

- [Nuclei Templates 官方文档](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Nuclei Templates 官方仓库](https://github.com/projectdiscovery/nuclei-templates)
- [`handbook/内网渗透测试手册_v2.md`](https://github.com/RBKD-SEC/Pentest-Playbook/blob/main/handbook/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E6%89%8B%E5%86%8C_v2.md)
