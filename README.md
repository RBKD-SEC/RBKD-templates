# Nuclei Custom Templates

本仓库存放团队自定义的 Nuclei YAML 模板，用于**内网安全风险发现**，不是通用互联网漏洞库。

核心模式：**先用 nmap / httpx 识别服务，再按服务名精准调用对应 workflow**。每个 workflow 直接引用具体的模板文件路径，精确控制扫描范围。

## 仓库结构

```text
.
├── workflows/               # 按服务拆分的工作流（每个服务独立一个文件）
│   ├── tomcat.yaml
│   ├── spring-boot.yaml
│   ├── redis.yaml
│   ├── mysql.yaml
│   ├── jenkins.yaml
│   ├── hikvision.yaml
│   └── ...                  # 共 68 个服务 workflow
├── fingerprints/            # 指纹识别模板
│   ├── http/
│   │   ├── middleware/
│   │   ├── devops/
│   │   ├── panels/
│   │   ├── cameras/
│   │   ├── network-devices/
│   │   └── ics/
│   └── network/
│       └── ics/
├── http/                    # HTTP 协议风险模板
│   ├── exposures/           # 敏感暴露
│   ├── misconfig/           # 错误配置
│   ├── panels/              # 面板检测
│   ├── sensitive-files/     # 敏感文件
│   └── default-logins/      # 默认口令
├── network/                 # 网络协议模板
│   ├── anonymous-access/    # 匿名访问
│   ├── no-auth/             # 未授权访问
│   ├── misconfig/           # 错误配置
│   └── default-logins/      # 默认口令
├── javascript/              # JavaScript 协议模板
│   ├── default-logins/
│   ├── no-auth/
│   └── protocol-checks/
├── payloads/                # 极小字典
│   ├── users-mini.txt
│   ├── passwords-mini.txt
│   └── service-defaults/
├── metadata/                # 元数据
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

- **服务精准匹配**：每个服务一个独立 workflow，直接 `template:` 引用模板路径，不用 tags 模糊匹配。
- **指纹先行**：先用 nmap / httpx 识别服务，再按服务名调用对应 workflow。
- **极小字典**：弱口令模板严格限制为 2 用户名 × 2 密码，最多 4 次尝试。
- **命中即停**：所有 brute 模板均设置 `stop-at-first-match: true`、`threads: 1`。
- **结果可审计**：建议所有扫描命令附加 `-o result.json -j`。
- **90% 复用官方**：优先复制/改造 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 官方模板，自研仅用于国产设备/摄像头/OA/门禁等官方未覆盖场景。

## 快速开始

### 推荐扫描命令

先用 nmap / httpx 识别服务：

```bash
# 服务识别
nmap -sV -p 1-65535 targets.txt -oA nmap-results
httpx -l web-targets.txt -o httpx-results.json -j
```

然后按服务名调用对应 workflow：

```bash
# Tomcat 专项
nuclei -l tomcat-targets.txt -t workflows/tomcat.yaml -rlm 30 -j -o results/tomcat.json

# Redis 专项
nuclei -l redis-targets.txt -t workflows/redis.yaml -rlm 30 -j -o results/redis.json

# MySQL 专项
nuclei -l mysql-targets.txt -t workflows/mysql.yaml -rlm 30 -j -o results/mysql.json

# Jenkins 专项
nuclei -l jenkins-targets.txt -t workflows/jenkins.yaml -rlm 30 -j -o results/jenkins.json

# 海康威视摄像头专项
nuclei -l camera-targets.txt -t workflows/hikvision.yaml -rlm 30 -j -o results/hikvision.json

# ICS/SCADA 专项（单线程，低速率）
nuclei -l ics-targets.txt -t workflows/s7comm.yaml -c 1 -rlm 10 -j -o results/s7comm.json
nuclei -l ics-targets.txt -t workflows/modbus.yaml -c 1 -rlm 10 -j -o results/modbus.json

# 验证全部模板语法
nuclei -validate -t .
```

### 单模板使用

```bash
# SSH 弱口令检测
nuclei -t ./javascript/default-logins/ssh-mini-brute.yaml -u <target>:22 -o ssh_weak.json -j

# FTP 弱口令检测
nuclei -t ./network/default-logins/ftp-mini-brute.yaml -u <target> -o ftp_weak.json -j

# Redis 未授权检测
nuclei -t ./network/no-auth/redis-no-auth.yaml -u <target>:6379 -o redis_unauth.json -j
```

## 模板清单

| 服务 | 指纹 | 检查模板 |
|------|------|---------|
| **中间件** | | |
| Tomcat | fingerprints/http/middleware/tomcat-detect.yaml | git-config-exposed, tomcat-manager-mini-brute |
| Spring Boot | fingerprints/http/middleware/spring-boot-detect.yaml | spring-boot-actuator-exposed, swagger-ui-exposed |
| Nginx | fingerprints/http/middleware/nginx-detect.yaml | directory-listing |
| Apache | fingerprints/http/middleware/apache-detect.yaml | apache-server-status-exposed, directory-listing |
| WebLogic | fingerprints/http/middleware/weblogic-detect.yaml | weblogic-console-exposed |
| JBoss | fingerprints/http/middleware/jboss-detect.yaml | jboss-jmx-console-exposed |
| Kafka | fingerprints/http/middleware/kafka-detect.yaml | kafka-connect-exposed, kafka-unauth |
| RocketMQ | fingerprints/http/middleware/rocketmq-detect.yaml | rocketmq-console-exposed |
| **DevOps** | | |
| Jenkins | fingerprints/http/devops/jenkins-detect.yaml | swagger-ui-exposed, jenkins-mini-brute |
| GitLab | fingerprints/http/devops/gitlab-detect.yaml | — |
| Nexus | fingerprints/http/devops/nexus-detect.yaml | nexus-mini-brute |
| Harbor | fingerprints/http/devops/harbor-detect.yaml | harbor-mini-brute |
| **监控面板** | | |
| Grafana | fingerprints/http/panels/grafana-detect.yaml | grafana-mini-brute |
| Kibana | fingerprints/http/panels/kibana-detect.yaml | — |
| Prometheus | fingerprints/http/panels/prometheus-detect.yaml | prometheus-metrics-exposed |
| Zabbix | fingerprints/http/panels/zabbix-detect.yaml | zabbix-mini-brute |
| MinIO | fingerprints/http/panels/minio-detect.yaml | minio-mini-brute |
| Druid | — | druid-monitor-exposed |
| **数据库** | | |
| Redis | fingerprints/network/redis-detect.yaml | redis-no-auth, redis-acl-mini-brute |
| MySQL | fingerprints/network/mysql-detect.yaml | mysql-mini-brute |
| PostgreSQL | fingerprints/network/postgres-detect.yaml | postgres-mini-brute |
| MongoDB | — | mongodb-no-auth |
| Elasticsearch | — | elasticsearch-no-auth |
| MSSQL | fingerprints/network/mssql-detect.yaml | mssql-mini-brute |
| ZooKeeper | fingerprints/network/zookeeper-detect.yaml | zookeeper-unauth |
| Memcached | fingerprints/network/memcached-detect.yaml | memcached-unauth |
| Dameng | fingerprints/network/dameng-detect.yaml | — |
| KingBase | fingerprints/network/kingbase-detect.yaml | kingbase-mini-brute |
| Oscar | fingerprints/network/oscar-detect.yaml | — |
| **网络协议** | | |
| SSH | fingerprints/network/ssh-detect.yaml | ssh-mini-brute |
| FTP | fingerprints/network/ftp-detect.yaml | ftp-anonymous-login, ftp-mini-brute |
| SMB | fingerprints/network/smb-detect.yaml | smb-null-session |
| Telnet | fingerprints/network/telnet-detect.yaml | — |
| RDP | fingerprints/network/rdp-detect.yaml | — |
| Rsync | fingerprints/network/rsync-detect.yaml | rsync-anonymous-list |
| SNMP | fingerprints/network/snmp-detect.yaml | snmp-public-community |
| **云原生** | | |
| Docker Registry | — | docker-registry-exposed |
| Kubernetes | — | kubernetes-api-unauth |
| Docker API | — | docker-api-unauth |
| etcd | — | etcd-unauth |
| Consul | — | consul-unauth |
| RabbitMQ | — | rabbitmq-mini-brute |
| ActiveMQ | — | activemq-mini-brute |
| **摄像头** | | |
| 海康威视 | fingerprints/http/cameras/hikvision-detect.yaml | hikvision-mini-brute |
| 大华 | fingerprints/http/cameras/dahua-detect.yaml | dahua-mini-brute |
| **网络设备** | | |
| H3C | fingerprints/http/network-devices/h3c-detect.yaml | h3c-mini-brute |
| 华为 | fingerprints/http/network-devices/huawei-detect.yaml | huawei-mini-brute |
| 锐捷 | fingerprints/http/network-devices/ruijie-detect.yaml | ruijie-mini-brute |
| 深信服 | fingerprints/http/network-devices/sangfor-detect.yaml | sangfor-mini-brute |
| 天融信 | fingerprints/http/network-devices/topsec-detect.yaml | topsec-mini-brute |
| 奇安信 | fingerprints/http/network-devices/qianxin-detect.yaml | qianxin-mini-brute |
| 启明星辰 | fingerprints/http/network-devices/venustech-detect.yaml | venustech-mini-brute |
| 绿盟 | fingerprints/http/network-devices/nsfocus-detect.yaml | nsfocus-mini-brute |
| **国产中间件** | | |
| 东方通 TongWeb | fingerprints/http/middleware/tongweb-detect.yaml | tongweb-mini-brute |
| 宝兰德 BES | fingerprints/http/middleware/bes-detect.yaml | bes-mini-brute |
| 金蝶 Apusic | fingerprints/http/middleware/apusic-detect.yaml | apusic-mini-brute |
| **ICS 协议** | | |
| Modbus | fingerprints/network/ics/modbus-detect.yaml | — |
| IEC 104 | fingerprints/network/ics/iec104-detect.yaml | — |
| S7comm | fingerprints/network/ics/s7comm-detect.yaml | — |
| DNP3 | fingerprints/network/ics/dnp3-detect.yaml | — |
| CODESYS | fingerprints/network/ics/codesys-detect.yaml | — |
| MMS | fingerprints/network/ics/mms-detect.yaml | — |
| **ICS 设备** | | |
| Siemens | fingerprints/http/ics/siemens-detect.yaml | siemens-mini-brute |
| Schneider | fingerprints/http/ics/schneider-detect.yaml | schneider-mini-brute |
| ABB | fingerprints/http/ics/abb-detect.yaml | abb-mini-brute |
| Rockwell | fingerprints/http/ics/rockwell-detect.yaml | rockwell-mini-brute |
| GE | fingerprints/http/ics/ge-detect.yaml | ge-mini-brute |
| Omron | fingerprints/http/ics/omron-detect.yaml | omron-mini-brute |
| **Web 通用** | | |
| PHP | — | phpinfo-exposed, phpmyadmin-mini-brute |
| Jolokia | — | jolokia-exposed |
| Git | — | git-config-exposed |

## 扫描政策

见 [`SCAN_POLICY.md`](SCAN_POLICY.md)。核心要求：

1. 弱口令模板默认最多 **4 次尝试**，必须声明 `metadata.max-request`。
2. 禁止硬编码客户环境信息、真实密码、真实内网 IP、真实扫描结果。

## 账号锁定风险规避

爆破模板（`*-mini-brute`）采用三层防护设计，但仍需注意聚合风险。

### 模板内建防护

| 防护措施 | 说明 |
|---------|------|
| 最大尝试次数 | 4（2 用户 × 2 密码，pitchfork） |
| 命中即停 | `stop-at-first-match: true` |
| 单线程 | `threads: 1` |
| 请求 pacing | 模板无内置 delay，通过 runner 参数 `-rlm`/`-c` 控制 |

### 聚合风险

同一主机被多个模板命中时，总尝试次数 = 模板数 × 4。例如一个 workflow 包含 3 个 brute 模板打同一台目标 = 12 次登录尝试。nuclei 无模板间全局去重机制，需在 runner 层面控制。

### 运行级防护

```bash
# 普通环境：限制每分钟总请求数
nuclei -l targets.txt -t workflows/<service>.yaml -rlm 30 -j -o results/<service>.json

# ICS 环境：单独运行，单线程，低速率
nuclei -l ics-targets.txt -t workflows/s7comm.yaml -c 1 -rlm 10 -j -o results/s7comm.json
```

| 场景 | 建议参数 | 说明 |
|------|---------|------|
| 普通服务 workflow | `-rlm 30` | 每分钟最多 30 个请求 |
| ICS/SCADA 专项 | `-c 1 -rlm 10` | 单线程 + 每分钟 10 请求 |
| 网络设备专项（多模板命中同一主机） | `-rlm 20` | 降低速率防聚合 |

### 注意事项

- **ICS/SCADA 设备务必单独运行**，不与普通模板混跑。工控设备对认证请求更敏感，即使 4 次也可能导致设备异常或服务中断。
- **确认目标锁定策略**：如已知目标账号锁定阈值（如 5 次/10 分钟），应据此调整 `-rlm` 或跳过爆破。

## 如何新增模板

1. 阅读 [`TEMPLATE_GUIDE.md`](TEMPLATE_GUIDE.md)。
2. 在对应协议目录下创建 `.yaml` 文件。
3. 本地运行 `nuclei -validate -t <文件>` 通过。
4. 若引用 `payloads/` 字典，实测 `nuclei -t .` 与 `nuclei -t workflows/x.yaml` 两种入口路径解析正确。
5. 若新增了一个新服务，在 `workflows/` 下创建对应的 `<service>.yaml` workflow 文件，直接 `template:` 引用该服务相关的模板。
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
