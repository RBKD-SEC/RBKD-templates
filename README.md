# RBKD Nuclei Templates

本仓库为 RBKD-SEC 团队自定义的 Nuclei 模板集合，用于**内网安全风险发现**。

仓库地址：https://github.com/RBKD-SEC/RBKD-templates

## 使用方式

将本仓库克隆到官方 nuclei-templates 同级目录：

```bash
cd nuclei-templates
git clone https://github.com/RBKD-SEC/RBKD-templates
```

最终目录结构：
```text
nuclei-templates/              # 官方模板
├── http/
├── network/
└── workflows/
└── RBKD-templates/            # 本仓库（自定义模板）
    ├── http/
    ├── network/
    └── workflows/
```

核心模式：**先用 nmap / httpx 识别服务，再按服务名精准调用对应 workflow**。

## 仓库结构

```text
.
├── workflows/                  # 按服务拆分的工作流
├── http/                       # HTTP 协议模板
│   ├── technologies/           # 指纹识别
│   ├── exposures/              # 敏感暴露、未授权访问
│   ├── default-logins/         # 默认口令
│   ├── vulnerabilities/        # CVE 漏洞
│   ├── misconfiguration/       # 错误配置
│   └── exposed-panels/         # 面板检测
├── network/                    # 网络协议模板
│   ├── technologies/           # 指纹识别
│   ├── misconfiguration/       # 未授权、匿名访问、错误配置
│   ├── default-logins/         # 默认口令
│   └── vulnerabilities/        # CVE 漏洞
├── javascript/                 # JavaScript 协议模板
│   └── default-logins/
├── dns/                        # DNS 模板
├── payloads/                   # 极小字典
│   ├── users-mini.txt
│   └── passwords-mini.txt
└── .github/workflows/          # CI
```

## 设计原则

- **服务精准匹配**：每个服务一个独立 workflow，直接 `template:` 引用模板路径。
- **指纹先行**：先用 nmap / httpx 识别服务，再按服务名调用对应 workflow。
- **极小字典**：弱口令模板最多 2 用户名 x 2 密码（4 次尝试），`stop-at-first-match: true`。
- **90% 复用官方**：优先复制/改造 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 官方模板。

## 快速开始

```bash
# 从官方 nuclei-templates 目录运行
cd nuclei-templates

# 服务识别
nmap -sV -p 1-65535 targets.txt -oA nmap-results
httpx -l web-targets.txt -o httpx-results.json -j

# 按服务名调用对应 workflow（RBKD-templates 为本仓库）
nuclei -l tomcat-targets.txt -t RBKD-templates/workflows/tomcat.yaml -rlm 30 -j -o results/tomcat.json
nuclei -l redis-targets.txt -t RBKD-templates/workflows/redis.yaml -rlm 30 -j -o results/redis.json

# ICS/SCADA 专项（单线程，低速率）
nuclei -l ics-targets.txt -t RBKD-templates/workflows/s7comm.yaml -c 1 -rlm 10 -j -o results/s7comm.json

# 验证全部模板语法
nuclei -validate -t RBKD-templates
```

## 参考

- [Nuclei Templates 官方仓库](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei 官方文档](https://docs.projectdiscovery.io/tools/nuclei/overview)
