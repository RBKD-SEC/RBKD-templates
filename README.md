# RBKD Nuclei Templates

本仓库为 RBKD-SEC 团队自定义的 Nuclei 模板集合，用于**内网安全风险发现**。

仓库地址：https://github.com/RBKD-SEC/RBKD-templates

## 使用方式

> ⚠️ **不要直接 clone 到官方 `nuclei-templates/` 目录内部**：`nuclei -update-templates`
> 会执行孤儿清理（删除官方 release 之外的所有模板文件），本仓库会被当作孤儿删除。
> 采用「物理分离 + 符号链接」方式安装可彻底规避。

### 安装

```bash
# 1. 克隆到官方 nuclei-templates 目录之外
git clone https://github.com/RBKD-SEC/RBKD-templates ~/RBKD-templates

# 2. 在官方模板目录内建立符号链接
#    （workflow 用形如 template: RBKD-templates/http/xxx.yaml 的相对路径引用子模板，
#     该路径以官方模板目录为基准解析，必须通过符号链接桥接）
ln -s ~/RBKD-templates ~/nuclei-templates/RBKD-templates

# 3. 让 nuclei 同时加载官方与 RBKD 两个目录（编辑 nuclei 配置：
#    macOS ~/Library/Application Support/nuclei/config.yaml，
#    Linux ~/.config/nuclei/config.yaml）
#    templates:
#      - ~/nuclei-templates
#      - ~/RBKD-templates
```

最终结构：
```text
~/nuclei-templates/            # 官方模板
├── http/
├── ...
└── RBKD-templates -> ~/RBKD-templates   # 符号链接，桥接 workflow 相对路径

~/RBKD-templates/              # 本仓库（独立 git 仓库，在官方目录之外）
├── http/
├── network/
└── workflows/
```

为什么符号链接不会被删除：nuclei 的孤儿清理用 `filepath.WalkDir` 遍历，
**不跟随符号链接目录**，且符号链接本身不是 `.yaml` 文件，既不会被当作孤儿，
也不会被递归清理。因此 `nuclei -update-templates` 对该符号链接完全安全。

更新方式：
- **官方模板**：`nuclei -update-templates` 或 `cd ~/nuclei-templates && git pull`
- **RBKD**：`cd ~/RBKD-templates && git pull`

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

# 按服务名调用对应 workflow
# 注意：加载 workflow 必须用 -workflows，不能用 -t
# （nuclei 用 -t 加载单个 workflow 文件会提示 "no templates provided"）
nuclei -l tomcat-targets.txt -workflows ~/RBKD-templates/workflows/tomcat.yaml -rlm 30 -j -o results/tomcat.json
nuclei -l redis-targets.txt -workflows ~/RBKD-templates/workflows/redis.yaml -rlm 30 -j -o results/redis.json

# ICS/SCADA 专项（单线程，低速率）
nuclei -l ics-targets.txt -workflows ~/RBKD-templates/workflows/s7comm.yaml -c 1 -rlm 10 -j -o results/s7comm.json

# 按 tag 直接加载官方 + RBKD 的所有相关模板（依赖上面的 config 配置）
nuclei -tags ssh -l targets.txt -rlm 30 -j -o results/ssh.json

# 验证全部模板语法
nuclei -validate -t ~/RBKD-templates
```

## 参考

- [Nuclei Templates 官方仓库](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei 官方文档](https://docs.projectdiscovery.io/tools/nuclei/overview)
