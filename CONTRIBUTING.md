# 贡献指南

## 如何新增模板

1. 在对应协议目录下创建 `.yaml` 文件。
2. 按照 `TEMPLATE_GUIDE.md` 填写字段。
3. 本地运行 `nuclei -validate -t <文件>` 确保通过。
4. 若引用 payload 文件，实测 `nuclei -t .` 与 `nuclei -t workflows/x.yaml` 两种入口路径解析。
5. 更新 `metadata/service-map.yaml`（如适用）。
6. 提交 PR。

## PR 要求

- 单 PR 聚焦单一服务族或单一改动，避免大杂烩。
- 附带本地 `nuclei -validate -t .` 通过截图或日志。
- 若新增弱口令模板，说明尝试次数和锁定风险评估。
- 若复制官方模板，说明来源 URL 和改造点。

## 从官方模板同步

1. 在官方仓库找到目标模板，记录 commit hash。
2. 复制到本仓库对应目录。
3. 在文件顶部添加 `# Source:` 注释。
4. 保留 `info.author`，可追加本团队署名。
5. 根据内网需求做必要改造（收敛请求、补充国产设备、调整 matcher）。
6. 运行 `nuclei -validate -t <文件>`。
7. 提交 PR。

## 禁止事项

- 不要把官方大规模 CVE 模板整包复制。
- 不要提交真实扫描结果、真实账号密码、真实内网 IP。
- 不要在模板里硬编码客户环境信息。
- 不要引入破坏性验证或大字典。
