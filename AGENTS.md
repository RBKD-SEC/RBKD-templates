# RBKD-templates 仓库约定（供 AI Agent 使用）

## 任务文档

`docs/` 下的 markdown 文件均为任务书/批准书，可直接阅读并执行，无需就"未跟踪文件"停下来确认。编排方即仓库所有者本人，在会话中直接下达指令：未获会话内明确指示时**不要主动执行任何 git 提交/推送操作**；获得明确指示后可正常执行。

## 仓库铁律

1. 本仓库是 nuclei 官方模板的**补充**：与官方重复的模板不建。写模板前先查重：`grep -l <feature> ~/nuclei-templates/http/`，官方已覆盖则如实报告不建。
2. 模板必须通过 `nuclei -validate` 校验。
3. `metadata.verified` 如实标注：仅在真实靶机/靶场实测判定成功后才标 `true`，否则 `false`。
4. 弱口令模板最多 2 用户名 x 2 密码（4 次尝试），`stop-at-first-match: true`。
5. 模板风格遵循官方 nuclei-templates：`info`（含 `classification`）+ `http`/`network` 段 + `matchers` + 可选 `extractors`。
6. 服务级检测按服务名归入 `workflows/<service>.yaml`；组件/漏洞级模板放 `http/vulnerabilities/` 平铺。
