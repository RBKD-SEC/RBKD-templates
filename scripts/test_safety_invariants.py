#!/usr/bin/env python3
"""RBKD 模板安全不变量测试。

每个自写模板的"安全声明"必须在这里钉死：判定只读性、出网阻断、
候选证据口径（Playbook ADR-0001）与请求预算。模板改动若触碰这些
属性，本测试先红。

历史注：2026-09 清仓（3a44abe）前的旧版本引用 6 个已删除模板
（vnc-mini-brute / cve-2017-7529 / webdav-anonymous-write /
cve-2014-6271-echo / samba-swat-mini-brute / cve-2024-6387），
自清仓起必然崩溃，2026-09-18 重写指向现存模板。

运行：uv run python scripts/test_safety_invariants.py（独立运行是权威
入口；pytest 收集亦可但 jsonschema 不在依赖内时以独立结果为准）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(text, *needles):
    for needle in needles:
        assert needle in text, f"missing safety invariant: {needle}"


def forbid(text, *needles):
    for needle in needles:
        assert needle not in text, f"forbidden pattern present: {needle}"


def test_generic_directory_listing():
    """目录列出：单请求、根路径、无深路径探测。"""
    t = read("http/misconfiguration/generic-directory-listing.yaml")
    require(t, "max-request: 1", "GET", "{{BaseURL}}")
    # 精度纪律：命中必须同时有索引页特征词 + 链接结构 + html 类型 + 200
    require(t, "Index of", "<a href=", "text/html", "status")
    # 只打根路径：不得出现逐级/深路径枚举或爆破字典
    forbid(t, "{{BaseURL}}/", "dirbuster", "robots.txt")


def test_ollama_push_path_traversal():
    """Ollama 遍历：registry 段钉死不可解析域名（出网阻断）、单请求、只读存在性。"""
    t = read("http/vulnerabilities/ollama-push-path-traversal.yaml")
    require(t, "max-request: 1")
    # 出网阻断：payload 的 registry 段必须是 invalid.invalid（3 段 name 形式）
    require(t, '"name":"invalid.invalid/', '"stream":false')
    # 禁真实 registry 域（防未来改动把探测引向真实出网）
    forbid(t, "docker.io", "ghcr.io", "registry-1", "quay.io")
    # 口径：存在性预言机，不含文件内容读取——描述必须如实声明
    require(t, "存在性", "不含文件内容读取")


def test_cups_web_lpe_version():
    """CUPS 版本候选：只做版本横幅判定，枚举上界钉死 2.4.16（2.4.17+ 不命中）。"""
    t = read("http/vulnerabilities/cups-web-lpe-version.yaml")
    require(t, "max-request: 1", "GET")
    # 候选证据口径（ADR-0001）：版本≠确认，描述必须写明
    require(t, "候选")
    # 上界钉死：1[0-6] 枚举段存在，且不得用宽松上界直通
    require(t, "1[0-6]")
    forbid(t, r"2\.4\.[0-9]+\\b")
    # 只读版本横幅：不携带操作型请求体
    forbid(t, "POST", "payload")


def test_global_invariants():
    """全模板通用：元数据齐全 + 无破坏性载荷模式。"""
    templates = sorted((ROOT / "http").rglob("*.yaml"))
    assert len(templates) >= 3, f"现存模板数异常（{len(templates)} < 3）"
    for p in templates:
        t = p.read_text(encoding="utf-8")
        require(t, "severity:", "author:")
        # 破坏性/越界模式全仓禁止
        forbid(t, "rm -rf", "mkfs", "shutdown ", ":(){:|:&};:")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ✓ {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  ✗ {fn.__name__}: {e}")
    print(f"\n结果：{len(tests) - failed} 通过，{failed} 失败，共 {len(tests)} 项")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
