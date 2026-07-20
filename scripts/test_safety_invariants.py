#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def require(text, *needles):
    for needle in needles:
        assert needle in text, f"missing safety invariant: {needle}"


vnc = read("javascript/default-logins/vnc-mini-brute.yaml")
require(vnc, "max-request: 2", "threads: 1", "stop-at-first-match: true")

nginx = read("http/vulnerabilities/cve-2017-7529.yaml")
require(nginx, 'response.read(8192)', 'b"Content-Range"', 'print("vulnerable-range-filter")')
assert "print(body" not in nginx

webdav = read("http/misconfiguration/webdav-anonymous-write.yaml")
require(webdav, "PUT /.rbkd-", "GET /.rbkd-", "DELETE /.rbkd-", "status_code_3")

shellshock = read("http/vulnerabilities/cve-2014-6271-echo.yaml")
require(shellshock, "echo rbkd-{{marker}}", "max-request: 1")
assert "cat /etc/passwd" not in shellshock

swat = read("http/default-logins/samba-swat-mini-brute.yaml")
require(swat, "max-request: 4", "threads: 1", "stop-at-first-match: true")

regresshion = read("network/vulnerabilities/cve-2024-6387-version-check.yaml")
require(regresshion, "safe candidate check only", "max-request: 1", "8\\.[5-9]", "9\\.[0-7]")
pattern_line = next(line.strip() for line in regresshion.splitlines() if line.strip().startswith("- '(?i)^SSH-"))
pattern = pattern_line[3:-1]
for banner in ("SSH-2.0-OpenSSH_8.5p1", "SSH-2.0-OpenSSH_9.7p1 Ubuntu-3"):
    assert re.search(pattern, banner), banner
for banner in ("SSH-2.0-OpenSSH_8.4p1", "SSH-2.0-OpenSSH_9.8p1"):
    assert not re.search(pattern, banner), banner

print("template safety invariants: ok")
