#!/usr/bin/env python3
"""CVE-2012-1675（Oracle TNS Poison）模板判定逻辑 harness。

起多端口 fixture 服务模拟不同 TNS Listener 应答类别，对
network/vulnerabilities/cve-2012-1675.yaml 跑 nuclei，断言命中与否。
判定语义对齐三方权威实现：MSF auxiliary/scanner/oracle/tnspoison_checker.rb、
ODAT isTNSListenerVulnerableToCVE_2012_1675、interference-security/check_tns_poison.py：
  - 响应 offset4 包类型 0x02（NSPTAC ACCEPT）且无错误栈 → 受影响 → 必须命中
  - 0x04（NSPTRF REFUSE）或含 "(ERROR_STACK=(ERROR=" → 拒绝注册 → 不得命中
  - 非 TNS 垃圾应答 / 不应答 → 无法判定 → 不得命中

探针为无害化 CONNECT 包（CONNECT_DATA=(COMMAND=service_register_NSGR)，无效命令，
不产生真实实例注册），fixture 无需按内容分发，逐端口固定应答即可。

用法:
    python3 tests/fixtures/oracle-tns-poison-harness.py [--template <path>] [--keep-up]

退出码: 全部符合预期 0，任一场景不符 1。仅用标准库。
"""
import argparse
import socketserver
import subprocess
import sys
import threading
import time
import struct

HOLD_SECONDS = 2  # 应答后保持连接再关闭：避免 nuclei 读端过早 EOF 的边界差异

BASE_PORT = 18452


def tns_frame(ptype, payload=b""):
    """构造最小 TNS 帧：len(2)+checksum(2)+type(1)+reserved(1)+hdr-csum(2)+payload。"""
    return struct.pack(">HHBBH", 8 + len(payload), 0, ptype, 0, 0) + payload


# 受影响 listener：对注册命令回 ACCEPT（type 0x02），携带地址体但无错误栈
ACCEPT_RESP = tns_frame(
    0x02,
    b"\x01\x2c\x00\x00" + b"(ADDRESS=(PROTOCOL=tcp)(HOST=10.0.0.5)(PORT=1521))",
)

# 已加固 listener：直接拒绝远程注册（REFUSE，type 0x04）
REFUSE_RESP = tns_frame(0x04, b"RETN\x00\x00\x00\x20")

# 已加固 listener（ODAT 路径）：连接层放行但数据层回错误栈，错误优先于类型判定
ERROR_STACK_RESP = tns_frame(
    0x06,
    b"(ERROR_STACK=(ERROR=(CODE=12564)(EMFI=4))(ERROR_TYPE=REMOTE_REGISTRATION))",
)

# 非 TNS 服务误占 1521 端口：垃圾二进制应答，不含任何判定锚点
GARBAGE_RESP = bytes.fromhex("deadbeef") * 24


class AcceptHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(ACCEPT_RESP)
        time.sleep(HOLD_SECONDS)


class RefuseHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(REFUSE_RESP)
        time.sleep(HOLD_SECONDS)


class ErrorStackHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(ERROR_STACK_RESP)
        time.sleep(HOLD_SECONDS)


class GarbageHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(GARBAGE_RESP)
        time.sleep(HOLD_SECONDS)


class SilentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)  # 不应答，直接收尾
        time.sleep(HOLD_SECONDS)


SCENARIOS = [
    ("accept-replay（受影响：ACCEPT 0x02）", AcceptHandler, True),
    ("refuse-replay（已加固：REFUSE 0x04）", RefuseHandler, False),
    ("error-stack-replay（已加固：数据层错误栈）", ErrorStackHandler, False),
    ("garbage-replay（非 TNS 二进制应答）", GarbageHandler, False),
    ("silent-replay（接受连接但不应答）", SilentHandler, False),
]


def run_nuclei(template, port):
    proc = subprocess.run(
        ["nuclei", "-t", template, "-u", f"127.0.0.1:{port}", "-silent", "-no-color", "-duc"],
        capture_output=True, text=True, timeout=180,
    )
    return proc.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default="network/vulnerabilities/cve-2012-1675.yaml")
    ap.add_argument("--keep-up", action="store_true")
    args = ap.parse_args()

    servers = []
    for i, (name, handler, expect) in enumerate(SCENARIOS):
        port = BASE_PORT + i
        socketserver.TCPServer.allow_reuse_address = True
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append((name, port, expect, srv))

    failures = []
    try:
        for name, port, expect, _ in servers:
            out = run_nuclei(args.template, port)
            matched = bool(out)
            ok = matched == expect
            print(f"[{'PASS' if ok else 'FAIL'}] {name} @:{port} 期望{'命中' if expect else '不命中'}"
                  f" 实际{'命中' if matched else '不命中'}" + (f" ({out})" if out else ""))
            if not ok:
                failures.append(name)
        if args.keep_up:
            print("fixture 保持运行，Ctrl-C 退出")
            while True:
                time.sleep(1)
    finally:
        for _, _, _, srv in servers:
            srv.shutdown()

    if failures:
        print(f"\n{len(failures)} 个场景不符预期: {failures}")
        return 1
    print(f"\n全部 {len(SCENARIOS)} 个场景符合预期")
    return 0


if __name__ == "__main__":
    sys.exit(main())
