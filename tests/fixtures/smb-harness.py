#!/usr/bin/env python3
"""SMB 模板误报修复 harness（任务书 docs/smb-null-session-echo-false-positive-fix-brief.md）。

起多端口 fixture 服务模拟正反例，对 network/detection/smb-detect.yaml 跑 nuclei
断言命中与否。replay 类 fixture 按到达探针分发真实捕获的响应字节（2026-08-26
Samba 4.19.9 实测抓包），模拟不同服务器类别。

fixture 语义（与真实服务器行为对齐，实测依据见任务书 E4/E5/E10/E12）：
  echo                 纯 TCP 反射器（run1 误报源）           → 不得命中
  http                 445 端口上的 HTTP 服务                   → 不得命中
  garbage              非 SMB 二进制应答                       → 不得命中
  smb2-only-replay     多协议探针→206B SMB2 帧；SMB1 探针→41B 无方言拒绝帧 → 命中（请求1 路径）
  smb1-capable-replay  多协议探针→41B 拒绝帧；SMB1 探针→163B NT LM 0.12 选中 → 命中（请求2 路径）

用法:
    python3 tests/fixtures/smb-harness.py [--template <path>] [--keep-up]

退出码: 全部符合预期 0，任一场景不符 1。
仅用标准库。注意（任务书 E13）：fixture 必须是宿主直连 listener，Docker 端口转发
会毁掉 nuclei 的 tcp 读。
"""
import argparse
import socketserver
import subprocess
import sys
import threading
import time

# ---- 真实捕获的响应字节（Samba 4.19.9 / Alpine 3.20，2026-08-26） ----

# SMB2 negotiate 响应（206B，\xfeSMB + StructureSize 0x0040）：默认配置/收紧配置 Samba、
# 本机 lab-samba 对多协议探针的统一应答。
SMB2_RESP_206 = bytes.fromhex(
    "000000cafe534d4240000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000100ff0200006462396166643330306138350000000007000000000080000000800000008000827b628aed34dd01000000000000000080004a0000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265")

# SMB1 NT LM 0.12 选中响应（163B，WordCount=0x11 + DialectIndex=0x0005）：
# SMB1 能力开启的 Samba 对扩展安全位 SMB1 方言表探针的应答。
SMB1_RESP_163 = bytes.fromhex(
    "0000009fff534d4272000000008853c80000000000000000000000000000fffe00000000110500033200"
    "0100044100000000010022000000fdf3808033f5e038ed34dd010000005a003564326162643931643765"
    "3700000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b"
    "246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265")

# "无方言"拒绝帧（41B，WordCount=1 + DialectIndex=0xFFFF）：Samba 对不接受的
# SMB1 方言协商的应答。
ERR_RESP_41 = bytes.fromhex(
    "00000025ff534d4272000000008813c00000000000000000000000000000fffe0000000001ffff0000")

GARBAGE = bytes.fromhex("deadbeef" * 24)  # 96B 非 SMB 二进制，不含任何锚点

HOLD_SECONDS = 2  # 应答后保持连接再关闭：模拟 smbd 不主动断（nuclei read 等 FIN/截止）

BASE_PORT = 18445


def is_dionaea_probe(data):
    return len(data) >= 4 and data[3] == 0x45  # NBT 长度 0x45 → 73B 多协议探针


def is_smb1_probe(data):
    return len(data) >= 4 and data[3] == 0x85  # NBT 长度 0x85 → 137B SMB1 方言表探针


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(4096)
            if not d:
                return
            self.request.sendall(d)


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        body = b"<html><body>SMB</body></html>"  # 正文含 "SMB"，旧版 word matcher 会命中
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
        time.sleep(HOLD_SECONDS)


class GarbageHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(4096)
        self.request.sendall(GARBAGE)
        time.sleep(HOLD_SECONDS)


def replay_handler(dionaea_resp, smb1_resp):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            d = self.request.recv(4096)
            if is_dionaea_probe(d):
                self.request.sendall(dionaea_resp)
            elif is_smb1_probe(d):
                self.request.sendall(smb1_resp)
            else:
                self.request.sendall(ERR_RESP_41)
            time.sleep(HOLD_SECONDS)
    return Handler


SCENARIOS = [
    ("echo（run1 误报源，红→绿主断言）", EchoHandler, False),
    ("http-on-smb-port（正文含 SMB 字样）", HttpHandler, False),
    ("garbage-binary（非 SMB 二进制应答）", GarbageHandler, False),
    ("smb2-only-replay（请求1 路径：206B SMB2 帧）",
     replay_handler(SMB2_RESP_206, ERR_RESP_41), True),
    ("smb1-capable-replay（请求2 路径：163B NT LM 0.12 选中）",
     replay_handler(ERR_RESP_41, SMB1_RESP_163), True),
]


def run_nuclei(template, port):
    proc = subprocess.run(
        ["nuclei", "-t", template, "-u", f"127.0.0.1:{port}", "-silent", "-no-color", "-duc"],
        capture_output=True, text=True, timeout=180,
    )
    return proc.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default="network/detection/smb-detect.yaml")
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
