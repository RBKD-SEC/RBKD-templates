#!/usr/bin/env python3
"""Kafka Connect 模板误报修复 harness（任务书 docs/kafka-connect-false-positive-fix-brief.md）。

起多端口 fixture 服务模拟正反例，对指定模板逐场景跑 nuclei 断言命中与否。

用法:
    python3 tests/fixtures/kafka-connect-harness.py [--template <path>] [--keep-up]

退出码: 全部符合预期 0，任一场景不符 1。
仅用标准库。
"""
import argparse
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONNECT_ROOT = (
    '{"version":"7.6.0-ccs","commit":"7e56342f0dcd0f9d","kafka_cluster_id":"kWcEuSVURyiKq4nNW0oZgA"}'
)

JSON = "application/json"


class Fixture:
    def __init__(self, name, expect_match, routes):
        self.name = name
        self.expect_match = expect_match
        self.routes = routes  # path -> (status, content_type, body bytes)


FIXTURES = [
    Fixture("positive", True, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (200, JSON, '["file-source", "jdbc-sink"]'),
    }),
    Fixture("positive-empty-connectors", True, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (200, JSON, "[]"),
    }),
    Fixture("neg-401-connectors (反例4: root可识别但枚举需认证)", False, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (401, JSON, '{"error_code":401,"message":"Unauthorized"}'),
    }),
    Fixture("neg-plain-rest (反例1: 普通REST返回200 [])", False, {
        "/": (200, JSON, "[]"),
        "/connectors": (404, JSON, '{"error":"not found"}'),
    }),
    Fixture("neg-html-brackets (反例2: HTML正文含[])", False, {
        "/": (200, "text/html", "<html><body>items [1] and [2]</body></html>"),
        "/connectors": (200, "text/html", "<html><body>[ ]</body></html>"),
    }),
    Fixture("neg-other-product (反例3: 其他产品/connectors路由)", False, {
        "/": (200, JSON, '{"service":"kafka-ui","version":"0.7.2","auth":"on"}'),
        "/connectors": (200, JSON, '["legacy-topic-connector"]'),
    }),
    Fixture("neg-json-object (反例5: /connectors返回JSON object)", False, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (200, JSON, '{"error":"internal server error"}'),
    }),
    Fixture("neg-json-string (反例5: /connectors返回字符串)", False, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (200, JSON, '"ok"'),
    }),
    Fixture("neg-malformed (反例5: /connectors畸形JSON)", False, {
        "/": (200, JSON, CONNECT_ROOT),
        "/connectors": (200, JSON, '["a", '),
    }),
]

BASE_PORT = 18083


def make_handler(fixture):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, ctype, body = fixture.routes.get(self.path, (404, JSON, ""))
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return Handler


def run_nuclei(template, url):
    proc = subprocess.run(
        ["nuclei", "-t", template, "-u", url, "-silent", "-no-color", "-duc"],
        capture_output=True, text=True, timeout=120,
    )
    return proc.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", default="http/exposures/kafka-connect-exposed.yaml")
    ap.add_argument("--keep-up", action="store_true", help="仅起服务不跑断言（调试用）")
    args = ap.parse_args()

    servers = []
    threads = []
    try:
        for i, fixture in enumerate(FIXTURES):
            port = BASE_PORT + i
            srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(fixture))
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            servers.append((fixture, port, srv))
            threads.append(t)

        if args.keep_up:
            print(f"fixtures up on 127.0.0.1:{BASE_PORT}-{BASE_PORT + len(FIXTURES) - 1}, Ctrl-C 退出")
            threads[0].join()
            return 0

        fails = 0
        print(f"模板: {args.template}\n")
        for fixture, port, _srv in servers:
            url = f"http://127.0.0.1:{port}"
            out = run_nuclei(args.template, url)
            matched = bool(out)
            ok = matched == fixture.expect_match
            mark = "PASS" if ok else "FAIL"
            fails += 0 if ok else 1
            hit = "命中" if matched else "未命中"
            want = "应命中" if fixture.expect_match else "应不命中"
            print(f"  [{mark}] {fixture.name:58s} 实际:{hit} {want}")
            if out:
                for line in out.splitlines():
                    print(f"        nuclei> {line}")
        print()
        print(f"结果：{len(FIXTURES) - fails} 通过，{fails} 失败")
        return 1 if fails else 0
    finally:
        for _f, _p, srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
