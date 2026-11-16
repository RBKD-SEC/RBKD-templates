#!/usr/bin/env bash
# cups-web-lpe-version 模板正反例门禁（CVE-2026-34990 / GHSA-c54j-2vqw-wpwp）
#
# 断言：
#   正例靶标（源码构建 CUPS 2.4.16，lab compose cups-2416，127.0.0.1:16416）
#     -> nuclei 必须命中（>= 1 条结果）
#   负例靶标（源码构建 CUPS 2.4.17，lab compose cups-2417，127.0.0.1:16417）
#     -> nuclei 必须零命中（2.4.17 禁 loopback local 证书，不在受影响区间）
#   另附靶标状态差分自检（版本横幅检查），防靶标版本漂移导致门禁假绿。
#
# 安全说明：探测仅为 GET /（只读、无认证、无状态副作用，幂等）；模板本身
# 只做版本候选判定（ADR-0001 口径：端口/版本只是候选证据，不能冒充确认）。
#
# 前置：lab 靶标已启动 —— docker compose -f ~/DEV/lab/docker-compose.yml up -d cups-2416 cups-2417
# 用法：bash scripts/verify-cups-web-lpe-version.sh
# 退出码：0 = 全部通过；1 = 有断言失败。
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO_ROOT/http/vulnerabilities/cups-web-lpe-version.yaml"
POS_URL="${POS_URL:-http://127.0.0.1:16416}"
NEG_URL="${NEG_URL:-http://127.0.0.1:16417}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/tests/evidence}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

command -v nuclei >/dev/null 2>&1 || fail "nuclei CLI 不在 PATH"
[ -f "$TEMPLATE" ] || fail "模板不存在: ${TEMPLATE}（先写模板再跑门禁）"
command -v curl >/dev/null 2>&1 || fail "curl 不在 PATH"

# 指纹预检：等待服务就绪（GET / 标题含 "Home - CUPS"）
wait_cups() {
    local url="$1" label="$2" i
    for i in $(seq 1 30); do
        if curl -s --max-time 3 "$url/" 2>/dev/null | grep -q "Home - CUPS"; then
            return 0
        fi
        sleep 2
    done
    fail "$label 指纹不可达（GET / 未返回 Home - CUPS 标题）: $url"
}

# --- 靶标状态差分自检（防版本漂移假绿） ---
check_positive_target() {
    wait_cups "$POS_URL" "正例靶标(2.4.16)"
    local body
    body="$(curl -s --max-time 5 "$POS_URL/")"
    echo "$body" | grep -qE 'CUPS v?2\.4\.16' \
        || fail "正例靶标页面未见 2.4.16 版本横幅（靶标可能不是 2.4.16）: $(echo "$body" | head -c 200)"
    echo "$body" | grep -qE 'CUPS v?2\.4\.17' \
        && fail "正例靶标页面出现 2.4.17 横幅（版本漂移？）" || true
    pass "正例靶标差分自检：版本横幅 2.4.16 符合预期"
}

check_negative_target() {
    wait_cups "$NEG_URL" "负例靶标(2.4.17)"
    local body
    body="$(curl -s --max-time 5 "$NEG_URL/")"
    echo "$body" | grep -qE 'CUPS v?2\.4\.17' \
        || fail "负例靶标页面未见 2.4.17 版本横幅（靶标可能不是 2.4.17）: $(echo "$body" | head -c 200)"
    pass "负例靶标差分自检：版本横幅 2.4.17 符合预期"
}

# --- nuclei 模板门禁 ---
run_nuclei() { # $1=url $2=输出文件 -> echo 命中条数
    local url="$1" out="$2"
    nuclei -t "$TEMPLATE" -u "$url" -jsonl -silent -nc -o "$out" >/dev/null 2>&1
    [ -f "$out" ] || return 0
    grep -c '^{' "$out" || true
}

mkdir -p "$EVIDENCE_DIR"

check_positive_target
check_negative_target

pos_out="$EVIDENCE_DIR/cups-web-lpe-version-positive-2.4.16.jsonl"
neg_out="$EVIDENCE_DIR/cups-web-lpe-version-negative-2.4.17.jsonl"
rm -f "$pos_out" "$neg_out"

pos_hits="$(run_nuclei "$POS_URL" "$pos_out")"
neg_hits="$(run_nuclei "$NEG_URL" "$neg_out")"

[ "${pos_hits:-0}" -ge 1 ] \
    || fail "正例未命中（2.4.16 必须命中），nuclei 输出: $pos_out"
pass "正例命中 ${pos_hits} 条（2.4.16）-> $pos_out"

[ "${neg_hits:-0}" -eq 0 ] \
    || fail "负例误报（2.4.17 必须零命中，实际 ${neg_hits} 条），nuclei 输出: $neg_out"
pass "负例零命中（2.4.17）-> $neg_out"

echo
echo "全部通过：模板在正例命中、负例零命中，靶标版本横幅符合预期。"
exit 0
