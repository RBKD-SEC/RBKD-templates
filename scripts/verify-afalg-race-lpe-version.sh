#!/usr/bin/env bash
# afalg-race-lpe-version 模板正反例门禁（CVE-2025-39964，AF_ALG 并发写竞态本地提权）
#
# 机制（docs/cve-2025-39964-afalg-lpe-brief.md §3）：
#   PATH shim 注入 fake uname（只输出 fixture 版本串）→ 跑真实 nuclei -code 引擎
#   加载模板副本（fake 必须经过真实包装层 / 模板 matcher 全链，禁止绕过模板直接测正则）。
#   Docker 共享宿主内核无法构造正/负例内核靶标（brief §2.4 裁定不建 lab），门禁走 fixture 版本集。
#
# 签名前置（nuclei v3.11.1 安全门：unsigned code 模板无条件拒载，见
#   projectdiscovery/nuclei pkg/catalog/loader/loader.go HasCodeRequest 分支）：
#   脚本用 openssl 生成一次性 EC P-256 密钥对（CN=rbkd-verify-ephemeral），经
#   NUCLEI_USER_CERTIFICATE / NUCLEI_USER_PRIVATE_KEY 环境变量注入，对临时副本执行
#   nuclei -sign —— git 仓内模板保持零签名（签名是本机自签自验语义，入仓对他人无意义）。
#
# 受影响区间（brief §1 核实结论，OSV/kernel.org CVE 记录 + git.kernel.org fix commits）：
#   introduced 2.6.38（commit 8ff590903d5f，algif_skcipher 接口引入）；
#   fixed 5.10.245 / 5.15.194 / 6.1.154 / 6.6.108 / 6.12.49 / 6.16.9（6.17+ 含 mainline 修复）。
#   注：brief 初稿的保守下界 4.13 已被核实推翻——3.x / 4.9.x 实际在区间内，为正例；
#   负例的「引入下界外」取 2.6.36 / 2.6.37。
#
# 断言：
#   正例（24 个，跨全部受影响分支 + 各受支持分支上边界 fix-1 + 无 stable 修复的 EOL
#   分支中段 + 发行版后缀形态 + 引入下界本身）-> 每个 fixture 必须 >= 1 条命中
#   负例（12 个，各分支修复版 + 修复版后继 + 带后缀修复版 + 引入下界外）-> 每个 fixture 必须零命中
#   差分自检：每个 fixture 跑 nuclei 前断言 PATH 注入下 uname -r 确实返回 fixture 串（防假绿）
#
# 安全说明：模板 code 段仅执行 uname -r（只读、无副作用）；fake uname shim 只回显
#   fixture 字符串；nuclei -duc 禁用联网更新检查；一次性密钥对与签名副本均在 mktemp
#   临时目录，脚本退出清理，不触碰用户 nuclei keys 目录。
#
# 用法：bash scripts/verify-afalg-race-lpe-version.sh
# 退出码：0 = 全部通过；1 = 有断言失败。
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO_ROOT/code/vulnerabilities/afalg-race-lpe-version.yaml"
EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/tests/evidence}"
DUMMY_TARGET="http://127.0.0.1" # code 模板本地执行，-u 仅为满足 nuclei target 要求

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

command -v nuclei >/dev/null 2>&1 || fail "nuclei CLI 不在 PATH"
command -v openssl >/dev/null 2>&1 || fail "openssl 不在 PATH（签名前置需要）"
[ -f "$TEMPLATE" ] || fail "模板不存在: ${TEMPLATE}（先写模板再跑门禁）"

# --- fixture 集（版本串 = shim uname -r 的输出） ---
# 正例：必须命中。四层覆盖：
#   1) 各受支持分支中段/下段 + 发行版后缀形态（generic/amd64/el7/arch/ubuntu 定制串），
#      spec §3 点名的 5.10.200/5.15.190/6.1.100/6.6.50/6.12.10 全含（6.6.50 以 Ubuntu
#      定制后缀形态出现）+ 引入下界本身；
#   2) 各受支持分支上边界 fix-1（5.10.244/5.15.193/6.1.153/6.6.107/6.12.48/6.16.8）——
#      与负例的修复版配对，每条分支上界在行为层双侧钉住；
#   3) 无 stable 修复的 EOL 分支中段（5.12.5/5.18.14/6.0.12/6.3.13/6.14.4，部分带后缀
#      形态）——这些分支的 catch-all regex（^5\.1[1-4]\. 等）被删/收窄时，缺正例即门禁
#      静默假阴性（P1-A）。
POSITIVE_FIXTURES=(
    "5.10.200"
    "5.10.0-28-amd64"
    "5.10.244"
    "5.15.190"
    "5.15.0-91-generic"
    "5.15.193"
    "6.1.100"
    "6.1.0-18-amd64"
    "6.1.153"
    "6.6.50-0ubuntu1-6.8.0-45-generic"
    "6.6.107"
    "6.12.10"
    "6.12.48"
    "2.6.38"
    "3.10.0-1160.el7.x86_64"
    "4.9.0-15-amd64"
    "5.4.0-150-generic"
    "6.8.0-45-generic"
    "5.12.5"
    "5.18.14-arch1-1"
    "6.0.12"
    "6.3.13"
    "6.14.4-arch1-1"
    "6.16.8-arch1-1"
)
# 负例：必须零命中。各受影响分支的修复版 + 修复版后继（6.16.20、6.17、6.18）+
# 带发行版后缀的修复版（防「只匹配裸版本」的半实现）+ 引入下界外（2.6.36/2.6.37，
# 取代 spec 初稿基于 4.13 假设的 4.9.x/3.x，见脚本头核实结论）。
NEGATIVE_FIXTURES=(
    "5.10.245"
    "5.10.246-0ubuntu1"
    "5.15.194"
    "6.1.154"
    "6.6.108"
    "6.12.49"
    "6.16.9"
    "6.16.20"
    "6.17.0"
    "6.18.4-arch1-1"
    "2.6.36-32-generic"
    "2.6.37"
)

[ "${#POSITIVE_FIXTURES[@]}" -ge 5 ] || fail "正例 fixture 数量不足 5（当前 ${#POSITIVE_FIXTURES[@]}）"
[ "${#NEGATIVE_FIXTURES[@]}" -ge 8 ] || fail "负例 fixture 数量不足 8（当前 ${#NEGATIVE_FIXTURES[@]}）"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/afalg-verify.XXXXXX")"
SHIM_DIR="$WORKDIR/shim"
KEY_DIR="$WORKDIR/keys"
trap 'rm -rf "$WORKDIR"' EXIT
mkdir -p "$SHIM_DIR" "$KEY_DIR"

# --- 一次性签名密钥对（openssl EC P-256 + 自签证书；CN 必填，nuclei ParseUserCert 校验） ---
openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/nuclei-user-private-key.pem" \
    >/dev/null 2>&1 || fail "openssl 生成 EC 私钥失败"
openssl req -new -x509 -key "$KEY_DIR/nuclei-user-private-key.pem" \
    -out "$KEY_DIR/nuclei-user.crt" -days 1 -subj "/CN=rbkd-verify-ephemeral" \
    >/dev/null 2>&1 || fail "openssl 自签证书失败"

export NUCLEI_USER_CERTIFICATE="$(cat "$KEY_DIR/nuclei-user.crt")"
export NUCLEI_USER_PRIVATE_KEY="$(cat "$KEY_DIR/nuclei-user-private-key.pem")"

# --- 模板副本签名（git 模板剥残留 digest 后拷贝，签名只落临时副本） ---
SIGNED_TEMPLATE="$WORKDIR/afalg-race-lpe-version.signed.yaml"
sed '/^# digest:/d' "$TEMPLATE" > "$SIGNED_TEMPLATE" || fail "模板拷贝失败"
nuclei -sign -t "$SIGNED_TEMPLATE" >/dev/null 2>&1 \
    || fail "nuclei -sign 签名模板副本失败（检查 openssl 密钥对生成）"
grep -q '^# digest:' "$SIGNED_TEMPLATE" \
    || fail "签名副本未见 digest 行（nuclei v3.11+ unsigned code 模板会被拒载，门禁无法进行）"
pass "模板副本签名完成（一次性密钥，git 模板保持零签名）"

# --- 单 fixture 跑真实 nuclei 引擎：PATH shim 注入 fake uname → -code 全链 ---
run_fixture() { # $1=fixture 版本串 $2=输出文件 -> echo 命中条数
    local fixture="$1" out="$2"
    # 差分自检：PATH 注入下 uname -r 必须确实返回 fixture 串（防 shim 失效假绿）
    printf '#!/bin/sh\necho "%s"\n' "$fixture" > "$SHIM_DIR/uname"
    chmod +x "$SHIM_DIR/uname"
    local observed
    observed="$(PATH="$SHIM_DIR:$PATH" uname -r)"
    [ "$observed" = "$fixture" ] \
        || fail "shim 差分自检失败：期望 uname -r 返回 [$fixture]，实际 [$observed]"
    rm -f "$out"
    PATH="$SHIM_DIR:$PATH" nuclei -code -t "$SIGNED_TEMPLATE" -u "$DUMMY_TARGET" \
        -duc -nc -silent -j -o "$out" >/dev/null 2>&1
    [ -f "$out" ] || return 0
    grep -c '^{' "$out" || true
}

mkdir -p "$EVIDENCE_DIR"
pos_out="$EVIDENCE_DIR/afalg-race-lpe-version-positive.jsonl"
neg_out="$EVIDENCE_DIR/afalg-race-lpe-version-negative.jsonl"
: > "$pos_out"
: > "$neg_out"

# --- 正例：全部必须命中 ---
pos_total=0
for fixture in "${POSITIVE_FIXTURES[@]}"; do
    hits="$(run_fixture "$fixture" "$WORKDIR/pos-current.jsonl")"
    [ "${hits:-0}" -ge 1 ] \
        || fail "正例未命中（${fixture} 必须命中）"
    cat "$WORKDIR/pos-current.jsonl" >> "$pos_out" 2>/dev/null || true
    pos_total=$((pos_total + hits))
    pass "正例命中 ${fixture}（${hits} 条）"
done

# --- 负例：全部必须零命中 ---
for fixture in "${NEGATIVE_FIXTURES[@]}"; do
    hits="$(run_fixture "$fixture" "$WORKDIR/neg-current.jsonl")"
    [ "${hits:-0}" -eq 0 ] \
        || fail "负例误报（${fixture} 必须零命中，实际 ${hits} 条）"
    cat "$WORKDIR/neg-current.jsonl" >> "$neg_out" 2>/dev/null || true
    pass "负例零命中 ${fixture}"
done

echo
echo "全部通过：正例 ${#POSITIVE_FIXTURES[@]}/${#POSITIVE_FIXTURES[@]} 命中（共 ${pos_total} 条），负例 ${#NEGATIVE_FIXTURES[@]}/${#NEGATIVE_FIXTURES[@]} 零命中。"
echo "evidence: $pos_out / $neg_out"
exit 0
