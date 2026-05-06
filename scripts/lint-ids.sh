#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0

# 1. 检查旧的 network/default-login/ 目录是否还存在
if [[ -d "network/default-login" ]]; then
  echo "ERROR: 旧目录 network/default-login/ 仍然存在，请迁移到 network/default-logins/"
  ERRORS=$((ERRORS + 1))
fi

# 2. 收集所有模板 id，检查唯一性
TMP_IDS=$(mktemp)
trap 'rm -f "$TMP_IDS"' EXIT

while IFS= read -r file; do
  id=$(grep -m1 '^id:' "$file" 2>/dev/null | sed 's/^id: *//' | tr -d ' ')
  if [[ -z "$id" ]]; then
    echo "WARNING: $file 未找到 id 字段"
    continue
  fi
  echo "$id|$file"
done < <(find . -name '*.yaml' -not -path './.git/*' -not -path './docs/*') > "$TMP_IDS"

# 检查重复 id
DUPLICATES=$(cut -d'|' -f1 "$TMP_IDS" | sort | uniq -d)
if [[ -n "$DUPLICATES" ]]; then
  while IFS= read -r dup_id; do
    echo "ERROR: 重复 id '$dup_id' 出现在:"
    grep "^${dup_id}|" "$TMP_IDS" | sed 's/^/  /'
    ERRORS=$((ERRORS + 1))
  done <<< "$DUPLICATES"
fi

# 3. 检查文件名与 id 是否基本一致
while IFS='|' read -r id file; do
  basename=$(basename "$file" .yaml)
  if [[ "$id" != "$basename" ]]; then
    echo "WARNING: id '$id' 与文件名 '$basename' 不一致: $file"
  fi
done < "$TMP_IDS"

# 4. 检查弱口令模板是否包含 stop-at-first-match 和 metadata.max-request
while IFS= read -r file; do
  if grep -q 'stop-at-first-match' "$file"; then
    if ! grep -q 'metadata:' "$file" || ! grep -A2 'metadata:' "$file" | grep -q 'max-request'; then
      echo "ERROR: 弱口令模板缺少 metadata.max-request: $file"
      ERRORS=$((ERRORS + 1))
    fi
    if ! grep -q 'stop-at-first-match: true' "$file"; then
      echo "ERROR: 弱口令模板 stop-at-first-match 未设为 true: $file"
      ERRORS=$((ERRORS + 1))
    fi
  fi
done < <(find . -name '*brute*.yaml' -o -name '*login*.yaml' -o -name '*default*.yaml' | grep -v '.git/')

if [[ $ERRORS -gt 0 ]]; then
  echo ""
  echo "发现 $ERRORS 个错误。"
  exit 1
fi

echo "lint-ids.sh 通过。"
