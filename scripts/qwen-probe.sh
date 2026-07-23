#!/usr/bin/env bash
# server2 诊断:直连 qwen 看浅层提示词下的原始输出(排 openJiuwen 'Json parse error'),ferry 回来。
# 前提: .env 填好(LLM_API_BASE → 本地 qwen);用 .venv312(已装 openai/httpx)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/qwen-probe.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"
[ -x "$PY" ] || PY=".venv/bin/python"          # 这脚本只用 openai/httpx,3.10 的 .venv 也行
[ -x "$PY" ] || { echo "!! 无 venv —— 先 bash scripts/cascade-gate.sh 或 selftest.sh 建一个"; exit 1; }

mkdir -p feedback
FB="feedback/qwen-probe.out"
{
  echo "=== qwen-probe $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/qwen_shallow_probe.py 2>&1
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: qwen-probe $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
