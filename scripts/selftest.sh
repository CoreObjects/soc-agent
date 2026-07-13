#!/usr/bin/env bash
# 在 server2 上一键批量自测:每类告警各抽 1 条 → 打印原始告警 + 研判全过程 → ferry 回来给 Claude 判。
# 用法: bash scripts/selftest.sh [每类条数=1] [技术类数上限=10] [--mode recipe|auto] [--write]
#   只测一类: bash scripts/selftest.sh --tech T1059
#   只测一条: bash scripts/selftest.sh --uid <alert_uid>
#   挖真攻击: bash scripts/selftest.sh 8 10 --order recent   (每类取最新 8 条;order=recent|severity|first)
# 前提: .env 已填(NEO4J_* → server1 图;LLM_API_BASE → 本地 qwen :8000)。
# 首跑自动建 venv + 装依赖(neo4j/openai)—— 不再需要手动 python3(那样会 ModuleNotFoundError)。
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "== 首跑:建 venv + 装依赖(neo4j/openai)=="
  python3 -m venv .venv
  ./.venv/bin/pip install -q -e .
fi

mkdir -p feedback
TS="$(date -u '+%Y%m%d-%H%M%SZ' 2>/dev/null || echo run)"
FB="feedback/selftest-${TS}.out"

# 批量自测 + tee 到 feedback(输出经 IP 打码;真实端点/口令只在 .env,不会打印)
{
  echo "=== selftest $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/batch_investigate.py "$@"
  echo "=== done $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
} 2>&1 | tee "$FB" || true      # 即使中途崩也继续:保证 traceback 也被 ferry 回来

# 回推 feedback(ferry:Claude pull 就能读)
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: selftest ${TS}" 2>&1 | tail -2 || true
if git push origin HEAD >/dev/null 2>&1 \
   || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD >/dev/null 2>&1; }; then
  echo "✅ 已推 $FB,Claude 可 pull"
else
  echo "!! push 失败,可手动: git push origin HEAD"
fi
