#!/usr/bin/env bash
# server2:回退后【所有保留功能】一把梭验证,结果 ferry 回来。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/verify_all.sh
# 覆盖:单元测试(全保留逻辑)+ import 健康 + neo4j/qwen 连通 + respond_cli + 处置面连通 + 慢研判端到端 + 第三类图台账。
set -uo pipefail                     # 不 -e:让每项都跑完
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "== 首跑:建 venv + 装依赖 =="
  python3 -m venv .venv && ./.venv/bin/pip install -q -e .
fi
./.venv/bin/pip install -q pytest >/dev/null 2>&1 || true

mkdir -p feedback
FB="feedback/verify-all.out"
{
  echo "=== verify-all  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo ""
  echo "## 1. 单元测试(保留逻辑:慢研判/路由/recipe/composer/plan/ledger/护栏/图台账写/models/config/llm)"
  PYTHONUTF8=1 "$PY" -m pytest -q 2>&1 | tail -3
  echo ""
  echo "## 2. import 健康(第二类 patterns 已删、无残留引用)"
  PYTHONUTF8=1 "$PY" -c "import soc_agent.cli, soc_agent.composer, soc_agent.composer.plan, soc_agent.respond_cli, soc_agent.orchestrator; print('imports OK')"
  echo ""
  echo "## 3. 连通性(neo4j 图 + 本地 qwen)"
  PYTHONUTF8=1 "$PY" scripts/preflight.py 2>&1 | tail -8
  echo ""
  echo "## 4. respond_cli(处置台账人审 CLI 可跑;reset 后应空)"
  PYTHONUTF8=1 "$PY" -m soc_agent.respond_cli list 2>&1 | tail -6
  echo ""
  echo "## 5. 处置面连通 + 护栏派生 + 慢研判端到端 + 第三类图台账"
  PYTHONUTF8=1 "$PY" scripts/verify_all.py
  echo ""
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: verify-all $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
