#!/usr/bin/env bash
# server2:第二类经验【威胁分支】端到端真机验证。结果 ferry 回来。
# 前置(按序):① GOAD 跑 deploy/setup/42-kerberoast-user.sh(jon.snow 域内 roast 造 TP 告警)+ 等 ingest
#             ② bash scripts/reset_pristine.sh(清空经验/案例,让 pass1 生死线考试无历史干扰)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/e2e_threat.sh
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }
./.venv/bin/pip install -q "psycopg2-binary>=2.9" >/dev/null 2>&1 || true

mkdir -p feedback
FB="feedback/e2e-threat.out"
{
  echo "=== e2e-threat  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/e2e_threat.py
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: e2e-threat $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
