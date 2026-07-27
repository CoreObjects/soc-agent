#!/usr/bin/env bash
# server2:诊断"create_app 只有 healthz、6 个 API router 没进"。清 pycache + 逐 router 数路由 + 全表。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/web-doctor.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/web-doctor.out"
{
  echo "=== web-doctor v2  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- git HEAD --"; git rev-parse --short HEAD 2>&1
  echo "-- 清 __pycache__(排除陈旧 .pyc)--"
  find soc_agent -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
  echo "  cleared"
  echo "-- 逐路由模块:file + router 里几条路由 --"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, traceback, importlib
sys.path.insert(0, os.getcwd())
for name in ["alerts", "plans", "stats", "experience", "config", "chat"]:
    try:
        m = importlib.import_module(f"soc_agent.web.routes.{name}")
        rts = [(getattr(r, "path", "?"), sorted(getattr(r, "methods", []) or [])) for r in m.router.routes]
        print(f"  [{name}] file={m.__file__}")
        print(f"        prefix={getattr(m.router,'prefix','?')}  routes={len(rts)}: {rts}")
    except Exception as e:
        print(f"  [{name}] IMPORT FAIL: {e!r}")
        traceback.print_exc()
print("-- create_app 全量路由 --")
try:
    from soc_agent.web.app import create_app
    app = create_app()
    print("  ", sorted({getattr(r, "path", "?") for r in app.routes}))
except Exception:
    traceback.print_exc()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: web-doctor v2" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
