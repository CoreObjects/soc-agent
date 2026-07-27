#!/usr/bin/env bash
# server2:诊断"为啥 create_app 只有 /api/healthz、dist 未托管"。打印 HEAD/文件/导入来源/路由全表/pip。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/web-doctor.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/web-doctor.out"
{
  echo "=== web-doctor  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- git HEAD --"; git rev-parse --short HEAD 2>&1; git log --oneline -3 2>&1
  echo "-- 工作树关键文件 --"
  echo "routes/:"; ls soc_agent/web/routes/ 2>&1
  echo "dist/index.html:"; ls -la soc_agent/frontend/dist/index.html 2>&1
  echo "app.py 关键行:"; grep -nE "include_router|from .routes import|def create_app" soc_agent/web/app.py 2>&1
  echo "-- python 到底导入的是哪个 soc_agent / app --"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import os, sys
sys.path.insert(0, os.getcwd())
import soc_agent
print("  soc_agent.__file__ =", soc_agent.__file__)
import soc_agent.web.app as a
print("  web.app.__file__   =", a.__file__)
app = a.create_app()
paths = sorted({getattr(r, "path", "?") for r in app.routes})
print("  路由总数 =", len(paths))
for p in paths:
    print("     ", p)
PYEOF
  echo "-- .venv312 里 soc-agent 装法(editable? 冻结副本?)--"
  "$PY" -m pip show soc-agent 2>/dev/null | grep -iE "Name|Version|Location|Editable" || echo "  (pip 未装 soc-agent — 靠 cwd 跑)"
  echo "  meta_path/.pth 里的 __editable__:"
  find .venv312 -maxdepth 4 -name "*.pth" 2>/dev/null | xargs grep -l "soc_agent\|__editable__" 2>/dev/null | head
  echo "  site-packages 里有没有 soc_agent 冻结副本:"
  find .venv312 -maxdepth 5 -path "*site-packages/soc_agent/web/app.py" 2>/dev/null | head
  echo "-- fastapi 版本 --"
  "$PY" -m pip show fastapi 2>/dev/null | grep -iE "Name|Version" || echo "  fastapi 没装?"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: web-doctor" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
