#!/usr/bin/env bash
# server2:研判+处置控制台 —— 探活自检(ferry)/ 构建前端 / 起服务。
# 前置:.venv312 + pip install '.[web]'(fastapi/uvicorn);.env 配 NEO4J_*/LLM_*/OG_*;可选 SOC_WEB_TOKEN。
# 用法:
#   自检(建 app + 列 /api 路由 + 探 /api/healthz,ferry 回结果):
#     cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/web.sh
#   构建前端 dist(需 node):        bash scripts/web.sh --build
#   起服务(常驻,后台;:8000):    nohup bash scripts/web.sh --serve >/dev/null 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || { echo "!! 缺 venv —— 先建 .venv312"; exit 1; }

MODE="${1:-probe}"

if [ "$MODE" = "--build" ]; then
  command -v npm >/dev/null || { echo "!! 无 npm —— 装 node 再来"; exit 1; }
  npm --prefix soc_agent/frontend install --no-audit --no-fund
  npm --prefix soc_agent/frontend run build
  echo "✅ 前端 dist:soc_agent/frontend/dist(FastAPI 会自动托管)"
  exit 0
fi

if [ "$MODE" = "--serve" ]; then
  echo "# 起 uvicorn :8000(有 frontend/dist 则一并托管;manual 模式默认)"
  exec env PYTHONUTF8=1 "$PY" -m uvicorn soc_agent.web.app:app --host 0.0.0.0 --port 8000
fi

# 默认:探活自检 + ferry(不连 neo4j,只验 app 装配 + healthz)
mkdir -p feedback
FB="feedback/web-probe.out"
{
  echo "=== web probe  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
try:
    from fastapi.testclient import TestClient
    from soc_agent.web.app import create_app
except Exception as e:
    print("!! 建 app 失败(是否 pip install '.[web]'?):", repr(e)); sys.exit(1)
app = create_app()
# ★用 openapi 列路由:fastapi 0.140+ 把 include_router 挂成子应用,直接遍历 app.routes 看不到(会误判"只有 healthz")
paths = sorted((app.openapi() or {}).get("paths", {}).keys())
print("API 路由(%d 条):" % len(paths))
for p in paths:
    print("   ", p)
c = TestClient(app)
print("healthz:", c.get("/api/healthz").status_code, c.get("/api/healthz").json())
print("前端托管 / :", c.get("/").status_code, "  SPA 回退 /queue :", c.get("/queue").status_code)
import os.path as _p
dist = _p.join("soc_agent", "frontend", "dist", "index.html")
print("前端 dist:", "已入库(会被托管)" if _p.isfile(dist) else "未入库(纯 API;bash scripts/web.sh --build 或拉最新)")
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: web probe" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
