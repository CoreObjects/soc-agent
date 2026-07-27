#!/usr/bin/env bash
# server2:强制重启 web(强杀旧 uvicorn→确认端口空→起新的)+ curl /api/stats 验证后端确实拾取最新字段。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/web-restart.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p logs feedback
FB="feedback/web-restart.out"
{
  echo "=== web-restart  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- 现有 uvicorn 进程 --"; pgrep -af "uvicorn soc_agent.web.app" 2>/dev/null || echo "  (无)"
  echo "-- 强杀所有 uvicorn --"; pkill -9 -f "uvicorn soc_agent.web.app" 2>/dev/null || true; sleep 2
  echo "-- 8000 端口是否还被占 --"; (ss -ltnp 2>/dev/null | grep ':8000' || netstat -ltnp 2>/dev/null | grep ':8000' || echo "  ✅ 8000 已空闲")
  echo "-- 起新的 uvicorn --"
  nohup env PYTHONUTF8=1 "$PY" -m uvicorn soc_agent.web.app:app --host 0.0.0.0 --port 8000 > logs/web.log 2>&1 &
  sleep 5
  echo "  PID=$!"
  echo "-- 启动日志(看有无 'address already in use' 或报错)--"; tail -6 logs/web.log 2>/dev/null
  echo "-- curl /api/stats 验证后端字段(应含 sig_reuse / deep_reuse)--"
  curl -s --noproxy '*' -m 15 http://127.0.0.1:8000/api/stats \
    | "$PY" -c "import sys,json; r=json.load(sys.stdin).get('reuse',{}); print('  reuse keys:', sorted(r.keys())); print('  sig_reuse=%s deep_reuse=%s reuse_hits=%s' % (r.get('sig_reuse'), r.get('deep_reuse'), r.get('reuse_hits')))" 2>&1 \
    || echo "  ⚠ curl/解析失败(服务没起好?看上面日志)"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: web-restart" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
