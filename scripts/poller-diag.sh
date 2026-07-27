#!/usr/bin/env bash
# server2:poller 卡死定位 —— 硬超时探 LLM(/models)+ openGauss(SELECT 1)+ 线程栈(py-spy 有才打)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-diag.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/poller-diag.out"
{
  echo "=== poller-diag  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="

  LLM=$(grep -E "^LLM_API_BASE=" .env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
  echo "-- ① LLM 端点 ${LLM}/models(硬超时 10s)--"
  curl -s --noproxy '*' -m 10 "${LLM%/}/models" -o /dev/null \
    -w "  HTTP %{http_code}  用时 %{time_total}s\n" \
    || echo "  ❌ curl 失败/超时 → 大模型不通或卡死(领导的 qwen 服务?)"

  echo "-- ② openGauss SELECT 1(硬超时 12s)--"
  if timeout 12 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
import psycopg2
c = Config.from_env(dotenv_path=".env")
t = time.time()
conn = psycopg2.connect(host=c.og_host, port=c.og_port, dbname=c.og_database,
                        user=c.og_user, password=c.og_password, connect_timeout=8)
cur = conn.cursor(); cur.execute("SELECT 1"); cur.fetchone(); conn.close()
print(f"  ✅ openGauss OK  用时 {time.time()-t:.2f}s")
PYEOF
  then :; else
    echo "  ❌ openGauss SELECT 1 超时/失败(12s)—— 库卡死。经验库共享锁会因此把所有 worker 冻住。"
    echo "     修:sudo podman restart opengauss  然后重启 poller"
  fi

  PID=$(pgrep -f "soc_agent.runtime" 2>/dev/null | head -1 || true)
  echo "-- ③ poller 线程栈(PID=${PID:-无};py-spy 有才打,看 8 个 worker 卡在哪一行)--"
  if [ -n "${PID:-}" ] && command -v py-spy >/dev/null 2>&1; then
    py-spy dump --pid "$PID" 2>&1 | head -70 || echo "  py-spy dump 失败(可能要 root)"
  elif [ -n "${PID:-}" ]; then
    echo "  (无 py-spy;装了能看精确卡点:$PY -m pip install py-spy;或 sudo 跑)"
    echo "  退而求其次——进程状态:"; ps -o pid,stat,etime,pcpu,pmem,cmd -p "$PID" 2>/dev/null || true
  fi
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-diag" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
