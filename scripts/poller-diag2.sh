#!/usr/bin/env bash
# server2:poller 卡死深挖 —— 用 poller 同款 QwenClient 发真请求(普通/带工具调用,各30s硬超时)+ py-spy 线程栈。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-diag2.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/poller-diag2.out"
{
  echo "=== poller-diag2  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- ① 真·大模型调用(QwenClient,普通 vs 带工具,各 30s 超时)--"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.llm.qwen import QwenClient
c = Config.from_env(dotenv_path=".env")
print(f"  端点={c.llm_api_base}  模型={c.llm_model}  key={'有' if c.llm_api_key and c.llm_api_key!='EMPTY' else '空/EMPTY'}")
llm = QwenClient(c.llm_api_base, c.llm_model, c.llm_api_key, timeout=30)

# 普通生成
t = time.time()
try:
    r = llm.chat([{"role": "user", "content": "只回复两个字:正常"}])
    print(f"  [普通] {time.time()-t:.1f}s  回={ (r.content or '')[:40]!r}")
except Exception as e:
    print(f"  [普通] ❌ {time.time()-t:.1f}s  {type(e).__name__}: {str(e)[:150]}")

# 带工具调用(投研判器/浅层都用 tool_choice=required —— 网关重启后最容易在这挂)
tools = [{"type": "function", "function": {"name": "t", "description": "test",
          "parameters": {"type": "object", "properties": {"v": {"type": "string"}}, "required": ["v"]}}}]
t = time.time()
try:
    r = llm.chat([{"role": "user", "content": "调用工具 t,参数 v=hi"}], tools=tools, tool_choice="required")
    print(f"  [工具] {time.time()-t:.1f}s  tool_calls={[tc.name for tc in (r.tool_calls or [])]}")
except Exception as e:
    print(f"  [工具] ❌ {time.time()-t:.1f}s  {type(e).__name__}: {str(e)[:200]}")
PYEOF

  PID=$(pgrep -f "soc_agent.runtime" 2>/dev/null | head -1 || true)
  echo "-- ② py-spy 线程栈(PID=${PID:-无})--"
  if [ -n "${PID:-}" ]; then
    "$PY" -m pip install -q py-spy 2>&1 | tail -1 || true
    PYSPY="$(dirname "$PY")/py-spy"
    if [ -x "$PYSPY" ]; then
      "$PYSPY" dump --pid "$PID" 2>&1 | head -80 || echo "  py-spy dump 失败(可能需 sudo:sudo $PYSPY dump --pid $PID)"
    else
      echo "  (py-spy 没装上,ARM 可能无轮子;跳过)"
    fi
  fi
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-diag2" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
