#!/usr/bin/env bash
# server2:定位 LLM 慢的根 —— 同一请求,几种"关思维"方式各测一次,看 completion_tokens / tokens每秒 / reasoning_content。
# 生成 token 巨多=思维链没关掉(生成海量隐藏推理);token 少但仍慢=硬件/服务本身慢(领导那边)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/llm-speed-probe.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/llm-speed-probe.out"
{
  echo "=== llm-speed-probe  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import time
import httpx
from openai import OpenAI
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
cfg = Config.from_env(dotenv_path=".env")
print(f"端点={cfg.llm_api_base}  模型={cfg.llm_model}\n")

client = OpenAI(base_url=cfg.llm_api_base, api_key=cfg.llm_api_key or "EMPTY",
                max_retries=0, http_client=httpx.Client(trust_env=False, timeout=600))

# 中等 prompt + 强制工具调用(仿投研判器/浅层)
ctx = ("这是一条安全告警:账号 robb.stark(NORTH 域,非特权)通过网络登录(logon type 3)到成员机 castelblack,"
       "有历史基线(登录 42 次),扇出 3 台。请判断是否为攻击并调用 judge 工具给出 verdict。" * 3)
messages = [{"role": "system", "content": "你是 SOC 研判助手,只调用工具。"},
            {"role": "user", "content": ctx}]
tools = [{"type": "function", "function": {"name": "judge", "description": "给出研判结论",
          "parameters": {"type": "object", "properties": {
              "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "suspicious"]},
              "rationale": {"type": "string"}}, "required": ["verdict"]}}}]

def probe(label, extra_body):
    t = time.time()
    try:
        r = client.chat.completions.create(model=cfg.llm_model, messages=messages, tools=tools,
                                           tool_choice="required", temperature=0.1,
                                           extra_body=extra_body)
        dt = time.time() - t
        u = r.usage
        m = r.choices[0].message
        rc = getattr(m, "reasoning_content", None) or ""
        ct = getattr(u, "completion_tokens", 0) or 0
        print(f"[{label}]")
        print(f"    {dt:6.1f}s  prompt_tokens={getattr(u,'prompt_tokens',0)} completion_tokens={ct}  "
              f"→ {ct/dt:.1f} tok/s")
        print(f"    reasoning_content={'有' if rc else '无'}({len(rc)}字符)  tool_calls={len(m.tool_calls or [])}")
    except Exception as e:
        print(f"[{label}] ❌ {time.time()-t:.1f}s  {type(e).__name__}: {str(e)[:120]}")

# ① 我们代码现用的方式:extra_body chat_template_kwargs enable_thinking=False
probe("关思维:extra_body chat_template_kwargs.enable_thinking=False(我们代码现用)",
      {"chat_template_kwargs": {"enable_thinking": False}})
# ② 完全不传(网关默认;若默认开思维,这条会明显更慢/token更多)
probe("默认(不传 extra_body)", None)
# ③ prompt 末尾加 /no_think(部分 qwen 用这个关)
messages[-1]["content"] = ctx + "\n/no_think"
probe("prompt 加 /no_think", None)
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: llm-speed-probe" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
