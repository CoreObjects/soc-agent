"""诊断:直连 qwen(OpenAI 兼容)看**浅层提示词下 qwen 到底吐什么** —— 排 openJiuwen 'Json parse error'。

分别试:关思维/开思维 × response_format(json_object / 无)。打印原始 content(截断)+ 有没有
单独的 reasoning_content。据此定 openJiuwen 侧怎么改(关思维?robust 解析?)。一次三四个调用,几分钟。
真实端点/口令只在 .env,不打印。
"""
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_agent.cascade.prompt import SHALLOW_PROMPT                            # noqa: E402
from soc_agent.config import Config                                           # noqa: E402

cfg = Config.from_env(dotenv_path=str(Path(__file__).resolve().parents[1] / ".env"))
print(f"# qwen_shallow_probe  base={cfg.llm_api_base}  model={cfg.llm_model}  timeout={cfg.llm_timeout}")

import httpx                                                                   # noqa: E402
from openai import OpenAI                                                      # noqa: E402

client = OpenAI(base_url=cfg.llm_api_base, api_key=cfg.llm_api_key or "EMPTY", max_retries=0,
                http_client=httpx.Client(trust_env=False, timeout=cfg.llm_timeout))  # 绕公司代理,同 QwenClient

MSGS = [
    {"role": "system", "content": SHALLOW_PROMPT},
    {"role": "user", "content": '{"rule_description":"WAF: SQL injection attempt on /login",'
                                '"source":"waf","severity":5,"technique_ids":["T1190"]}'},
]
NOTHINK = {"extra_body": {"chat_template_kwargs": {"enable_thinking": False}}}


def call(tag, **extra):
    print(f"\n===== {tag} =====")
    try:
        t = time.time()
        r = client.chat.completions.create(model=cfg.llm_model, messages=MSGS, temperature=0.1, **extra)
        m = r.choices[0].message
        print(f"  {time.time() - t:.0f}s  finish={r.choices[0].finish_reason}")
        rc = getattr(m, "reasoning_content", None)
        print(f"  reasoning_content(前160): {rc[:160]!r}" if rc else "  reasoning_content: (无/未分离)")
        print(f"  content(前700): {(m.content or '')[:700]!r}")
    except Exception:
        print("  [FAIL]\n" + traceback.format_exc()[:900])


call("A 关思维 + response_format=json_object", response_format={"type": "json_object"}, **NOTHINK)
call("B 关思维 + 无 response_format", **NOTHINK)
call("C 开思维(=openJiuwen 现状)+ json_object", response_format={"type": "json_object"})
print("\n# done")
