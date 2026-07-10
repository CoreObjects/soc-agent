"""QwenClient —— 本地 qwen(vLLM,OpenAI 兼容,native tool calling)的 LLMClient 实现。

- 无 key:填占位 "EMPTY"。
- ★必须 trust_env=False:否则到内网模型会被公司代理劫(和入图 ES 一样)。
- 解析(parse_openai_response)是纯逻辑、本机可测;网络在 server2 验。
- openai/httpx 惰性导入(只在 QwenClient.__init__),不污染纯逻辑测试。
"""
import json

from . import LLMResponse, ToolCall

__all__ = ["QwenClient", "parse_openai_response"]


def parse_openai_response(message) -> LLMResponse:
    """OpenAI chat 返回的 message 对象 → LLMResponse。"""
    tool_calls = []
    for tc in (getattr(message, "tool_calls", None) or []):
        args = tc.function.arguments
        if isinstance(args, str):
            try:
                args = json.loads(args) if args.strip() else {}
            except (ValueError, TypeError):
                args = {"_raw": args}          # 坏 JSON 不崩,留原文供排查
        tool_calls.append(ToolCall(id=getattr(tc, "id", None) or "", name=tc.function.name,
                                   arguments=args or {}))
    return LLMResponse(
        tool_calls=tool_calls,
        content=getattr(message, "content", None) or "",
        finish_reason=getattr(message, "finish_reason", None),
    )


class QwenClient:
    def __init__(self, base_url, model, api_key="EMPTY", timeout=180, temperature=0.1):
        import httpx                            # 惰性导入,纯逻辑测试无需装 openai/httpx
        from openai import OpenAI
        self._client = OpenAI(
            base_url=base_url,
            api_key=api_key or "EMPTY",
            http_client=httpx.Client(trust_env=False, timeout=timeout),  # ★绕过公司代理
        )
        self.model = model
        self.temperature = temperature

    def chat(self, messages, tools=None) -> LLMResponse:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools or None,
            temperature=self.temperature,
        )
        return parse_openai_response(resp.choices[0].message)
