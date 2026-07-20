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
    def __init__(self, base_url, model, api_key="EMPTY", timeout=600, temperature=0.1,
                 enable_thinking=False):
        import httpx                            # 惰性导入,纯逻辑测试无需装 openai/httpx
        from openai import OpenAI
        self._client = OpenAI(
            base_url=base_url,
            api_key=api_key or "EMPTY",
            max_retries=0,                       # ★不重试:本地模型超时=真慢,重试只会 3× 浪费(122b 15min 惨案)
            http_client=httpx.Client(trust_env=False, timeout=timeout),  # ★绕过公司代理
        )
        self.model = model
        self.temperature = temperature
        # ★默认关掉 qwen3 思维链:开着的话强制工具调用(tool_choice=required)会先吐一大段 Thinking,
        #   既拖慢(易读超时)又污染工具输出。SOC 研判只要干净的工具调用,不要思维过程。
        #   非思维模型忽略该模板参数,无害。要看思维过程再传 enable_thinking=True。
        self.enable_thinking = enable_thinking

    def chat(self, messages, tools=None, tool_choice=None) -> LLMResponse:
        kwargs = dict(model=self.model, messages=messages, tools=tools or None,
                      temperature=self.temperature)
        if tool_choice is not None and tools:
            kwargs["tool_choice"] = tool_choice    # "required"=必须调工具(逼它别光说话)
        if not self.enable_thinking:               # vLLM 透传给 qwen3 chat 模板 → 关思维
            kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
        resp = self._client.chat.completions.create(**kwargs)
        return parse_openai_response(resp.choices[0].message)
