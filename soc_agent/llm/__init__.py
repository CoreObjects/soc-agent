"""LLM 抽象:可插拔的 chat(messages, tools) -> LLMResponse。

- LLMClient: 接口(qwen 现在,后续可换 Claude/别的)。
- FakeLLMClient: 脚本化,给 orchestrator 循环做本机 TDD。
- QwenClient: 真实现(openai 兼容),在 soc_agent.llm.qwen,惰性导入 openai,不污染纯逻辑测试。
"""
from dataclasses import dataclass, field
from typing import Optional, Protocol

__all__ = ["ToolCall", "LLMResponse", "LLMClient", "FakeLLMClient"]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    """一次 chat 的返回:要么请求工具调用,要么给最终文本。"""
    tool_calls: list = field(default_factory=list)   # list[ToolCall]
    content: str = ""
    finish_reason: Optional[str] = None

    @property
    def is_final(self) -> bool:
        return not self.tool_calls


class LLMClient(Protocol):
    def chat(self, messages: list, tools: Optional[list] = None,
             tool_choice=None) -> LLMResponse:
        ...


class FakeLLMClient:
    """按序返回脚本化的 LLMResponse,并记录每次 chat 的入参(供断言)。"""

    def __init__(self, scripted: list):
        self._scripted = list(scripted)
        self._i = 0
        self.calls: list = []

    def chat(self, messages: list, tools: Optional[list] = None,
             tool_choice=None) -> LLMResponse:
        self.calls.append({"messages": messages, "tools": tools, "tool_choice": tool_choice})
        resp = self._scripted[self._i]      # 脚本耗尽 → IndexError(测试可断言)
        self._i += 1
        return resp
