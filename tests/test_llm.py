"""LLM 抽象:可插拔的 chat(messages, tools)->LLMResponse。

真实现 = QwenClient(openai 兼容,server2 上跑);测试用 FakeLLMClient 脚本化返回,
让 orchestrator 的 tool-calling 循环在本机完整可测(不碰真模型)。
"""
import pytest

from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall


def test_toolcall_and_response_shapes():
    tc = ToolCall(id="c1", name="run_cypher", arguments={"query": "MATCH (n) RETURN n"})
    r = LLMResponse(tool_calls=[tc])
    assert r.tool_calls[0].name == "run_cypher"
    assert r.tool_calls[0].arguments["query"].startswith("MATCH")
    assert r.is_final is False


def test_response_final_when_no_tool_calls():
    r = LLMResponse(content="研判完成")
    assert r.is_final is True
    assert r.content == "研判完成"


def test_fake_llm_returns_scripted_responses_in_order():
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "..."})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict", {"verdict": "benign"})]),
    ])
    a = llm.chat([{"role": "user", "content": "x"}], tools=[])
    assert a.tool_calls[0].id == "c1"
    b = llm.chat([{"role": "user", "content": "x"}], tools=[])
    assert b.tool_calls[0].name == "finalize_verdict"


def test_fake_llm_records_calls():
    llm = FakeLLMClient([LLMResponse(content="ok")])
    llm.chat([{"role": "user", "content": "hi"}], tools=[{"name": "t"}])
    assert llm.calls[0]["messages"][0]["content"] == "hi"
    assert llm.calls[0]["tools"] == [{"name": "t"}]


def test_fake_llm_raises_when_exhausted():
    llm = FakeLLMClient([LLMResponse(content="ok")])
    llm.chat([], None)
    with pytest.raises(IndexError):
        llm.chat([], None)
