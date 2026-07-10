"""QwenClient 的响应解析(纯逻辑,本机可测;网络部分在 server2 验)。

OpenAI chat 返回的 message → LLMResponse:解 tool_calls、把 JSON 字符串参数解成 dict、
无 tool_calls 即最终文本、坏 JSON 不崩(留原文)。
"""
from types import SimpleNamespace

from soc_agent.llm.qwen import parse_openai_response


def _tc(cid, name, arguments):
    return SimpleNamespace(id=cid, function=SimpleNamespace(name=name, arguments=arguments))


def test_parse_tool_calls_with_json_string_args():
    msg = SimpleNamespace(content="", tool_calls=[_tc("c1", "run_cypher", '{"query": "MATCH (n) RETURN n"}')])
    r = parse_openai_response(msg)
    assert r.is_final is False
    assert r.tool_calls[0].name == "run_cypher"
    assert r.tool_calls[0].arguments == {"query": "MATCH (n) RETURN n"}


def test_parse_final_text_no_tool_calls():
    r = parse_openai_response(SimpleNamespace(content="研判完成", tool_calls=None))
    assert r.is_final is True
    assert r.content == "研判完成"


def test_parse_handles_dict_args():
    msg = SimpleNamespace(content=None, tool_calls=[_tc("c1", "finalize_verdict", {"verdict": "benign"})])
    r = parse_openai_response(msg)
    assert r.tool_calls[0].arguments == {"verdict": "benign"}
    assert r.content == ""


def test_parse_bad_json_args_kept_as_raw():
    msg = SimpleNamespace(content="", tool_calls=[_tc("c1", "x", "{not valid json")])
    r = parse_openai_response(msg)
    assert "_raw" in r.tool_calls[0].arguments
