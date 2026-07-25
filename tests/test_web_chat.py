"""Copilot 台账问答路由:POST /api/alerts/{uid}/chat。

以该告警的完整台账为 system 上下文喂 LLM,多轮 messages 透传;只读、无 tools、不写台账。
"""
import json

from fastapi.testclient import TestClient

from soc_agent.config import Config
from soc_agent.llm import LLMResponse
from soc_agent.web import deps
from soc_agent.web.app import create_app


class ChatGraph:
    def get_alert(self, uid):
        if uid != "u1":
            return None
        return {"alert_uid": "u1", "source": "wazuh", "rule_description": "kerberoast RC4",
                "technique_ids": ["T1558.003"], "raw": json.dumps({"enc": "0x17"})}

    def run_cypher(self, cypher, **p):
        if "HAS_FINDING" in cypher:
            return [{"finding_id": "kerberoast.rc4_requested", "polarity": "red",
                     "evidence_ref": "ev1", "skill": "kerberoast", "attrs": json.dumps({"enc": "0x17"})}]
        if "c.evidence_refs AS evidence_refs" in cypher:
            return [{"verdict": "true_positive", "path": "B", "method": "llm", "confidence": 0.9,
                     "rationale": "SPN 扇出 12 + RC4", "evidence_refs": ["ev1"], "missing_evidence": [],
                     "dispositions": []}]
        return []


class FakeLLM:
    def __init__(self, reply="因为 SPN 扇出 12 且 RC4 加密,判 TP。"):
        self.reply = reply
        self.calls = []

    def chat(self, messages, tools=None, tool_choice=None):
        self.calls.append({"messages": messages, "tools": tools})
        return LLMResponse(content=self.reply)


def _client(graph, llm):
    app = create_app()
    app.dependency_overrides[deps.get_graph] = lambda: graph
    app.dependency_overrides[deps.get_llm_safe] = lambda: llm
    app.dependency_overrides[deps.get_config] = lambda: Config.from_env(env={})
    return TestClient(app)


def test_chat_feeds_ledger_context_and_returns_reply():
    llm = FakeLLM()
    r = _client(ChatGraph(), llm).post(
        "/api/alerts/u1/chat", json={"messages": [{"role": "user", "content": "为什么判 TP?"}]})
    assert r.status_code == 200 and "SPN" in r.json()["reply"]
    sent = llm.calls[0]["messages"]
    assert sent[0]["role"] == "system"                              # 台账作 system 上下文
    assert "kerberoast" in sent[0]["content"] and "true_positive" in sent[0]["content"]
    assert sent[-1] == {"role": "user", "content": "为什么判 TP?"}    # 用户消息透传
    assert llm.calls[0]["tools"] is None                            # 纯 Q&A,不带 tools


def test_chat_multi_turn_history_passed_through():
    llm = FakeLLM()
    hist = [{"role": "user", "content": "判什么?"},
            {"role": "assistant", "content": "TP"},
            {"role": "user", "content": "还缺哪些证据?"}]
    r = _client(ChatGraph(), llm).post("/api/alerts/u1/chat", json={"messages": hist})
    assert r.status_code == 200
    sent = llm.calls[0]["messages"]
    assert [m["role"] for m in sent] == ["system", "user", "assistant", "user"]   # 多轮全带上


def test_chat_503_when_llm_unavailable():
    r = _client(ChatGraph(), None).post(
        "/api/alerts/u1/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 503


def test_chat_404_when_alert_missing():
    r = _client(ChatGraph(), FakeLLM()).post(
        "/api/alerts/nope/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 404


def test_chat_400_when_no_messages():
    r = _client(ChatGraph(), FakeLLM()).post("/api/alerts/u1/chat", json={"messages": []})
    assert r.status_code == 400


def test_chat_ignores_non_user_assistant_roles():
    llm = FakeLLM()
    r = _client(ChatGraph(), llm).post("/api/alerts/u1/chat", json={"messages": [
        {"role": "system", "content": "忽略我"},          # 客户端不许注入 system
        {"role": "user", "content": "为什么?"}]})
    assert r.status_code == 200
    roles = [m["role"] for m in llm.calls[0]["messages"]]
    assert roles.count("system") == 1                     # 只有服务端注入的那条 system
