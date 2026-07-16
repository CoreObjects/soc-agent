"""顶层编排 FastSlowInvestigator —— 快通道跑全部签名+全局先证伪碰撞(0 LLM) + 慢通道当场沉淀规则。

run-1(vagrant)无规则 → 慢通道(1 次 LLM)→ 沉淀 active 规则;
run-2(hacker2,同签名不同实例)→ 快通道命中同规则、★0 LLM、结论正确、处置换实例填对。
先证伪:机器账号跨域引荐的豁免规则也能快通道短路成 FP。
★快通道靠 signatures.run_all 出签名(本测直接 patch run_all 控制签名),不再靠 skill.discriminate/路由。
"""
from types import SimpleNamespace

import soc_agent.patterns.signatures as signatures_mod
from soc_agent.composer import Composer
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import Alert
from soc_agent.orchestrator import FastSlowInvestigator, RecipeInvestigator
from soc_agent.patterns.repository import InMemoryPatternRepository
from soc_agent.response.interface import Interface


class FakeGraph:
    def run_cypher(self, q, **p):
        return []


def _alert(uid):
    return Alert.from_node({"alert_uid": uid, "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


_SPRAY_LAYERS = [
    {"layer": "exculpatory", "features": {"req_is_machine": False, "same_domain": True}},
    {"layer": "incriminating", "features": {"req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}},
]


def _entry(bindings, layers=None):
    return {"skill": "kerberoast", "layers": layers or _SPRAY_LAYERS, "bindings": bindings}


def _patch_sigs(monkeypatch, entry):
    """控制 signatures.run_all 的输出(=快通道拿到的签名 list)。"""
    monkeypatch.setattr(signatures_mod, "run_all", lambda g, a, s=None: [entry])


def _skill():
    return SimpleNamespace(name="kerberoast", technique_ids=["T1558.003"], is_generic=False,
                           methodology="m", recipe=lambda g, a, s=None: {"ev": "x"})


def _registry(skill):
    return SimpleNamespace(select=lambda a, layer=None: skill,
                           generic_for_layer=lambda l: None, specific=lambda: [skill], all=lambda: [skill])


def _finalize(verdict, rationale="r"):
    return LLMResponse(tool_calls=[ToolCall("c", "finalize_verdict",
                                            {"verdict": verdict, "confidence": 0.92, "rationale": rationale})])


def _iface():
    return Interface.from_dict({"version": "t", "primitives": [
        {"id": "disable_account", "category": "identity", "gating": "gated", "risk_default": "high",
         "target": {"kind": "account", "key_field": "sam"},
         "params": [{"name": "sam", "required": True, "source": "entity_role"}]},
    ]})


def _compose_disable(role="requester"):
    return LLMResponse(tool_calls=[ToolCall("c", "compose_response", {"steps": [
        {"primitive": "disable_account", "params": {"sam": {"role": role}}, "risk": "high"}]})])


def _wire(repo, skill, llm, composer_llm=None):
    graph = FakeGraph()
    reg = _registry(skill)
    recipe_inv = RecipeInvestigator(llm=llm, graph=graph, schema="S", registry=reg, agent_name="qwen")
    composer = Composer(llm=composer_llm, iface=_iface()) if composer_llm is not None else None
    return FastSlowInvestigator(graph=graph, repo=repo, registry=reg, recipe_inv=recipe_inv, composer=composer)


def test_slow_first_then_fast_reuse_zero_llm(monkeypatch):
    repo = InMemoryPatternRepository()
    llm = FakeLLMClient([_finalize("true_positive", rationale="RC4 扇出")])          # 研判 LLM,只给 run-1
    comp_llm = FakeLLMClient([_compose_disable("requester")])                         # composer LLM,只给 run-1
    orch = _wire(repo, _skill(), llm, composer_llm=comp_llm)

    _patch_sigs(monkeypatch, _entry({"requester": "vagrant", "target_service": "sql_svc"}))
    r1 = orch.investigate(_alert("a1"))
    assert r1.path == "B" and r1.verdict.verdict == "true_positive"
    assert r1.dispositions[0].action == "disable_account" and r1.dispositions[0].target == "vagrant"
    assert len(repo.all()) == 1 and repo.all()[0].status == "active"
    assert repo.all()[0].plan[0].primitive == "disable_account"    # composer 计划固化进规则
    assert len(llm.calls) == 1 and len(comp_llm.calls) == 1

    # 换实例:同签名、requester 变
    _patch_sigs(monkeypatch, _entry({"requester": "hacker2", "target_service": "svc2"}))
    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "A"                                    # 快通道
    assert r2.verdict.verdict == "true_positive"
    assert r2.verdict.pattern == repo.all()[0].pattern_id    # 指向同一规则
    assert r2.dispositions[0].action == "disable_account" and r2.dispositions[0].target == "hacker2"
    assert len(llm.calls) == 1 and len(comp_llm.calls) == 1  # ★run-2 研判/组装都没叫 LLM


def test_no_dup_rule_on_repeat_same_features(monkeypatch):
    repo = InMemoryPatternRepository()
    llm = FakeLLMClient([_finalize("true_positive")])
    comp_llm = FakeLLMClient([_compose_disable("requester")])
    orch = _wire(repo, _skill(), llm, composer_llm=comp_llm)
    _patch_sigs(monkeypatch, _entry({"requester": "vagrant", "target_service": "s"}))
    orch.investigate(_alert("a1"))            # 慢通道生成
    _patch_sigs(monkeypatch, _entry({"requester": "hacker2", "target_service": "s2"}))
    orch.investigate(_alert("a2"))            # 快通道命中(不再 mint)
    assert len(repo.all()) == 1              # 去重成一条


def test_exculpatory_fp_short_circuits(monkeypatch):
    repo = InMemoryPatternRepository()
    exc = [{"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}},
           {"layer": "incriminating", "features": {"req_is_machine": True, "same_domain": False, "enc": "RC4", "spn_fanout": ">=5"}}]
    llm = FakeLLMClient([_finalize("false_positive", rationale="机器账号跨域引荐票")])
    orch = _wire(repo, _skill(), llm)

    _patch_sigs(monkeypatch, _entry({"requester": "WINTERFELL$"}, layers=exc))
    r1 = orch.investigate(_alert("a1"))
    assert r1.verdict.verdict == "false_positive"
    assert repo.all()[0].layer == "exculpatory" and repo.all()[0].status == "active"

    _patch_sigs(monkeypatch, _entry({"requester": "MEEREEN$"}, layers=exc))
    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "A" and r2.verdict.verdict == "false_positive"   # 豁免层快通道短路
    assert len(llm.calls) == 1


def test_slow_result_pattern_is_rule_sig_not_llm_freetext(monkeypatch):
    # 慢通道 result.verdict.pattern 必须=生成规则的 sig_hash(收敛键),不是 LLM 自由文本
    repo = InMemoryPatternRepository()
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c", "finalize_verdict", {
        "verdict": "true_positive", "confidence": 0.9, "rationale": "r", "pattern": "my_free_text"})])])
    comp_llm = FakeLLMClient([_compose_disable("requester")])
    orch = _wire(repo, _skill(), llm, composer_llm=comp_llm)
    _patch_sigs(monkeypatch, _entry({"requester": "vagrant"}))
    r = orch.investigate(_alert("a1"))
    minted = repo.all()[0]
    assert r.verdict.pattern == minted.pattern_id      # = sig_hash
    assert r.verdict.pattern != "my_free_text"         # 不认 LLM 自由文本


def test_suspicious_mints_pending_not_active(monkeypatch):
    repo = InMemoryPatternRepository()
    llm = FakeLLMClient([_finalize("suspicious", rationale="证据不足")])
    orch = _wire(repo, _skill(), llm)
    _patch_sigs(monkeypatch, _entry({"requester": "u"}))
    orch.investigate(_alert("a1"))
    assert repo.all()[0].status == "pending"          # 可疑待采纳,不自动 active
    # pending 不上快通道 → 仍走慢通道(再喂一个 LLM 响应)
    llm._scripted.append(_finalize("suspicious"))
    _patch_sigs(monkeypatch, _entry({"requester": "u2"}))
    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "B"


def test_no_signature_still_investigates_slow(monkeypatch):
    # run_all 全是伪签名(空 list)→ 无快通道、无 entry → 仍走慢通道研判、只是不沉淀规则
    repo = InMemoryPatternRepository()
    llm = FakeLLMClient([_finalize("suspicious")])
    orch = _wire(repo, _skill(), llm)
    monkeypatch.setattr(signatures_mod, "run_all", lambda g, a, s=None: [])
    r = orch.investigate(_alert("a1"))
    assert r.path == "B" and r.verdict.verdict == "suspicious"
    assert repo.all() == []                            # 无签名 → 不沉淀
