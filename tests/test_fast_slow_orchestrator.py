"""顶层编排 FastSlowInvestigator —— 快通道命中免 LLM + 慢通道当场生成规则(换实例双跑,首刀验收的单元版)。

run-1(vagrant)无规则 → 慢通道(1 次 LLM)→ 生成 active 规则;
run-2(hacker2,同判别特征不同实例)→ 快通道命中同规则、★0 LLM、结论正确、处置换实例填对。
先证伪:机器账号跨域引荐的豁免规则也能快通道短路成 FP。
"""
from types import SimpleNamespace

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


def _skill(disc):
    return SimpleNamespace(name="kerberoast", technique_ids=["T1558.003"], is_generic=False,
                           methodology="m", recipe=lambda g, a, s=None: {"ev": "x"},
                           discriminate=lambda g, a, s=None: disc)


def _registry(skill):
    return SimpleNamespace(select=lambda a, layer=None: skill,
                           generic_for_layer=lambda l: None, specific=lambda: [skill])


def _finalize(verdict, target=None, rationale="r"):
    # target 参数保留兼容旧签名但已无效:finalize 只出 verdict,处置交 composer
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


def test_slow_first_then_fast_reuse_zero_llm():
    repo = InMemoryPatternRepository()
    skill = _skill({"layers": _SPRAY_LAYERS, "bindings": {"requester": "vagrant", "target_service": "sql_svc"}})
    llm = FakeLLMClient([_finalize("true_positive", rationale="RC4 扇出")])         # 研判 LLM,只给 run-1
    comp_llm = FakeLLMClient([_compose_disable("requester")])                        # composer LLM,只给 run-1
    orch = _wire(repo, skill, llm, composer_llm=comp_llm)

    r1 = orch.investigate(_alert("a1"))
    assert r1.path == "B" and r1.verdict.verdict == "true_positive"
    assert r1.dispositions[0].action == "disable_account" and r1.dispositions[0].target == "vagrant"
    assert len(repo.all()) == 1 and repo.all()[0].status == "active"
    assert repo.all()[0].plan[0].primitive == "disable_account"    # composer 计划固化进规则
    assert len(llm.calls) == 1 and len(comp_llm.calls) == 1

    # 换实例:同判别特征、requester 变
    skill.discriminate = lambda g, a, s=None: {"layers": _SPRAY_LAYERS, "bindings": {"requester": "hacker2", "target_service": "svc2"}}
    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "A"                                    # 快通道
    assert r2.verdict.verdict == "true_positive"
    assert r2.verdict.pattern == repo.all()[0].pattern_id    # 指向同一规则
    assert r2.dispositions[0].action == "disable_account" and r2.dispositions[0].target == "hacker2"
    assert len(llm.calls) == 1 and len(comp_llm.calls) == 1  # ★run-2 研判/组装都没叫 LLM


def test_no_dup_rule_on_repeat_same_features():
    repo = InMemoryPatternRepository()
    skill = _skill({"layers": _SPRAY_LAYERS, "bindings": {"requester": "vagrant", "target_service": "s"}})
    llm = FakeLLMClient([_finalize("true_positive")])
    comp_llm = FakeLLMClient([_compose_disable("requester")])
    orch = _wire(repo, skill, llm, composer_llm=comp_llm)
    orch.investigate(_alert("a1"))            # 慢通道生成
    orch.investigate(_alert("a2"))            # 快通道命中(不再 mint)
    assert len(repo.all()) == 1              # 去重成一条


def test_exculpatory_fp_short_circuits():
    repo = InMemoryPatternRepository()
    exc = [{"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}},
           {"layer": "incriminating", "features": {"req_is_machine": True, "same_domain": False, "enc": "RC4", "spn_fanout": ">=5"}}]
    skill = _skill({"layers": exc, "bindings": {"requester": "WINTERFELL$"}})
    llm = FakeLLMClient([_finalize("false_positive", rationale="机器账号跨域引荐票")])
    orch = _wire(repo, skill, llm)

    r1 = orch.investigate(_alert("a1"))
    assert r1.verdict.verdict == "false_positive"
    assert repo.all()[0].layer == "exculpatory" and repo.all()[0].status == "active"

    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "A" and r2.verdict.verdict == "false_positive"   # 豁免层快通道短路
    assert len(llm.calls) == 1


def test_slow_result_pattern_is_rule_sig_not_llm_freetext():
    # 慢通道 result.verdict.pattern 必须=生成规则的 sig_hash(收敛键),不是 LLM 自由文本 →
    # 铸规则的这条告警才和后续快通道复用者收敛到同一 Verdict 节点
    repo = InMemoryPatternRepository()
    skill = _skill({"layers": _SPRAY_LAYERS, "bindings": {"requester": "vagrant"}})
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c", "finalize_verdict", {
        "verdict": "true_positive", "confidence": 0.9, "rationale": "r", "pattern": "my_free_text"})])])
    comp_llm = FakeLLMClient([_compose_disable("requester")])
    orch = _wire(repo, skill, llm, composer_llm=comp_llm)
    r = orch.investigate(_alert("a1"))
    minted = repo.all()[0]
    assert r.verdict.pattern == minted.pattern_id      # = sig_hash
    assert r.verdict.pattern != "my_free_text"         # 不认 LLM 自由文本


def test_suspicious_mints_pending_not_active():
    repo = InMemoryPatternRepository()
    skill = _skill({"layers": _SPRAY_LAYERS, "bindings": {"requester": "u"}})
    llm = FakeLLMClient([_finalize("suspicious", rationale="证据不足")])
    orch = _wire(repo, skill, llm)
    orch.investigate(_alert("a1"))
    assert repo.all()[0].status == "pending"          # 可疑待采纳,不自动 active
    # 同形状再来一条:pending 不上快通道 → 仍走慢通道(需再喂一个 LLM 响应)
    llm._scripted.append(_finalize("suspicious"))
    r2 = orch.investigate(_alert("a2"))
    assert r2.path == "B"
