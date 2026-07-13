"""慢通道自主研判循环(AgentInvestigator)。

用 FakeLLMClient 脚本化 + FakeGraph,完整验证 tool-calling 循环:
系统提示含 schema+skill方法论 → LLM 反复 run_cypher 取证 → finalize_verdict 出结论 →
InvestigationResult(path=B,处置默认 proposed)。含证据不足/非法 verdict/未结论兜底。
"""
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import Alert
from soc_agent.orchestrator import AgentInvestigator, RecipeInvestigator
from soc_agent.skills_runtime import SkillRegistry
from soc_agent.tools import default_toolbox


class FakeGraph:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []
        self.queries = []

    def run_cypher(self, q, **params):
        self.queries.append(q)
        return self.rows


def _kerberoast_skill(base):
    d = base / "identity" / "kerberoast"
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        "---\nname: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]\n"
        "description: Kerberoasting 研判\n---\n方法论:先证伪(跨域RC4/扫描器)→看SPN扇出→看落地。\n",
        encoding="utf-8")


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100002"})


def _inv(tmp_path, llm, graph, **kw):
    _kerberoast_skill(tmp_path)
    return AgentInvestigator(llm=llm, toolbox=default_toolbox(graph), schema="SCHEMA-XYZ",
                             registry=SkillRegistry(tmp_path), agent_name="qwen32b-ft", **kw)


def test_slow_path_runs_tools_then_finalizes(tmp_path):
    graph = FakeGraph(rows=[{"sam": "vagrant", "enc": "0x17"}])
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "MATCH (a:Alert) RETURN a"})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict", {
            "verdict": "true_positive", "confidence": 0.9, "rationale": "RC4 单用户扇出",
            "evidence_refs": ["e1"],
            "dispositions": [{"action": "disable_account", "target": "vagrant", "risk": "high"}]})]),
    ])
    r = _inv(tmp_path, llm, graph).investigate(_alert(), seed={"triggering_event": {"enc": "0x17"}})
    assert r.path == "B"
    assert r.verdict.verdict == "true_positive"
    assert r.verdict.agent == "qwen32b-ft"
    assert r.skill == "kerberoast"
    assert r.dispositions[0].action == "disable_account"
    assert r.dispositions[0].status == "proposed"       # 默认仅建议
    assert graph.queries                                # run_cypher 真被调过
    sys_msg = llm.calls[0]["messages"][0]
    assert sys_msg["role"] == "system"
    assert "SCHEMA-XYZ" in sys_msg["content"]           # schema 注入了
    assert "先证伪" in sys_msg["content"]                # skill 方法论注入了


def test_immediate_finalize_nudged_then_investigates(tmp_path):
    # 0 取证就想 finalize → 骨架保底打回,逼它先查图,再 finalize
    graph = FakeGraph(rows=[{"x": 1}])
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
                    {"verdict": "benign", "confidence": 0.4, "rationale": "seed 够了"})]),   # 被打回
        LLMResponse(tool_calls=[ToolCall("c2", "run_cypher", {"query": "MATCH (a:Alert) RETURN a"})]),
        LLMResponse(tool_calls=[ToolCall("c3", "finalize_verdict",
                    {"verdict": "benign", "confidence": 0.4, "rationale": "查完确认良性"})]),
    ])
    r = _inv(tmp_path, llm, graph).investigate(_alert(), seed={})
    assert r.verdict.verdict == "benign"
    assert graph.queries                       # 被逼查了图(不再 0 取证下结论)


def test_stubborn_finalize_accepted_after_nudge_limit(tmp_path):
    fin = LLMResponse(tool_calls=[ToolCall("c", "finalize_verdict",
                      {"verdict": "benign", "confidence": 0.3, "rationale": "就不查"})])
    llm = FakeLLMClient([fin, fin, fin])       # 一直想直接 finalize
    r = _inv(tmp_path, llm, FakeGraph()).investigate(_alert(), seed={})
    assert r.verdict.verdict == "benign"       # 打回 2 次后第 3 次接受,不无限循环


def test_nudges_then_finalizes_when_model_returns_bare_text(tmp_path):
    graph = FakeGraph(rows=[{"x": 1}])
    llm = FakeLLMClient([
        LLMResponse(content="我觉得像攻击"),            # 无工具调用 → 催
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict",
                    {"verdict": "true_positive", "confidence": 0.8, "rationale": "x"})]),
    ])
    r = _inv(tmp_path, llm, graph).investigate(_alert(), seed={})
    assert r.verdict.verdict == "true_positive"
    # 第二次 chat 的 messages 里应有催它取证/finalize 的提示
    assert any("finalize_verdict" in (m.get("content") or "") for m in llm.calls[1]["messages"])


def test_exhausts_to_suspicious_when_never_finalizes(tmp_path):
    llm = FakeLLMClient([LLMResponse(content="...")] * 5)
    r = _inv(tmp_path, llm, FakeGraph(), max_iterations=3).investigate(_alert(), seed={})
    assert r.verdict.verdict == "suspicious"
    assert r.verdict.missing_evidence                   # 说明未结论/证据不足


def test_freeform_disposition_action_normalized_to_escalate(tmp_path):
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c0", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict", {
            "verdict": "suspicious", "confidence": 0.5, "rationale": "x",
            "dispositions": [{"action": "推动淘汰RC4等弱加密", "target": "NORTH", "risk": "high"}]})]),
    ])
    r = _inv(tmp_path, llm, FakeGraph()).investigate(_alert(), seed={})
    assert r.dispositions[0].action == "escalate"      # 词表外的自由发挥 → 归一为升级人工


def _kerberoast_skill_with_recipe(base, recipe_ret):
    d = base / "identity" / "kerberoast"
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        "---\nname: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]\n---\n方法论:跨域信任→FP。\n",
        encoding="utf-8")
    (d / "recipe.py").write_text(
        "def collect(graph, alert, seed=None):\n    return " + repr(recipe_ret) + "\n", encoding="utf-8")


def test_recipe_investigator_runs_recipe_then_llm_only_judges(tmp_path):
    _kerberoast_skill_with_recipe(tmp_path, {"跨域信任": {"trusts": ["sevenkingdoms.local"]}})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
          {"verdict": "false_positive", "confidence": 0.9, "rationale": "跨域信任正常 RC4"})])])
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="SCHEMA", registry=reg, agent_name="qwen32b-ft")
    a = _alert()
    assert inv.has_recipe(a) is True
    r = inv.investigate(a, seed={})
    assert r.verdict.verdict == "false_positive"
    assert r.skill == "kerberoast"
    assert any(t.get("tool") == "recipe_step" for t in r.trace)       # recipe 步进了 trace
    assert "跨域信任" in llm.calls[0]["messages"][1]["content"]         # 证据喂进了 user 消息
    assert llm.calls[0]["tools"][0]["function"]["name"] == "finalize_verdict"   # 只给 finalize
    assert llm.calls[0]["tool_choice"] == "required"                  # 逼它直接定性


def test_recipe_investigator_fallback_when_llm_gives_no_finalize(tmp_path):
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(content="我随便说说")])            # 没调 finalize
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="S", registry=reg, agent_name="q")
    assert inv.investigate(_alert(), seed={}).verdict.verdict == "suspicious"


def test_recipe_investigator_has_recipe_false_without_recipe(tmp_path):
    _kerberoast_skill(tmp_path)                                       # 只有 SKILL.md,无 recipe.py
    inv = RecipeInvestigator(llm=FakeLLMClient([]), graph=FakeGraph(),
                             schema="S", registry=SkillRegistry(tmp_path))
    assert inv.has_recipe(_alert()) is False


def test_invalid_verdict_from_llm_normalized_to_suspicious(tmp_path):
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c0", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
                    {"verdict": "PWNED", "confidence": 1.0, "rationale": "x"})]),
    ])
    r = _inv(tmp_path, llm, FakeGraph()).investigate(_alert(), seed={})
    assert r.verdict.verdict == "suspicious"            # 非法 verdict 归一,不崩
