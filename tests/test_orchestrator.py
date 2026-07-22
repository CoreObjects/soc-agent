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


def _run(tmp_path, llm, graph, seed=None, **kw):
    """建 AgentInvestigator + 用(预选的)kerberoast skill 研判一条告警。"""
    _kerberoast_skill(tmp_path)
    reg = SkillRegistry(tmp_path)
    inv = AgentInvestigator(llm=llm, toolbox=default_toolbox(graph), schema="SCHEMA-XYZ",
                            registry=reg, agent_name="qwen32b-ft", **kw)
    return inv.investigate(_alert(), seed=seed or {}, skill=reg.by_name("kerberoast"))


def test_slow_path_runs_tools_then_finalizes(tmp_path):
    graph = FakeGraph(rows=[{"sam": "vagrant", "enc": "0x17"}])
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "MATCH (a:Alert) RETURN a"})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict", {
            "verdict": "true_positive", "confidence": 0.9, "rationale": "RC4 单用户扇出",
            "evidence_refs": ["e1"],
            "dispositions": [{"action": "disable_account", "target": "vagrant", "risk": "high"}]})]),
    ])
    r = _run(tmp_path, llm, graph, seed={"triggering_event": {"enc": "0x17"}})
    assert r.path == "B"
    assert r.verdict.verdict == "true_positive"
    assert r.verdict.agent == "qwen32b-ft"
    assert r.skill == "kerberoast"
    assert r.dispositions == []                          # ★研判只出 verdict;处置由独立 composer 环节组装
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
    r = _run(tmp_path, llm, graph)
    assert r.verdict.verdict == "benign"
    assert graph.queries                       # 被逼查了图(不再 0 取证下结论)


def test_stubborn_finalize_accepted_after_nudge_limit(tmp_path):
    fin = LLMResponse(tool_calls=[ToolCall("c", "finalize_verdict",
                      {"verdict": "benign", "confidence": 0.3, "rationale": "就不查"})])
    llm = FakeLLMClient([fin, fin, fin])       # 一直想直接 finalize
    r = _run(tmp_path, llm, FakeGraph())
    assert r.verdict.verdict == "benign"       # 打回 2 次后第 3 次接受,不无限循环


def test_nudges_then_finalizes_when_model_returns_bare_text(tmp_path):
    graph = FakeGraph(rows=[{"x": 1}])
    llm = FakeLLMClient([
        LLMResponse(content="我觉得像攻击"),            # 无工具调用 → 催
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict",
                    {"verdict": "true_positive", "confidence": 0.8, "rationale": "x"})]),
    ])
    r = _run(tmp_path, llm, graph)
    assert r.verdict.verdict == "true_positive"
    # 第二次 chat 的 messages 里应有催它取证/finalize 的提示
    assert any("finalize_verdict" in (m.get("content") or "") for m in llm.calls[1]["messages"])


def test_exhausts_to_suspicious_when_never_finalizes(tmp_path):
    llm = FakeLLMClient([LLMResponse(content="...")] * 5)
    r = _run(tmp_path, llm, FakeGraph(), max_iterations=3)
    assert r.verdict.verdict == "suspicious"
    assert r.verdict.missing_evidence                   # 说明未结论/证据不足


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
    skill = reg.by_name("kerberoast")
    assert skill.recipe is not None
    r = inv.investigate(_alert(), seed={}, skill=skill)
    assert r.verdict.verdict == "false_positive"
    assert r.skill == "kerberoast"
    assert any(t.get("tool") == "recipe_step" for t in r.trace)       # recipe 步进了 trace
    assert "跨域信任" in llm.calls[0]["messages"][1]["content"]         # 证据喂进了 user 消息
    assert llm.calls[0]["tools"][0]["function"]["name"] == "finalize_verdict"   # 只给 finalize
    assert llm.calls[0]["tool_choice"] == "required"                  # 逼它直接定性


def test_recipe_investigator_recalls_similar_cases_as_intel(tmp_path):
    # 图里有同技术历史判例 → 作情报召回,喂进 LLM(user 消息)+ 记 trace(recall_similar)
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    graph = FakeGraph(rows=[{"verdict": "false_positive", "n": 42, "examples": ["跨域 RC4 正常"]}])
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
          {"verdict": "false_positive", "confidence": 0.8, "rationale": "历史同类多为 FP"})])])
    inv = RecipeInvestigator(llm=llm, graph=graph, schema="S", registry=reg, agent_name="q")
    r = inv.investigate(_alert(), seed={}, skill=reg.by_name("kerberoast"))
    assert any(t.get("tool") == "recall_similar" for t in r.trace)        # 情报召回记入 trace
    assert "历史相似判例" in llm.calls[0]["messages"][1]["content"]         # 情报喂进 user 消息


def test_recipe_investigator_no_recall_when_no_history(tmp_path):
    # 图里无历史判例(空)→ 不加情报、不记 recall_similar,只有 recipe_step
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
          {"verdict": "benign", "confidence": 0.5, "rationale": "无历史"})])])
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="S", registry=reg, agent_name="q")
    r = inv.investigate(_alert(), seed={}, skill=reg.by_name("kerberoast"))
    assert not any(t.get("tool") == "recall_similar" for t in r.trace)


def test_recipe_investigator_fallback_when_llm_gives_no_finalize(tmp_path):
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(content="我随便说说")])            # 没调 finalize
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="S", registry=reg, agent_name="q")
    r = inv.investigate(_alert(), seed={}, skill=reg.by_name("kerberoast"))
    assert r.verdict.verdict == "suspicious"


def test_skill_router_picks_skill_by_description(tmp_path):
    # LLM 按 description 选 skill(Agent Skills 的 Discovery→Activation)
    _kerberoast_skill(tmp_path)
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "select_skill", {"name": "kerberoast"})])])
    from soc_agent.orchestrator import SkillRouter
    picked = SkillRouter(llm=llm, registry=reg).route(_alert())
    assert picked is not None and picked.name == "kerberoast"
    # 候选目录(name+description)喂进了提示,且只给了 select_skill 工具 + required
    assert "kerberoast" in llm.calls[0]["messages"][0]["content"]
    assert llm.calls[0]["tools"][0]["function"]["name"] == "select_skill"
    assert llm.calls[0]["tool_choice"] == "required"


def test_skill_router_feeds_raw_alert_to_llm(tmp_path):
    # ★路由据原始告警内容选 skill:原始告警必须喂进路由提示(没有它选不对 skill)
    _kerberoast_skill(tmp_path)
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "select_skill", {"name": "kerberoast"})])])
    from soc_agent.orchestrator import SkillRouter
    alert = Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                             "rule_description": "Kerberoasting", "raw": '{"RAWMARKER_ROUTE": "orig alert"}'})
    SkillRouter(llm=llm, registry=reg).route(alert)
    assert "RAWMARKER_ROUTE" in llm.calls[0]["messages"][1]["content"]   # 原始告警喂进路由 user 提示


def test_agent_investigator_user_prompt_includes_raw(tmp_path):
    # ★auto 研判也要拿到整段原始告警(大模型整段读)
    graph = FakeGraph(rows=[{"x": 1}])
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c1", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c2", "finalize_verdict",
                    {"verdict": "benign", "confidence": 0.5, "rationale": "x"})]),
    ])
    _kerberoast_skill(tmp_path)
    reg = SkillRegistry(tmp_path)
    inv = AgentInvestigator(llm=llm, toolbox=default_toolbox(graph), schema="S", registry=reg, agent_name="q")
    alert = Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"], "raw": '{"RAWMARKER_AGENT": 1}'})
    inv.investigate(alert, seed={}, skill=reg.by_name("kerberoast"))
    assert "RAWMARKER_AGENT" in llm.calls[0]["messages"][1]["content"]   # user 提示含原始告警


def test_recipe_investigator_includes_raw_alert(tmp_path):
    # ★recipe 研判也要拿到整段原始告警
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
          {"verdict": "benign", "confidence": 0.5, "rationale": "x"})])])
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="S", registry=reg, agent_name="q")
    alert = Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"], "raw": '{"RAWMARKER_RECIPE": 2}'})
    inv.investigate(alert, seed={}, skill=reg.by_name("kerberoast"))
    assert "RAWMARKER_RECIPE" in llm.calls[0]["messages"][1]["content"]  # user 证据含原始告警


def test_investigators_tolerate_missing_raw(tmp_path):
    # 旧告警未回填 raw(None)→ 三处都不崩,优雅退回
    _kerberoast_skill_with_recipe(tmp_path, {"x": 1})
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
          {"verdict": "benign", "confidence": 0.5, "rationale": "x"})])])
    inv = RecipeInvestigator(llm=llm, graph=FakeGraph(), schema="S", registry=reg, agent_name="q")
    alert = Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"]})   # 无 raw
    r = inv.investigate(alert, seed={}, skill=reg.by_name("kerberoast"))
    assert r.verdict.verdict == "benign"


def test_skill_router_none_falls_back_to_generic_layer(tmp_path):
    _kerberoast_skill(tmp_path)                                       # identity 具体 skill
    # 一个 identity 层通用兜底
    g = tmp_path / "_generic" / "identity"
    g.mkdir(parents=True, exist_ok=True)
    (g / "SKILL.md").write_text("---\nname: generic_identity\nlayer: identity\ntechnique_ids: []\n---\n通用身份\n",
                                encoding="utf-8")
    reg = SkillRegistry(tmp_path)
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("c1", "select_skill", {"name": "none"})])])
    from soc_agent.orchestrator import SkillRouter
    picked = SkillRouter(llm=llm, registry=reg).route(_alert())      # T1558.003 → identity 层
    assert picked is not None and picked.name == "generic_identity"


def test_suspicious_lean_normalized_in_build_result():
    from soc_agent.orchestrator import build_result
    # suspicious 缺 lean → 归一 unknown(不留"纯黑洞")
    r = build_result(_alert(), "adcs", {"verdict": "suspicious", "confidence": 0.5, "rationale": "x"}, "q", trace=[])
    assert r.verdict.lean == "unknown"
    # suspicious 带合法 lean → 保留
    r2 = build_result(_alert(), "adcs",
                      {"verdict": "suspicious", "lean": "malicious", "confidence": 0.5, "rationale": "x"}, "q", trace=[])
    assert r2.verdict.lean == "malicious"
    # 非 suspicious → 清掉 lean(TP/FP 不带倾向)
    r3 = build_result(_alert(), "kerberoast",
                      {"verdict": "true_positive", "lean": "malicious", "confidence": 0.9, "rationale": "x"}, "q", trace=[])
    assert r3.verdict.lean is None


def test_invalid_verdict_from_llm_normalized_to_suspicious(tmp_path):
    llm = FakeLLMClient([
        LLMResponse(tool_calls=[ToolCall("c0", "run_cypher", {"query": "MATCH (n) RETURN n"})]),
        LLMResponse(tool_calls=[ToolCall("c1", "finalize_verdict",
                    {"verdict": "PWNED", "confidence": 1.0, "rationale": "x"})]),
    ])
    r = _run(tmp_path, llm, FakeGraph())
    assert r.verdict.verdict == "suspicious"            # 非法 verdict 归一,不崩
