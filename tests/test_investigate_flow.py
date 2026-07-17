"""流水线整合:取证 → 经验短路(AUTO_TP/AUTO_FP)/ FALLTHROUGH→LLM→组处置→回流沉淀。"""
from soc_agent.cli import Pipeline, run_pipeline
from soc_agent.composer.plan import PrimitiveStepTemplate
from soc_agent.experience.consult import consult
from soc_agent.experience.fingerprint import build_fingerprint
from soc_agent.experience.store import Experience, ExperienceCache, InMemoryExperienceStore
from soc_agent.experience.cases import InMemoryCaseStore
from soc_agent.experience.distill import DISTILL
from soc_agent.forensics import Finding, Forensics
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import InvestigationResult, Verdict
from soc_agent.response import default_interface

_FINDINGS = [Finding("kerberoast.rc4_requested", {"enc_type": "0x17"}),
             Finding("kerberoast.spn_fanout", {"distinct_targets": 12, "bucket": "high"})]
_BINDINGS = {"attacker_account": "hacker2", "attacker_account_domain": "NORTH"}


def _forensics():
    return Forensics(findings=list(_FINDINGS), bindings=dict(_BINDINGS), context={"x": 1})


class _Skill:
    name = "kerberoast"
    methodology = "m"
    path = None

    def __init__(self):
        self.recipe = lambda g, a, s: _forensics()


class _Graph:
    def __init__(self, node):
        self.node = node
        self.written = []

    def get_alert(self, uid):
        return self.node

    def seed(self, alert):
        return {}

    def write_result(self, uid, result):
        self.written.append((uid, result))

    def close(self):
        pass


class _Router:
    def __init__(self, skill):
        self.skill = skill

    def route(self, alert, seed=None):
        return self.skill


class _Inv:
    """假研判器:回放脚本结论,并把 forensics 的 findings/bindings 带进 result(仿真 recipe inv)。"""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def investigate(self, alert, seed=None, skill=None, forensics=None, match_report=None):
        self.calls.append({"forensics": forensics, "match_report": match_report})
        self.result.findings = list(forensics.findings) if forensics else []
        self.result.bindings = dict(forensics.bindings) if forensics else {}
        return self.result


class _Composer:
    def __init__(self, templates):
        self.templates = templates

    def compose(self, result, disc, skill, seed=None):
        return list(self.templates)


def _pipeline(exp_store, inv_result=None, templates=None, llm=None):
    skill = _Skill()
    inv = _Inv(inv_result) if inv_result is not None else _Inv(None)
    return Pipeline(
        graph=_Graph({"alert_uid": "a1", "technique_ids": ["T1558.003"]}),
        router=_Router(skill), agent_inv=inv, recipe_inv=inv,
        composer=_Composer(templates or []), llm=llm or FakeLLMClient([]),
        policy={"protected_hosts": [], "protected_accounts": []}, iface=default_interface(),
        exp_store=exp_store, case_store=InMemoryCaseStore(), agent_name="q"), inv


def _threat_exp(playbook=None):
    return Experience(skill="kerberoast", kind="threat", verdict="true_positive",
                      fingerprint=build_fingerprint(_FINDINGS, _BINDINGS),
                      rule={"and": [{"exists": "kerberoast.rc4_requested"},
                                    {"exists": "kerberoast.spn_fanout"}]},
                      playbook=playbook or [])


def test_auto_tp_reuses_experience_without_llm():
    store = ExperienceCache(InMemoryExperienceStore())
    exp = _threat_exp(playbook=[PrimitiveStepTemplate(
        order=1, primitive="disable_account",
        params={"sam": {"source": "entity_role", "role": "attacker_account"}}, risk="high").to_dict()])
    store.add(exp)
    pl, inv = _pipeline(store)
    result, report, picked = run_pipeline(pl, "a1")
    assert report.decision == "AUTO_TP" and result.path == "A"
    assert result.verdict.verdict == "true_positive"
    assert inv.calls == []                                       # ★没走 LLM 研判
    assert store.get(exp.exp_id).hit_count == 1                  # 命中计数 +1
    assert pl.graph.written and pl.graph.written[0][1] is result  # 台账照写


def test_auto_fp_suppresses_without_llm():
    store = ExperienceCache(InMemoryExperienceStore())
    store.add(Experience(skill="kerberoast", kind="benign_fp", verdict="false_positive",
                         fingerprint=build_fingerprint(_FINDINGS, _BINDINGS)))
    pl, inv = _pipeline(store)
    result, report, picked = run_pipeline(pl, "a1")
    assert report.decision == "AUTO_FP" and result.path == "A"
    assert result.verdict.verdict == "false_positive" and result.dispositions == []
    assert inv.calls == []


def test_fallthrough_llm_tp_composes_and_sediments():
    store = ExperienceCache(InMemoryExperienceStore())       # 空 → FALLTHROUGH
    tp = InvestigationResult(alert_uid="a1", path="B", skill="kerberoast",
                             verdict=Verdict("true_positive", confidence=0.9, rationale="RC4 扇出", agent="q"))
    templates = [PrimitiveStepTemplate(order=1, primitive="disable_account",
                 params={"sam": {"source": "entity_role", "role": "attacker_account"}}, risk="high")]
    # pl.llm 仅被 sediment(distill)调用:回一个威胁经验蒸馏
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("1", DISTILL, {
        "decisive_finding_ids": ["kerberoast.rc4_requested", "kerberoast.spn_fanout"],
        "rule": {"and": [{"exists": "kerberoast.rc4_requested"},
                         {"exists": "kerberoast.spn_fanout"}]}})])])
    pl, inv = _pipeline(store, inv_result=tp, templates=templates, llm=llm)
    result, report, picked = run_pipeline(pl, "a1")
    assert report.decision == "FALLTHROUGH"
    assert len(inv.calls) == 1                                    # ★走了 LLM 研判
    assert inv.calls[0]["forensics"] is not None                 # 取证结果传入(不重跑)
    assert inv.calls[0]["match_report"] is report                # 命中报告作已知信息喂进
    assert result.playbook and result.dispositions               # ★组了处置剧本
    # ★回流:蒸馏→考试→入库,新威胁经验带上处置剧本
    active = store.active_for_skill("kerberoast")
    assert len(active) == 1 and active[0].kind == "threat"
    assert active[0].playbook == result.playbook
    assert pl.case_store.by_skill("kerberoast")                  # 案例快照进语料


def test_fallthrough_llm_fp_sediments_benign_no_compose():
    store = ExperienceCache(InMemoryExperienceStore())
    fp = InvestigationResult(alert_uid="a1", path="B", skill="kerberoast",
                             verdict=Verdict("false_positive", confidence=0.9,
                                             rationale="跨域机器账号引荐票", agent="q"))
    llm = FakeLLMClient([LLMResponse(tool_calls=[ToolCall("1", DISTILL, {
        "decisive_finding_ids": ["kerberoast.spn_fanout"]})])])
    pl, inv = _pipeline(store, inv_result=fp, templates=[PrimitiveStepTemplate(order=1, primitive="disable_account")],
                        llm=llm)
    result, report, picked = run_pipeline(pl, "a1")
    assert report.decision == "FALLTHROUGH" and result.verdict.verdict == "false_positive"
    assert result.dispositions == [] and result.playbook == []   # FP 不组处置
    active = store.active_for_skill("kerberoast")
    assert len(active) == 1 and active[0].kind == "benign_fp" and active[0].rule is None
