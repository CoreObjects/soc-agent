"""生死线考试:新经验入库前 —— 原案例必点火 + 历史反类案例回归不误点火;回流 sediment 只入过关经验。"""
from soc_agent.experience.cases import Case, InMemoryCaseStore
from soc_agent.experience.distill import DISTILL
from soc_agent.experience.exam import exam, sediment
from soc_agent.experience.fingerprint import build_fingerprint
from soc_agent.experience.store import Experience, InMemoryExperienceStore
from soc_agent.forensics import Finding
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import InvestigationResult, Verdict


def _threat(fids, rule):
    return Experience(skill="k", kind="threat", verdict="true_positive",
                      fingerprint=build_fingerprint([Finding(f) for f in fids], {}), rule=rule)


class _Skill:
    name = "k"
    methodology = "m"


# ---- exam ----
def test_exam_passes_when_origin_fires_and_no_adversary_mishit():
    exp = _threat(["k.rc4", "k.hv"], {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]})
    cases = [Case("k", "fp1", "false_positive", [Finding("k.machine")])]     # 良性,无 rc4/hv → 不误点火
    passed, rep = exam(exp, [Finding("k.rc4"), Finding("k.hv")], cases)
    assert passed is True and rep["reason"] == "passed"


def test_exam_fails_origin_miss():
    exp = _threat(["k.rc4", "k.hv"], {"exists": "k.zzz"})                    # 规则要不存在的 finding
    passed, rep = exam(exp, [Finding("k.rc4"), Finding("k.hv")], [])
    assert passed is False and rep["reason"] == "origin_miss"


def test_exam_fails_regression_mishit_on_fp_case():
    exp = _threat(["k.rc4"], {"exists": "k.rc4"})                            # 过宽:有 rc4 就判威胁
    cases = [Case("k", "fp1", "false_positive", [Finding("k.rc4")])]         # 历史误报里也有 rc4
    passed, rep = exam(exp, [Finding("k.rc4")], cases)
    assert passed is False and rep["reason"] == "regression_mishit" and "fp1" in rep["mishit_cases"]


# ---- sediment 回流 ----
def _result(uid, verdict, findings):
    return InvestigationResult(alert_uid=uid, path="B", skill="k",
                               verdict=Verdict(verdict, confidence=0.9, rationale="r", agent="q"),
                               findings=findings, bindings={})


def _llm(args):
    return FakeLLMClient([LLMResponse(tool_calls=[ToolCall("1", DISTILL, args)])])


def test_sediment_stores_when_exam_passes():
    result = _result("a1", "true_positive", [Finding("k.rc4"), Finding("k.hv")])
    llm = _llm({"decisive_finding_ids": ["k.rc4", "k.hv"], "rule": {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]}})
    exp_store, case_store = InMemoryExperienceStore(), InMemoryCaseStore()
    case_store.add(Case("k", "fp1", "false_positive", [Finding("k.machine")]))
    exp, rep = sediment(llm, _Skill(), result, exp_store, case_store, agent_name="q")
    assert exp is not None and rep["reason"] == "passed"
    assert len(exp_store.active_for_skill("k")) == 1 and exp.origin_case_id == "a1"


def test_sediment_rejects_when_regression_fails():
    result = _result("a2", "true_positive", [Finding("k.rc4")])
    llm = _llm({"decisive_finding_ids": ["k.rc4"], "rule": {"exists": "k.rc4"}})     # 过宽
    exp_store, case_store = InMemoryExperienceStore(), InMemoryCaseStore()
    case_store.add(Case("k", "fp1", "false_positive", [Finding("k.rc4")]))           # 历史误报含 rc4
    exp, rep = sediment(llm, _Skill(), result, exp_store, case_store)
    assert exp is None and rep["reason"] == "regression_mishit" and exp_store.all() == []


def test_sediment_converges_when_prior_active_experience_covers():
    # 收敛守卫:已有 active 同类经验能在这些 findings 上点火 → 不重复入库(替代删掉的 pattern_id 去重)。
    # (正常流水线里 FALLTHROUGH 本就没经验点火;这条守卫防批量重派生/竞态下的重复插入。)
    result = _result("a9", "true_positive", [Finding("k.rc4"), Finding("k.hv")])
    llm = _llm({"decisive_finding_ids": ["k.rc4", "k.hv"], "rule": {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]}})
    exp_store, case_store = InMemoryExperienceStore(), InMemoryCaseStore()
    prior = _threat(["k.rc4", "k.hv"], {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]})
    exp_store.add(prior)
    exp, rep = sediment(llm, _Skill(), result, exp_store, case_store)
    assert exp is None and rep["reason"] == "converged" and rep["covered_by"] == prior.exp_id
    assert len(exp_store.active_for_skill("k")) == 1              # 没新增
    assert exp_store.get(prior.exp_id).hit_count == 1            # 复用记一次命中


def test_sediment_no_converge_across_kind():
    # 不同 kind 不算覆盖(威胁经验点火 ≠ 误报可复用)→ 照常入库
    result = _result("a10", "false_positive", [Finding("k.rc4"), Finding("k.hv")])
    llm = _llm({"decisive_finding_ids": ["k.rc4", "k.hv"]})
    exp_store, case_store = InMemoryExperienceStore(), InMemoryCaseStore()
    exp_store.add(_threat(["k.rc4", "k.hv"], {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]}))  # 威胁 prior
    exp, rep = sediment(llm, _Skill(), result, exp_store, case_store)
    assert exp is not None and exp.kind == "benign_fp"           # 误报照常沉淀,不被威胁 prior 收敛


def test_sediment_skips_suspicious():
    result = _result("a3", "suspicious", [Finding("k.rc4")])
    result.verdict.lean = "unknown"
    exp, rep = sediment(_llm({"decisive_finding_ids": ["k.rc4"]}), _Skill(), result,
                        InMemoryExperienceStore(), InMemoryCaseStore())
    assert exp is None and rep["reason"] == "not_distilled"
