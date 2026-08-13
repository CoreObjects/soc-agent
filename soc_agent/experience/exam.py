"""生死线考试 + 回流沉淀。

考试(入库前必过):① 回放原案例必点火(指纹/规则确实复现本次定性)② 历史反类案例回归不得误点火
(威胁经验别命中历史 FP/benign;误报指纹别命中历史 TP)。过关才 active,否则拒绝并记因。
用与快通道一致的 experience_fires 判据 —— 考试标准 = 线上标准。

回流 sediment:完整研判后 蒸馏 → 考试 → 过关入库。让快通道越用越宽。
"""
from .distill import distill
from .matching import experience_fires

__all__ = ["exam", "sediment"]


def exam(exp, origin_findings, cases):
    """(passed, report)。cases = 同 skill 历史案例快照(list[Case])。"""
    if not experience_fires(exp, origin_findings)[0]:
        return False, {"reason": "origin_miss",
                       "detail": "新经验在原案例上不点火(指纹/规则没复现本次定性)"}
    if exp.kind == "threat":
        adversary = [c for c in cases if c.verdict in ("false_positive", "benign")]
    else:                                                        # benign_fp
        adversary = [c for c in cases if c.verdict == "true_positive"]
    mishits = [c.alert_uid for c in adversary if experience_fires(exp, c.findings)[0]]
    if mishits:
        return False, {"reason": "regression_mishit", "mishit_cases": mishits, "checked": len(adversary)}
    return True, {"reason": "passed", "checked_adversary": len(adversary)}


def sediment(llm, skill, result, exp_store, case_store, agent_name=None, coverage_sig=""):
    """完整研判后回流:蒸馏 → 考试(对已存案例)→ 过关入库 active。返回 (exp or None, report)。

    调用前应已 snapshot_case(本案例进语料);exam 用 result.findings 直接回放 origin,反类只查异类案例。
    """
    exp = distill(llm, skill, result.findings, result.bindings, result.verdict,
                  agent_name=agent_name, origin_case_id=result.alert_uid,
                  coverage_sig=coverage_sig)      # ★记下学它时的覆盖度条件(WP9,只记录不召回)
    if exp is None:
        return None, {"reason": "not_distilled"}
    # 收敛守卫(替代删掉的 pattern_id 去重):已有 active 同类经验能覆盖本案(在这些 findings 上点火)→
    # 不重复入库,只记它一次命中。正常流水线 FALLTHROUGH 本就没经验点火(否则会 AUTO 短路);
    # 这条防批量重派生(path-G 重放已研判告警)/竞态下把同一模式反复插成新行 → 库膨胀。
    for prior in (exp_store.active_for_skill(exp.skill) if exp_store is not None else []):
        if prior.kind == exp.kind and experience_fires(prior, result.findings)[0]:
            exp_store.bump_hit(prior.exp_id)
            return None, {"reason": "converged", "covered_by": prior.exp_id}
    if exp.kind == "threat":                                        # 处置那一半:Composer 产出的剧本模板
        exp.playbook = list(getattr(result, "playbook", None) or [])
    cases = case_store.by_skill(exp.skill) if case_store is not None else []
    passed, report = exam(exp, result.findings, cases)
    if not passed:
        return None, report
    exp_store.add(exp)
    return exp, report
