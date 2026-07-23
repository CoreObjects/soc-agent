"""浅层 payload 签名库:从 payload 蒸出的规则 + 确定性匹配(B 类"越用越省")。

match_spec(存 openGauss experience.rule 列,kind="payload"):
  {"conditions": [{"path","op","value"}...], "verdict": "false_positive|true_positive"}
所有 condition AND 命中才算命中。path 走 alert.raw(json.loads 后点路径),外加顶层归一字段
(rule_description/source/rule_id/severity/technique_ids)也可作根键。

★可移植红线(见 [[soc-signature-portability-redline]]):规则是 qwen 学进 openGauss、不硬编码进代码;
键在源特定 raw 路径(v1 取舍,换源重学)——本体键的可移植版等 OCSF 归一另立项。
★安全:进程/文件用 basename_eq(末段相等),别用裸 endswith(否则 wazuh-agent.exe 会误命中 evil-wazuh-agent.exe)。
"""
import json
import re
from dataclasses import dataclass
from typing import Optional

from ..experience.store import Experience

__all__ = ["payload_match", "match_ctx", "OPS", "PayloadCase", "sig_consult",
           "distill_signature", "sig_sediment", "SIGNATURE_DISTILL_PROMPT",
           "payload_case_of", "InMemoryPayloadCaseStore"]

OPS = ("eq", "in", "basename_eq", "contains", "gt", "gte", "lt", "lte")
_NUM_OPS = {"gt", "gte", "lt", "lte"}


def match_ctx(alert) -> dict:
    """alert.raw(json)展开 + 顶层归一字段并进根,供 path 提取。raw 坏/空 → 只剩顶层字段。"""
    try:
        obj = json.loads(alert.raw) if getattr(alert, "raw", None) else {}
    except (ValueError, TypeError):
        obj = {}
    ctx = dict(obj) if isinstance(obj, dict) else {}
    ctx["rule_description"] = getattr(alert, "rule_description", None)
    ctx["source"] = getattr(alert, "source", None)
    ctx["rule_id"] = getattr(alert, "rule_id", None)
    ctx["severity"] = getattr(alert, "severity", None)
    ctx["technique_ids"] = getattr(alert, "technique_ids", None)
    return ctx


def _walk(ctx, path):
    cur = ctx
    for key in str(path).split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def _basename(s):
    return re.split(r"[\\/]", str(s))[-1]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _cond_ok(cond, ctx) -> bool:
    op, path, val = cond.get("op"), cond.get("path"), cond.get("value")
    actual = _walk(ctx, path)
    if actual is None:
        return False
    if op == "eq":
        return str(actual).casefold() == str(val).casefold()
    if op == "in":
        vals = val if isinstance(val, (list, tuple)) else [val]
        return any(str(actual).casefold() == str(v).casefold() for v in vals)
    if op == "basename_eq":
        return _basename(actual).casefold() == str(val).casefold()
    if op == "contains":
        return str(val).casefold() in str(actual).casefold()
    if op in _NUM_OPS:
        a, v = _num(actual), _num(val)
        if a is None or v is None:
            return False
        return {"gt": a > v, "gte": a >= v, "lt": a < v, "lte": a <= v}[op]
    return False                       # 未知算子 → fail-closed(坏规则不误命中)


def payload_match(spec, alert) -> bool:
    """match_spec 是否命中该 alert 的 payload。空 conditions / 坏规则 / 坏 raw → False(安全)。"""
    conds = (spec or {}).get("conditions") or []
    if not conds:
        return False
    ctx = match_ctx(alert)
    return all(_cond_ok(c, ctx) for c in conds)


def sig_consult(exp_store, alert):
    """签名库匹配:返回命中的 payload Experience(含 verdict 可复用),无则 None。★零 LLM。"""
    if exp_store is None:
        return None
    skill = (getattr(alert, "source", None) or "shallow")
    for e in exp_store.active_for_skill(skill):
        if getattr(e, "kind", None) == "payload" and payload_match(e.rule, alert):
            return e
    return None


# ============ 从 payload 蒸馏签名规则 + 考试门(仿 experience.exam,但键在 payload)============
@dataclass
class PayloadCase:
    """浅层判例语料(供反例回归)。字段够 payload_match 直接 duck-type 匹配。"""
    alert_uid: str
    source: Optional[str] = None
    raw: Optional[str] = None
    verdict: Optional[str] = None
    rule_description: Optional[str] = None
    rule_id: Optional[str] = None
    severity: object = None
    technique_ids: Optional[list] = None


def payload_case_of(alert, verdict) -> PayloadCase:
    """从 alert + 浅层 verdict 造一条语料(payload_match 能直接匹配它)。"""
    return PayloadCase(alert_uid=alert.alert_uid, source=getattr(alert, "source", None),
                       raw=getattr(alert, "raw", None), verdict=verdict,
                       rule_description=getattr(alert, "rule_description", None),
                       rule_id=getattr(alert, "rule_id", None), severity=getattr(alert, "severity", None),
                       technique_ids=getattr(alert, "technique_ids", None))


class InMemoryPayloadCaseStore:
    """浅层判例语料库(内存版:selftest / 未配 openGauss 降级)。按 source 分区取反例。"""

    def __init__(self):
        self._cases = []

    def add(self, case) -> None:
        self._cases.append(case)

    def for_source(self, source):
        s = source or "shallow"
        return [c for c in self._cases if (getattr(c, "source", None) or "shallow") == s]

    def all(self):
        return list(self._cases)


SIGNATURE_DISTILL_PROMPT = (
    "你是 SOC 签名蒸馏器。给你一条**已判定**的告警(原文+元数据)、结论和依据。"
    "从告警**自身字段**提炼一条**可复用签名规则**:若干条件(path/op/value)全部满足时,"
    "同类告警可直接套用这个结论。\n"
    "★抓本质、别过拟合:**绝不**用具体 IP、账号名、主机名、时间戳、GUID、随机 hash 当 value;"
    "进程/文件路径用 op=basename_eq + 纯文件名(如 wazuh-agent.exe),不要完整路径;"
    "签名/事件码/枚举用 eq/in;明显特征子串用 contains;数值阈值用 gt/gte/lt/lte。\n"
    "path 是告警字段的点路径:raw 里的嵌套(如 data.win.eventdata.sourceImage)或顶层 "
    "rule_description/source/rule_id。只挑**真正驱动这次结论**的判别字段,别塞无关项。\n"
    "只调用 distill_signature 工具,不要多余解释。"
)

DISTILL_SIG = "distill_signature"

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_HEX16 = re.compile(r"^[0-9a-fA-F]{16,}$")


def _overfit(value) -> bool:
    """过拟合护栏:IP/GUID/时间戳/长 hash 当值 → 丢(换实例就废,别入规则)。"""
    if not isinstance(value, str):
        return False
    s = value.strip()
    return bool(_IPV4.match(s) or _GUID.match(s) or _TS.search(s) or _HEX16.match(s))


def _valid_cond(c) -> bool:
    return isinstance(c, dict) and c.get("path") and c.get("op") in OPS and ("value" in c)


def _distill_spec():
    return [{"type": "function", "function": {
        "name": DISTILL_SIG,
        "description": "从这条已判定的告警自身字段提炼一条可复用签名规则(若干 path/op/value 条件,全满足即复用本结论)。",
        "parameters": {"type": "object", "properties": {
            "conditions": {"type": "array", "items": {"type": "object", "properties": {
                "path": {"type": "string", "description": "告警字段点路径(raw 嵌套 或 顶层 rule_description/source)"},
                "op": {"type": "string", "enum": list(OPS)},
                "value": {"description": "比较值(进程/文件用 basename 文件名;别用具体 IP/账号/主机/时间戳)"},
            }, "required": ["path", "op", "value"]}},
            "note": {"type": "string", "description": "一句话本质"},
        }, "required": ["conditions"]}}}]


def _alert_view(alert) -> dict:
    return {"alert_uid": getattr(alert, "alert_uid", None),
            "rule_description": getattr(alert, "rule_description", None),
            "source": getattr(alert, "source", None), "sensor": getattr(alert, "sensor", None),
            "severity": getattr(alert, "severity", None),
            "technique_ids": getattr(alert, "technique_ids", None), "raw": getattr(alert, "raw", None)}


def distill_signature(llm, alert, verdict, rationale) -> Optional[dict]:
    """qwen 从 payload 蒸一条 match_spec(过拟合值过滤后);无有效条件 → None。"""
    user = json.dumps({"verdict": verdict, "rationale": rationale, "alert": _alert_view(alert)},
                      ensure_ascii=False, default=str)
    resp = llm.chat([{"role": "system", "content": SIGNATURE_DISTILL_PROMPT},
                     {"role": "user", "content": user}],
                    tools=_distill_spec(), tool_choice="required")
    args = None
    for tc in (getattr(resp, "tool_calls", None) or []):
        if getattr(tc, "name", None) == DISTILL_SIG:
            args = tc.arguments or {}
    if not args:
        return None
    conds = [c for c in (args.get("conditions") or []) if _valid_cond(c) and not _overfit(c.get("value"))]
    if not conds:
        return None
    return {"conditions": conds, "verdict": verdict, "note": args.get("note")}


def sig_sediment(llm, exp_store, opposite_cases, alert, result, agent_name=None):
    """浅层 terminal → 从 payload 蒸签名规则 → 考试(回放命中源 + 反例不误命中)→ 入库。
    返回 (Experience|None, report)。仿 experience.exam.sediment,但键在 payload。"""
    v = getattr(result, "verdict", None)
    if v is None or v.verdict not in ("true_positive", "false_positive"):
        return None, {"reason": "not_terminal_tp_fp"}
    skill = (getattr(alert, "source", None) or "shallow")
    for e in exp_store.active_for_skill(skill):                     # 收敛:同款已覆盖 → bump 不重插
        if getattr(e, "kind", None) == "payload" and e.verdict == v.verdict and payload_match(e.rule, alert):
            exp_store.bump_hit(e.exp_id)
            return None, {"reason": "converged", "exp_id": e.exp_id}
    spec = distill_signature(llm, alert, v.verdict, v.rationale)
    if not spec:
        return None, {"reason": "no_spec"}
    if not payload_match(spec, alert):                             # 考试①回放:必须命中源告警
        return None, {"reason": "origin_miss"}
    opp = "false_positive" if v.verdict == "true_positive" else "true_positive"
    mishits = [getattr(c, "alert_uid", None) for c in (opposite_cases or [])
               if getattr(c, "verdict", None) == opp and payload_match(spec, c)]
    if mishits:                                                    # 考试②反例回归:相反判例被命中 → 拒
        return None, {"reason": "regression_mishit", "mishits": mishits[:5]}
    exp = Experience(skill=skill, kind="payload", verdict=v.verdict, fingerprint={}, rule=spec,
                     playbook=[], created_by=agent_name, origin_case_id=alert.alert_uid,
                     origin_verdict_id=v.verdict_id, note=spec.get("note"))
    exp_store.add(exp)
    return exp, {"reason": "added", "exp_id": exp.exp_id}
