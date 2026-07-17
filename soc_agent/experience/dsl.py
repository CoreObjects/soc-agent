"""威胁判定规则的受限 DSL 解释器(第二类经验:确定性验证)。

规则 = JSON 表达式树,作用于一次取证的 findings(list[Finding] 或 list[dict])。
算子(克制,仅此):
  {"exists": "finding_id"}                          某 finding 是否出现
  {"eq": ["fid:attr", value]}                       ∃ 某 finding 其 attr == value
  {"gt"|"gte"|"lt"|"lte": ["fid:attr", number]}     ∃ 数值比较
  {"in": ["fid:attr", [v, ...]]}                    ∃ attr ∈ 集合(桶/枚举)
  {"same_source": ["fid_a:attr", "fid_b:attr"]}     同源关联:两类 finding 的 attr 有相等值
  {"and"|"or": [node, ...]}   {"not": node}         布尔组合

比较一律"存在性"语义(findings 是一次告警的集合)。evaluate(rule, findings) -> (hit, trace);
确定、可解释。畸形规则(未知算子/结构不对/ref 无 :attr)→ DSLError —— 考试期用它拒规则;
快通道用 safe_evaluate 兜为不命中(fail-closed,不崩 daemon)。
"""

__all__ = ["DSLError", "evaluate", "safe_evaluate"]

_CMP = {"eq", "gt", "gte", "lt", "lte", "in"}


class DSLError(ValueError):
    """规则畸形(未知算子 / 结构非法 / 字段引用非法)。"""


def _finding_view(findings):
    """归一为 {finding_id: [attrs, ...]};接受 Finding 对象或 dict。"""
    idx = {}
    for f in findings or []:
        if hasattr(f, "finding_id"):
            fid, attrs = f.finding_id, (f.attrs or {})
        else:
            fid, attrs = f.get("finding_id"), (f.get("attrs") or {})
        if fid is None:
            continue
        idx.setdefault(fid, []).append(attrs)
    return idx


def _split_ref(ref):
    if not isinstance(ref, str) or ":" not in ref:
        raise DSLError(f"字段引用须为 'finding_id:attr':{ref!r}")
    fid, _, attr = ref.partition(":")
    if not fid or not attr:
        raise DSLError(f"字段引用须为 'finding_id:attr':{ref!r}")
    return fid, attr


def _values(idx, ref):
    fid, attr = _split_ref(ref)
    return [a.get(attr) for a in idx.get(fid, [])]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _require_pair(op, operand):
    if not isinstance(operand, (list, tuple)) or len(operand) != 2:
        raise DSLError(f"{op} 操作数须是 [ref, value]:{operand!r}")
    return operand[0], operand[1]


def _eval_cmp(op, operand, idx):
    ref, target = _require_pair(op, operand)
    vals = _values(idx, ref)
    if op == "eq":
        return any(v == target for v in vals)
    if op == "in":
        if not isinstance(target, (list, tuple, set)):
            raise DSLError(f"in 的第二操作数须是列表:{target!r}")
        return any(v in target for v in vals)
    t = _num(target)
    if t is None:
        raise DSLError(f"{op} 的比较值须是数值:{target!r}")
    ops = {"gt": lambda a: a > t, "gte": lambda a: a >= t,
           "lt": lambda a: a < t, "lte": lambda a: a <= t}
    fn = ops[op]
    return any(_num(v) is not None and fn(_num(v)) for v in vals)


def _eval_same_source(operand, idx):
    ref_a, ref_b = _require_pair("same_source", operand)
    a = {v for v in _values(idx, ref_a) if v is not None}
    b = {v for v in _values(idx, ref_b) if v is not None}
    return bool(a & b)


def _require_list(operand, op):
    if not isinstance(operand, (list, tuple)):
        raise DSLError(f"{op} 操作数须是节点列表:{operand!r}")


def _eval(node, idx, trace):
    if not isinstance(node, dict) or len(node) != 1:
        raise DSLError(f"规则节点须是单键 dict:{node!r}")
    op, operand = next(iter(node.items()))
    if op == "exists":
        if not isinstance(operand, str):
            raise DSLError(f"exists 操作数须是 finding_id 字符串:{operand!r}")
        r = operand in idx
        trace.append({"op": "exists", "ref": operand, "result": r})
        return r
    if op in _CMP:
        r = _eval_cmp(op, operand, idx)
        trace.append({"op": op, "operand": operand, "result": r})
        return r
    if op == "same_source":
        r = _eval_same_source(operand, idx)
        trace.append({"op": "same_source", "operand": operand, "result": r})
        return r
    if op == "not":
        r = not _eval(operand, idx, trace)
        trace.append({"op": "not", "result": r})
        return r
    if op in ("and", "or"):
        _require_list(operand, op)
        results = [_eval(n, idx, trace) for n in operand]        # 全评(不短路),trace 完整可解释
        r = all(results) if op == "and" else any(results)
        trace.append({"op": op, "n": len(results), "result": r})
        return r
    raise DSLError(f"未知算子:{op!r}")


def evaluate(rule, findings):
    """确定性执行规则。返回 (hit: bool, trace: list)。畸形规则抛 DSLError。"""
    idx = _finding_view(findings)
    trace = []
    hit = _eval(rule, idx, trace)
    return hit, trace


def safe_evaluate(rule, findings):
    """快通道用:畸形规则 fail-closed 为不命中,不抛异常。"""
    try:
        return evaluate(rule, findings)
    except DSLError as e:
        return False, [{"op": "error", "error": str(e)}]
