"""研判留痕持久化(HAS_TRACE→:Trace)+ 收紧3 落库限大小(丢行数据/截断 prompt)。

纯逻辑(build_write_statements),不连 neo4j。
"""
import json

from soc_agent.graph.client import build_constraints, build_write_statements
from soc_agent.models import InvestigationResult, Verdict


def _res(trace, reuse=None):
    v = Verdict("true_positive", confidence=0.9, agent="q")
    return InvestigationResult(alert_uid="a1", path="B", verdict=v, skill="kerberoast",
                               trace=trace, reuse_verdict_id=reuse)


def test_trace_persisted_and_size_bounded():
    trace = [
        {"tool": "run_cypher",
         "args": {"query": "MATCH (x)   RETURN x"},
         "result": {"rows": [{"a": 1}, {"a": 2}, {"a": 3}]}},     # 3 行真数据
        {"tool": "llm_input", "content": "X" * 5000},              # 大 prompt
        {"tool": "guardrail", "decision": "propose_only", "action": "disable_account",
         "target": "vagrant", "reason": "TP"},
    ]
    stmts = build_write_statements("a1", _res(trace))
    tstmts = [(c, p) for c, p in stmts if "HAS_TRACE" in c]
    assert len(tstmts) == 1
    c, p = tstmts[0]
    assert "MERGE (a)-[:HAS_TRACE]->(t:Trace {alert_uid:$alert_uid})" in c and "SET t.steps=$steps" in c
    steps = json.loads(p["steps"])
    # run_cypher:行数据被丢,只留计数 + 归一化后的 query
    assert steps[0]["tool"] == "run_cypher" and steps[0]["rows"] == 3
    assert "result" not in steps[0] and steps[0]["query"].startswith("MATCH (x) RETURN x")
    # 大 content:只留长度 + 截断预览,原文绝不落库
    assert steps[1]["content_len"] == 5000
    assert len(steps[1]["content_preview"]) <= 600
    assert "X" * 5000 not in p["steps"]
    # 小标量步骤原样留
    assert steps[2]["decision"] == "propose_only" and steps[2]["target"] == "vagrant"


def test_reuse_path_writes_no_trace():
    stmts = build_write_statements("a1", _res([{"tool": "x"}], reuse="ORIGIN_V"))
    assert not any("HAS_TRACE" in c for c, _ in stmts)             # 复用未真研判 → 不落 trace


def test_no_trace_no_stmt():
    assert not any("HAS_TRACE" in c for c, _ in build_write_statements("a1", _res([])))


def test_trace_step_cap():
    big = [{"tool": "recipe_step", "step": f"s{i}", "rows": i} for i in range(1000)]
    tp = [p for c, p in build_write_statements("a1", _res(big)) if "HAS_TRACE" in c][0]
    assert len(json.loads(tp["steps"])) <= 400                     # 步数封顶,防超长 trace 膨胀


def test_trace_constraint_present():
    assert "t.alert_uid IS UNIQUE" in " ".join(build_constraints())
