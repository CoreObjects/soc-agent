"""工具箱:暴露给 LLM 的工具 + 调度。

run_cypher       只读取证(过守卫;写被拦、图错误被包成 {error} 让 LLM 改写,不崩循环)。
finalize_verdict 终结工具(LLM 调它给结论;orchestrator 特判、不当普通工具派发)。
"""
from soc_agent.tools import default_toolbox


class FakeGraph:
    def __init__(self, rows=None, err=None):
        self.rows = rows if rows is not None else []
        self.err = err
        self.queries = []

    def run_cypher(self, q):
        self.queries.append(q)
        if self.err:
            raise self.err
        return self.rows


def test_specs_are_openai_shaped():
    tb = default_toolbox(FakeGraph())
    names = {s["function"]["name"] for s in tb.specs()}
    assert "run_cypher" in names and "finalize_verdict" in names
    for s in tb.specs():
        assert s["type"] == "function"
        assert "parameters" in s["function"]


def test_run_cypher_dispatch_returns_rows():
    g = FakeGraph(rows=[{"sam": "jon.snow"}])
    out = default_toolbox(g).dispatch("run_cypher", {"query": "MATCH (a:Account) RETURN a.sam AS sam"})
    assert out["rows"] == [{"sam": "jon.snow"}]
    assert g.queries[0].startswith("MATCH")


def test_run_cypher_blocks_writes_via_guard():
    g = FakeGraph()
    out = default_toolbox(g).dispatch("run_cypher", {"query": "MATCH (a) SET a.x = 1"})
    assert "error" in out
    assert g.queries == []          # 守卫拦下,根本没打到图


def test_run_cypher_wraps_graph_error():
    g = FakeGraph(err=RuntimeError("boom"))
    out = default_toolbox(g).dispatch("run_cypher", {"query": "MATCH (n) RETURN n"})
    assert "error" in out and "boom" in out["error"]


def test_finalize_is_terminal():
    tb = default_toolbox(FakeGraph())
    assert tb.is_terminal("finalize_verdict") is True
    assert tb.is_terminal("run_cypher") is False


def test_unknown_tool_returns_error():
    out = default_toolbox(FakeGraph()).dispatch("nonexistent", {})
    assert "error" in out
