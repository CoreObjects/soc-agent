"""auto 模式处置编排 + 处置状态中文标识单测(mock graph,3.10 可跑)。"""
from soc_agent.response.auto import auto_respond, zh_status


def test_zh_status_pending_and_done():
    assert zh_status("proposed") == "待处置"
    assert zh_status("executed") == "已处置"
    assert zh_status("none") == "无需处置"
    assert zh_status("weird") == "weird"          # 未知原样返回


class _FakeGraph:
    def __init__(self, plan_ids):
        self._plan_ids = plan_ids
        self.writes = []

    def run_cypher(self, cypher, **params):
        if "status='proposed'" in cypher:         # q_alert_proposed_plans
            return [{"plan_id": pid} for pid in self._plan_ids]
        return []

    def run_write(self, cypher, **params):
        self.writes.append((cypher, params))
        return [{"x": 1}]                          # 守卫式转移返回非空=成功


def test_auto_respond_approves_without_appliance():
    g = _FakeGraph(["a1"])
    out = auto_respond(g, client=None, alert_uid="a1")
    assert out == [{"plan_id": "a1", "approved": True, "executed": None}]
    assert any("approved" in c for c, _ in g.writes)          # approve 转移被写(proposed→approved)


def test_auto_respond_no_plan_is_noop():
    g = _FakeGraph([])                             # FP 无处置计划
    assert auto_respond(g, client=None, alert_uid="a1") == []


def test_auto_respond_executes_with_appliance(monkeypatch):
    import soc_agent.respond_cli as rc
    ran = []
    monkeypatch.setattr(rc, "approve", lambda g, pid, by, now: True)
    monkeypatch.setattr(rc, "run_plan",
                        lambda g, c, pid, now, lease: (ran.append(pid) or {"ok": True, "steps": [{"order": 1}]}))

    class _Client:
        enabled = True

    g = _FakeGraph(["a1"])
    out = auto_respond(g, client=_Client(), alert_uid="a1")
    assert ran == ["a1"]                           # auto 模式真调 run_plan(执行)
    assert out[0]["executed"] is True
