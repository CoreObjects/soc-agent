"""Web 读路由单测:FastAPI TestClient + dependency_overrides,mock graph/exp_store(离线,3.10)。

断言路由把现成查询/store 的返回**拼装成对的响应形状**(队列分页、完整溯源、大盘含复用拆分、经验库)。
"""
import json

import pytest
from fastapi.testclient import TestClient

from soc_agent.config import Config
from soc_agent.experience.store import Experience
from soc_agent.web import deps
from soc_agent.web.app import create_app


class FakeGraph:
    """按 cypher 关键片段分发 canned 行(仿 test_poller._FakeGraph)。"""

    def __init__(self):
        self.node = {
            "alert_uid": "u1", "source": "wazuh", "sensor": "srv01",
            "rule_id": "100", "rule_description": "kerberoast RC4",
            "severity": 12, "technique_ids": ["T1558.003"], "time": "2026-07-25T00:00:00Z",
            "raw": json.dumps({"data": {"win": {"eventdata": {"ticketEncryptionType": "0x17"}}}}),
        }

    def get_alert(self, uid):
        return dict(self.node) if uid == "u1" else None

    def seed(self, alert):
        return {"event": {"event_code": "4769"}, "subject": {"sam": "vagrant"}, "related": []}

    def recall_ledger(self, uid):
        return None

    def run_cypher(self, cypher, **p):
        if "count(DISTINCT a.alert_uid) AS n" in cypher:
            return [{"n": 2}]
        if "SKIP $skip LIMIT $limit" in cypher:
            return [
                {"alert_uid": "u1", "rule_description": "kerberoast RC4", "severity": 12,
                 "technique_ids": ["T1558.003"], "source": "wazuh", "sensor": "srv01",
                 "verdict": "true_positive", "path": "B", "method": "llm",
                 "plan_status": "proposed", "arrival_ms": 200, "concluded_at": "2026-07-25T01:00:00Z"},
                {"alert_uid": "u2", "rule_description": "cross-domain machine ticket", "severity": 5,
                 "technique_ids": ["T1558.003"], "source": "wazuh", "sensor": "srv02",
                 "verdict": "false_positive", "path": "A", "method": "reuse",
                 "plan_status": None, "arrival_ms": 100, "concluded_at": "2026-07-25T00:30:00Z"},
            ]
        if "HAS_FINDING" in cypher:
            return [{"finding_id": "kerberoast.rc4_requested", "polarity": "red",
                     "evidence_ref": "ev1", "skill": "kerberoast", "attrs": json.dumps({"enc": "0x17"})}]
        if "HAS_TRACE" in cypher:
            return [{"steps": json.dumps([{"tool": "run_cypher", "rows": 3}, {"tool": "verdict"}])}]
        if "origin.alert_uid AS origin_uid" in cypher:
            return [{"verdict_id": None, "verdict": None, "origin_uid": None}]   # u1 非复用
        if "c.evidence_refs AS evidence_refs" in cypher:
            return [{"verdict": "true_positive", "lean": None, "agent": "qwen32b-ft",
                     "path": "B", "method": "llm", "confidence": 0.9, "concluded_at": "2026-07-25T01:00:00Z",
                     "summary": "用户账号被 kerberoast", "rationale": "SPN 扇出 12 + RC4",
                     "evidence_refs": ["ev1"], "missing_evidence": [],
                     "dispositions": [
                         {"action": "disable_account", "target": "vagrant", "target_kind": "account",
                          "status": "proposed", "risk": "high", "params": "{}", "step_key": "u1#1"},
                         {"action": "none", "status": "none", "step_key": "__no_op__"},   # 单例,应被滤
                     ]}]
        if "NOT (a)-[:CONCLUDED]->()" in cypher:
            return [{"n": 40}]
        if "coalesce(a.poller_skip,false)=true" in cypher:
            return [{"n": 0}]
        if "count(DISTINCT a) AS n" in cypher:
            return [{"n": 60}]
        if "coalesce(c.method,'llm') AS method" in cypher:
            return [{"method": "reuse", "path": "A", "n": 10},
                    {"method": "llm", "path": "S", "n": 45},
                    {"method": "llm", "path": "B", "n": 5}]
        if "v.verdict AS verdict, coalesce(c.path,v.path) AS path" in cypher:
            return [{"verdict": "false_positive", "path": "S", "n": 45},
                    {"verdict": "true_positive", "path": "B", "n": 5}]
        if "d.step_key <> '__no_op__'" in cypher:
            return [{"status": "proposed", "n": 5}]
        if "(p:ResponsePlan) RETURN p.status AS status" in cypher:
            return [{"status": "proposed", "n": 5}]
        if "verdict:'true_positive'" in cypher:
            return [{"uid": "u1", "plan": "proposed",
                     "steps": [{"action": "disable_account", "target": "vagrant", "status": "proposed"}]}]
        if "(p:ResponsePlan {status:$status})" in cypher:
            return [{"plan_id": "u1", "status": "proposed", "claimed_by": None,
                     "alert_uid": "u1", "verdict": "true_positive", "rationale": "SPN 扇出"}]
        if "[st:STEP]->(d:Disposition)" in cypher and "st.order AS order" in cypher:
            return [{"order": 1, "step_key": "u1#1", "primitive": "disable_account",
                     "params": "{}", "target": "vagrant", "target_kind": "account",
                     "risk": "high", "status": "proposed", "rollback_handle": None}]
        return []


class FakeExp:
    def all(self):
        return [
            Experience(skill="kerberoast", kind="threat", verdict="true_positive",
                       note="用户账号 SPN 扇出", hit_count=3, origin_case_id="u1"),
            Experience(skill="kerberoast", kind="benign_fp", verdict="false_positive",
                       note="跨域机器账号引荐票", hit_count=20, origin_case_id="u2"),
        ]


@pytest.fixture
def client():
    app = create_app()
    g, e = FakeGraph(), FakeExp()
    app.dependency_overrides[deps.get_graph] = lambda: g
    app.dependency_overrides[deps.get_exp_store] = lambda: e
    app.dependency_overrides[deps.get_config] = lambda: Config.from_env(env={})   # 无 SOC_WEB_TOKEN → 开放
    return TestClient(app)


def test_alerts_queue_paged(client):
    r = client.get("/api/alerts?page=1&size=50")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2 and body["page"] == 1 and body["size"] == 50
    assert len(body["items"]) == 2
    it = body["items"][0]
    assert it["alert_uid"] == "u1" and it["verdict"] == "true_positive" and it["path"] == "B"
    assert it["plan_status"] == "proposed" and it["plan_status_zh"] == "待处置"


def test_alerts_queue_filter_passthrough(client):
    # 筛选参数应传到查询(count/page 都被调,返回 200)
    r = client.get("/api/alerts?verdict=true_positive&path=B&dispo_status=proposed&q=kerb")
    assert r.status_code == 200 and r.json()["total"] == 2


def test_alert_detail_full_flow(client):
    r = client.get("/api/alerts/u1")
    assert r.status_code == 200
    d = r.json()
    assert d["alert_uid"] == "u1"
    assert d["raw"]["data"]["win"]["eventdata"]["ticketEncryptionType"] == "0x17"   # raw 解析成对象
    assert d["seed"]["event"]["event_code"] == "4769"                                # 图上下文
    assert d["findings"][0]["finding_id"] == "kerberoast.rc4_requested"
    assert d["findings"][0]["attrs"] == {"enc": "0x17"}                              # attrs json 串→对象
    assert d["verdict"] == "true_positive" and d["path"] == "B" and d["method"] == "llm"
    assert d["evidence_refs"] == ["ev1"] and d["missing_evidence"] == []
    # __no_op__ 单例被滤,只留真处置
    assert len(d["dispositions"]) == 1
    assert d["dispositions"][0]["action"] == "disable_account"
    assert d["dispositions"][0]["status_zh"] == "待处置"
    assert d["trace"] == [{"tool": "run_cypher", "rows": 3}, {"tool": "verdict"}]     # 有 trace → 逐步
    assert d["reuse_source"] is None                                                 # u1 非复用


def test_alert_detail_404(client):
    assert client.get("/api/alerts/missing").status_code == 404


def test_plans_list(client):
    r = client.get("/api/plans?status=proposed")
    assert r.status_code == 200
    plans = r.json()["plans"]
    assert plans[0]["plan_id"] == "u1" and plans[0]["status_zh"] == "待处置"
    assert plans[0]["steps"][0]["primitive"] == "disable_account"


def test_stats_with_reuse_split(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    s = r.json()
    assert s["progress"]["concluded"] == 60 and s["progress"]["backlog"] == 40 and s["progress"]["poison"] == 0
    # ★收紧1:复用命中(method=reuse=10)与浅层短路(llm+S=45)、深度(llm+B=5)分开
    assert s["reuse"]["reuse_hits"] == 10
    assert s["reuse"]["shallow_short"] == 45
    assert s["reuse"]["deep"] == 5
    assert abs(s["reuse"]["reuse_rate"] - 10 / 60) < 1e-6
    assert s["dispo_status"][0]["status_zh"] == "待处置"


def test_experience_list(client):
    r = client.get("/api/experience")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 2
    assert {i["kind"] for i in items} == {"threat", "benign_fp"}
    assert items[0]["note"] and "hit_count" in items[0]


def test_experience_filter_by_kind(client):
    r = client.get("/api/experience?kind=threat")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["kind"] == "threat"
