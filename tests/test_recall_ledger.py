"""按 alert_uid(命中经验的来源 VID)从图台账捞回原始上下文:Alert 字段 + Verdict.summary/rationale + 处置。

★坑:summary/rationale 在 CONCLUDED 边(shape 从 run_cypher 扁平化后的 row 取);无处置是
`Disposition{action:'none', step_key:'__no_op__'}` 单例 → 捞回时过滤掉,只留真处置。
"""
from soc_agent.graph.client import Neo4jGraph, shape_ledger, _LEDGER_CYPHER


def _row(**over):
    row = {"alert": {"source": "wazuh", "sensor": "castelblack", "rule_id": "100801",
                     "rule_description": "Kerberoasting", "severity": 10, "technique_ids": ["T1558.003"]},
           "verdict": "true_positive", "summary": "jon.snow 对多个 SPN 发起 RC4 请求",
           "rationale": "跨域普通域用户 roast,非机器账号", "confidence": 0.9,
           "dispositions": [{"action": "disable_account", "target": "jon.snow",
                             "target_kind": "account", "status": "proposed"}]}
    row.update(over)
    return row


def test_shape_ledger_extracts_alert_verdict_dispositions():
    led = shape_ledger([_row()])
    assert led["verdict"] == "true_positive"
    assert led["summary"] == "jon.snow 对多个 SPN 发起 RC4 请求"      # ★来自 CONCLUDED 边
    assert led["rationale"].startswith("跨域")
    assert led["alert"]["rule_description"] == "Kerberoasting"
    assert led["dispositions"] == [{"action": "disable_account", "target": "jon.snow",
                                    "target_kind": "account", "status": "proposed"}]


def test_shape_ledger_filters_noop_disposition():
    # 无处置单例 action='none' → 过滤,dispositions 空
    led = shape_ledger([_row(dispositions=[{"action": "none", "target": None,
                                            "target_kind": None, "status": "none"}])])
    assert led["dispositions"] == []


def test_shape_ledger_empty_is_none():
    assert shape_ledger([]) is None
    assert shape_ledger(None) is None


class _StubGraph(Neo4jGraph):
    """绕过 __init__(不 import neo4j),只桩 run_cypher。"""
    def __init__(self, rows):
        self._rows = rows

    def run_cypher(self, query, **params):
        self.query, self.params = query, params
        return self._rows


def test_recall_ledger_queries_by_uid_and_injects_uid():
    g = _StubGraph([_row()])
    led = g.recall_ledger("a0")
    assert g.params == {"uid": "a0"}                 # 按 alert_uid 查
    assert g.query == _LEDGER_CYPHER
    assert led["alert_uid"] == "a0"                  # 回填 VID,自描述
    assert led["verdict"] == "true_positive"


def test_recall_ledger_missing_returns_none():
    assert _StubGraph([]).recall_ledger("nope") is None
