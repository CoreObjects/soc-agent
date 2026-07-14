"""核心数据契约:Alert(取自 :Alert 节点)/ Verdict / Disposition / InvestigationResult。

Verdict/Disposition 的 to_props() 直接喂图写回(经验层);处置默认仅建议(propose-only)。
"""
import pytest

from soc_agent.models import Alert, Disposition, InvestigationResult, Verdict


def test_alert_from_graph_node():
    node = {
        "alert_uid": "abc", "source": "wazuh", "rule_id": "100002",
        "rule_description": "Kerberoasting", "severity": 10,
        "technique_ids": ["T1558.003"], "time": "2026-07-09T10:00:00Z",
        "raw_ref": "soc-hids-alert-x:1",
    }
    a = Alert.from_node(node)
    assert a.alert_uid == "abc"
    assert a.rule_id == "100002"
    assert a.technique_ids == ["T1558.003"]
    assert a.primary_technique == "T1558.003"


def test_alert_primary_technique_none_when_empty():
    a = Alert.from_node({"alert_uid": "x"})
    assert a.primary_technique is None
    assert a.technique_ids == []


def test_verdict_valid_and_props():
    v = Verdict(verdict="true_positive", confidence=0.9, summary="s", rationale="r",
                evidence_refs=["e1"], agent="qwen32b-ft")
    assert v.verdict == "true_positive"
    p = v.to_props()
    assert p["verdict"] == "true_positive"
    assert p["confidence"] == 0.9
    assert p["verdict_id"]                    # 自动生成非空
    assert p["summary"] == "s"


def test_verdict_rejects_unknown_verdict():
    with pytest.raises(ValueError):
        Verdict(verdict="totally_pwned", confidence=1.0)


def test_verdict_lean_validation_and_props():
    v = Verdict(verdict="suspicious", lean="benign", confidence=0.5)
    assert v.to_props()["lean"] == "benign"        # lean 进 to_props(写回图)
    with pytest.raises(ValueError):
        Verdict(verdict="suspicious", lean="totally_bad")


def test_verdict_ids_unique():
    a = Verdict(verdict="benign", confidence=0.1)
    b = Verdict(verdict="benign", confidence=0.1)
    assert a.verdict_id != b.verdict_id


def test_disposition_defaults_propose_only():
    d = Disposition(action="disable_account", target="jon.snow", risk="high")
    assert d.status == "proposed"             # 默认仅建议,不自动执行
    assert d.by == "auto"
    p = d.to_props()
    assert p["disposition_id"]
    assert p["action"] == "disable_account"
    assert p["target"] == "jon.snow"


def test_disposition_rejects_bad_status_and_risk():
    with pytest.raises(ValueError):
        Disposition(action="block_ip", target="1.2.3.4", risk="nope")
    with pytest.raises(ValueError):
        Disposition(action="block_ip", target="1.2.3.4", status="whatever")


def test_investigation_result_bundles():
    v = Verdict(verdict="benign", confidence=0.5)
    r = InvestigationResult(alert_uid="abc", path="B", verdict=v, dispositions=[], latency_ms=1234)
    assert r.path == "B"
    assert r.verdict.verdict == "benign"
    assert r.dispositions == []
