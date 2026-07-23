"""浅度研判硬底线 `cascade.floor.force_deep` 单测。

★2026-07-23 起 floor 退成空底线(不再按高危技战术强制升级 —— 那些是签名直判的 B 类,升级只补
细节不改结论)。故 force_deep 现在对任何告警都返回 False,升/不升全交浅层 LLM。
"""
from soc_agent.cascade.floor import force_deep
from soc_agent.models import Alert


def _alert(**kw):
    kw.setdefault("alert_uid", "a-1")
    return Alert(**kw)


def test_high_stakes_technique_no_longer_forces():
    # DCSync(T1003.006)是签名直判的 B 类,不再强制升级
    a = _alert(technique_ids=["T1003.006"], rule_description="directory replication request")
    assert force_deep(a, {"protected_hosts": [], "protected_accounts": []}) is False


def test_kerberos_technique_no_longer_forces():
    a = _alert(technique_ids=["T1558.003"])  # Kerberoast
    assert force_deep(a, None) is False


def test_protected_host_in_text_does_not_force():
    a = _alert(technique_ids=["T1059"], raw='{"host":"dc01.corp.local","cmd":"whoami"}')
    assert force_deep(a, {"protected_hosts": ["dc01"], "protected_accounts": []}) is False


def test_normal_technique_does_not_force():
    a = _alert(technique_ids=["T1190"], rule_description="SQLi attempt on /login")
    assert force_deep(a, None) is False


def test_no_technique_is_false():
    a = _alert(technique_ids=[], rule_description="benign scheduled login")
    assert force_deep(a, None) is False
