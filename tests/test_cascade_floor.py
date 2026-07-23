"""浅度研判硬底线 `cascade.floor.force_deep` 单测。

纯 Python、只读告警字段(technique_ids / rule_description / raw),不查图不 seed。
职责:高危技战术 或 告警文本涉及受保护主机(DC/CA)→ 强制升级深度研判(不许浅层终局)。
"""
from soc_agent.cascade.floor import force_deep
from soc_agent.models import Alert


def _alert(**kw):
    kw.setdefault("alert_uid", "a-1")
    return Alert(**kw)


def test_high_stakes_technique_forces_deep():
    # DCSync 子技术 T1003.006 → 前缀 T1003(凭据转储)命中
    a = _alert(technique_ids=["T1003.006"], rule_description="directory replication request")
    assert force_deep(a, {"protected_hosts": [], "protected_accounts": []}) is True


def test_kerberos_technique_forces_deep():
    a = _alert(technique_ids=["T1558.004"])  # AS-REP Roasting → 前缀 T1558
    assert force_deep(a, None) is True


def test_normal_technique_no_asset_does_not_force():
    a = _alert(technique_ids=["T1190"], rule_description="SQLi attempt on /login")
    assert force_deep(a, {"protected_hosts": ["dc01"], "protected_accounts": []}) is False


def test_protected_host_in_text_forces_deep():
    a = _alert(technique_ids=["T1059"], raw='{"host":"dc01.corp.local","cmd":"whoami"}')
    assert force_deep(a, {"protected_hosts": ["dc01"], "protected_accounts": []}) is True


def test_protected_host_substring_no_false_positive():
    # adc01 不应被 dc01 命中(子串 bug 防回归,和 disposition._host_matches 一致的纪律)
    a = _alert(technique_ids=["T1059"], raw='{"host":"adc01","cmd":"whoami"}')
    assert force_deep(a, {"protected_hosts": ["dc01"], "protected_accounts": []}) is False


def test_protected_host_given_as_fqdn_matches_bare_label():
    a = _alert(technique_ids=["T1059"], raw='{"host":"dc01"}')
    assert force_deep(a, {"protected_hosts": ["dc01.corp.local"], "protected_accounts": []}) is True


def test_no_technique_no_asset_is_false():
    a = _alert(technique_ids=[], rule_description="benign scheduled login")
    assert force_deep(a, {"protected_hosts": ["dc01"], "protected_accounts": []}) is False
