"""行为指纹:构造(占位符抽象/易变剔除/语义保留)+ 匹配(加权重合度,非全等)。"""
from soc_agent.experience.fingerprint import build_fingerprint, match
from soc_agent.forensics import Finding


def _kerb_findings():
    return [Finding("kerberoast.rc4_requested", {"enc_type": "0x17"}),
            Finding("kerberoast.requester_is_machine", {"sam": "DC01$"}),
            Finding("kerberoast.cross_domain", {"req_domain": "NORTH", "tgt_domain": "ESSOS"})]


def _kerb_bindings():
    return {"attacker_account": "DC01$", "attacker_account_domain": "NORTH",
            "target_account": "svc", "target_account_domain": "ESSOS"}


# ---- 构造 ----
def test_build_abstracts_account_keeps_semantic_drops_volatile():
    fs = [Finding("k.mach", {"sam": "DC01$", "pid": 4242, "enc_type": "0x17"})]
    fp = build_fingerprint(fs, {"attacker_account": "DC01$"})
    canon = fp["canon"]["k.mach"]
    assert canon["sam"] == "<attacker_account>"       # 账号(实例值)抽象为占位符
    assert canon["enc_type"] == "0x17"                # 语义值保留
    assert "pid" not in canon                         # 易变字段剔除
    assert fp["finding_ids"] == ["k.mach"]


def test_build_keeps_process_image_raw():
    fs = [Finding("lsass.source_is_security_agent",
                  {"agent": "Wazuh", "src_image": r"C:\Program Files\Wazuh\wazuh-agent.exe"})]
    fp = build_fingerprint(fs, {"source_process": r"C:\Program Files\Wazuh\wazuh-agent.exe"})
    canon = fp["canon"]["lsass.source_is_security_agent"]
    assert "wazuh-agent.exe" in canon["src_image"]     # 进程名不抽象(可移植承重 key,守红线)


def test_build_subset_selects_ids():
    fp = build_fingerprint(_kerb_findings(), _kerb_bindings(),
                           subset_ids=["kerberoast.requester_is_machine", "kerberoast.cross_domain"])
    assert set(fp["finding_ids"]) == {"kerberoast.requester_is_machine", "kerberoast.cross_domain"}


# ---- 匹配 ----
def test_match_hits_other_instance_via_placeholder():
    fp = build_fingerprint(_kerb_findings(), _kerb_bindings(),
                           subset_ids=["kerberoast.requester_is_machine", "kerberoast.cross_domain"])
    other = [Finding("kerberoast.requester_is_machine", {"sam": "SRV9$"}),
             Finding("kerberoast.cross_domain", {"req_domain": "WEST", "tgt_domain": "EAST"})]
    hit, score, matched = match(fp, other)             # 不同账号/域,结构相同 → 占位符通配 → 命中
    assert hit is True and score == 1.0
    assert set(matched) == {"kerberoast.requester_is_machine", "kerberoast.cross_domain"}


def test_match_partial_below_threshold():
    fp = build_fingerprint(_kerb_findings(), _kerb_bindings())     # 3 个 finding
    partial = [Finding("kerberoast.requester_is_machine", {"sam": "X$"})]
    hit, score, _ = match(fp, partial, threshold=1.0)
    assert hit is False and abs(score - 1 / 3) < 1e-6
    assert match(fp, partial, threshold=0.3)[0] is True            # 阈值放宽 → 命中(模糊召回)


def test_match_decisive_raw_attr_mismatch_misses():
    # 良性指纹键在原始进程名;换成攻击进程 → 决定性字段不符 → 不命中(防伪装成良性)
    benign = build_fingerprint([Finding("lsass.lsass_accessed", {"src_image": "wazuh-agent.exe"})],
                               {"source_process": "wazuh-agent.exe"})
    evil = [Finding("lsass.lsass_accessed", {"src_image": "mimikatz.exe"})]
    assert match(benign, evil, threshold=1.0)[0] is False


def test_match_empty_fp_and_dict_findings():
    # 空指纹不命中;findings 传 dict 也能匹配
    assert match({"finding_ids": [], "canon": {}, "weights": {}}, _kerb_findings())[0] is False
    fp = build_fingerprint([{"finding_id": "a.b", "attrs": {"x": 1}}], {})
    assert match(fp, [{"finding_id": "a.b", "attrs": {"x": 1}}])[0] is True
