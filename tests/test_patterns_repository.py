"""规则库仓储(patterns.repository)—— 接口 + 内存 fake。

规则 = 签名 → verdict+处置模板 + 状态(pending/active/deprecated)。
仓储必须:按 sig_hash 去重(upsert 幂等)、find_active 只服务 active(快通道热读)、状态可转、命中计数。
openGauss/Redis 具体适配按这份接口另建;本测用内存 fake。
"""
from soc_agent.patterns.rule import PatternRule, VerdictTemplate, PrimitiveStepTemplate
from soc_agent.patterns.repository import InMemoryPatternRepository


def _rule(sig_hash="h1", status="active", skill="kerberoast", layer="incriminating"):
    return PatternRule(
        skill=skill, layer=layer, sig="enc=RC4;spn_fanout=>=5", sig_hash=sig_hash,
        verdict=VerdictTemplate(verdict="true_positive", confidence=0.9, canonical_rationale="RC4 扇出"),
        plan=[PrimitiveStepTemplate(order=1, primitive="disable_account",
                                    params={"sam": {"source": "entity_role", "role": "requester"}}, risk="high")],
        status=status)


def test_pattern_id_is_sig_hash():
    assert _rule(sig_hash="abc").pattern_id == "abc"          # pattern_id 就是 sig_hash(确定性、稳定溯源)


def test_upsert_dedups_by_sig_hash():
    repo = InMemoryPatternRepository()
    repo.upsert(_rule(sig_hash="h1"))
    repo.upsert(_rule(sig_hash="h1"))                         # 同键再铸
    assert len(repo.all()) == 1                              # 去重成一条


def test_upsert_bumps_hit_count():
    repo = InMemoryPatternRepository()
    repo.upsert(_rule(sig_hash="h1"))
    repo.upsert(_rule(sig_hash="h1"))
    assert repo.get("h1").stats["hit_count"] == 2


def test_find_active_only_active():
    repo = InMemoryPatternRepository()
    repo.upsert(_rule(sig_hash="h1", status="pending"))
    assert repo.find_active("h1") is None                    # pending 不上快通道
    repo.set_status("h1", "active")
    assert repo.find_active("h1").sig_hash == "h1"


def test_find_active_miss_returns_none():
    assert InMemoryPatternRepository().find_active("nope") is None


def test_deprecated_not_served():
    repo = InMemoryPatternRepository()
    repo.upsert(_rule(sig_hash="h1", status="active"))
    repo.set_status("h1", "deprecated")
    assert repo.find_active("h1") is None


def test_list_pending():
    repo = InMemoryPatternRepository()
    repo.upsert(_rule(sig_hash="h1", status="pending"))
    repo.upsert(_rule(sig_hash="h2", status="active"))
    assert [r.sig_hash for r in repo.list_pending()] == ["h1"]
