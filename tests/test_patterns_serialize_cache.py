"""规则序列化(↔DB行)+ 进程内热读缓存。纯逻辑,本地可测(openGauss 适配复用序列化)。"""
from soc_agent.patterns.cache import CachedPatternRepository
from soc_agent.patterns.repository import InMemoryPatternRepository
from soc_agent.patterns.rule import PatternRule, VerdictTemplate, DispositionTemplate
from soc_agent.patterns.serialize import rule_to_row, row_to_rule


def _rule(sig_hash="h1", status="active"):
    return PatternRule(
        skill="kerberoast", layer="incriminating", sig="enc=RC4;spn_fanout=>=5", sig_hash=sig_hash,
        verdict=VerdictTemplate("true_positive", lean=None, confidence=0.9, canonical_rationale="RC4 扇出"),
        dispositions=[DispositionTemplate("disable_account", "account", "requester", "high")],
        status=status)


def test_serialize_roundtrip():
    r = _rule()
    back = row_to_rule(rule_to_row(r))
    assert back.sig_hash == r.sig_hash and back.skill == r.skill and back.layer == r.layer
    assert back.status == r.status
    assert back.verdict.verdict == "true_positive" and back.verdict.confidence == 0.9
    assert back.dispositions[0].action == "disable_account"
    assert back.dispositions[0].target_field == "requester"
    assert back.pattern_id == r.pattern_id


def test_row_keys_are_db_columns():
    row = rule_to_row(_rule())
    assert set(row) == {"sig_hash", "skill", "layer", "sig", "verdict_tmpl", "disp_tmpl", "status", "stats", "provenance"}
    assert isinstance(row["verdict_tmpl"], str) and isinstance(row["disp_tmpl"], str)   # json blob


def test_cache_serves_active_and_caches():
    backing = InMemoryPatternRepository()
    backing.upsert(_rule("h1", "active"))
    cache = CachedPatternRepository(backing)
    assert cache.find_active("h1").sig_hash == "h1"
    # 篡改 backing 内部(模拟别处改)后,缓存仍返回旧值 → 证明走了缓存
    backing._by_hash["h1"].status = "deprecated"
    assert cache.find_active("h1") is not None      # 缓存命中,没回源


def test_cache_miss_cached_then_invalidated_on_status_change():
    backing = InMemoryPatternRepository()
    backing.upsert(_rule("h1", "pending"))
    cache = CachedPatternRepository(backing)
    assert cache.find_active("h1") is None          # pending 不服务,miss 缓存
    cache.set_status("h1", "active")                # 写穿 + 失效
    assert cache.find_active("h1").sig_hash == "h1"  # 回源拿到 active


def test_cache_upsert_writes_through_and_invalidates():
    backing = InMemoryPatternRepository()
    cache = CachedPatternRepository(backing)
    assert cache.find_active("h1") is None          # miss 缓存
    cache.upsert(_rule("h1", "active"))             # 写穿 + 失效 miss
    assert cache.find_active("h1").sig_hash == "h1"  # 回源拿到
