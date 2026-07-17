"""第二类经验库:Experience 记录 + 内存 store CRUD + 进程内缓存(写后失效)。

openGauss 真连在 Phase 6 server2 验;这里全用内存实现(= 未配 og 时的降级实现)。
"""
import pytest

from soc_agent.experience.store import (
    Experience,
    ExperienceCache,
    InMemoryExperienceStore,
)


def _threat_exp(skill="kerberoast", **kw):
    d = dict(skill=skill, kind="threat", verdict="true_positive",
             fingerprint={"finding_ids": ["kerberoast.rc4_requested"]},
             rule={"exists": "kerberoast.rc4_requested"},
             playbook=[{"order": 1, "primitive": "disable_account"}])
    d.update(kw)
    return Experience(**d)


def _benign_exp(skill="kerberoast", **kw):
    d = dict(skill=skill, kind="benign_fp", verdict="false_positive",
             fingerprint={"finding_ids": ["kerberoast.requester_is_machine"]})
    d.update(kw)
    return Experience(**d)


# ---- 记录 ----
def test_experience_roundtrip():
    e = _threat_exp(origin_case_id="c1", created_by="qwen32b-ft")
    assert Experience.from_dict(e.to_dict()) == e


def test_experience_rejects_bad_kind_and_status():
    with pytest.raises(ValueError):
        Experience(skill="k", kind="nonsense", verdict="true_positive")
    with pytest.raises(ValueError):
        _threat_exp(status="weird")


# ---- 内存 store ----
def test_store_add_and_active_for_skill():
    store = InMemoryExperienceStore()
    eid = store.add(_threat_exp())
    assert isinstance(eid, str)
    store.add(_benign_exp())
    store.add(_threat_exp(skill="lsass_dump"))
    assert {e.exp_id for e in store.active_for_skill("kerberoast")} == set(
        e.exp_id for e in store.all() if e.skill == "kerberoast")
    assert len(store.active_for_skill("kerberoast")) == 2
    assert len(store.active_for_skill("lsass_dump")) == 1


def test_store_by_kind_and_status_filtering():
    store = InMemoryExperienceStore()
    t = _threat_exp()
    store.add(t)
    store.add(_benign_exp())
    assert [e.kind for e in store.by_kind("kerberoast", "threat")] == ["threat"]
    assert [e.kind for e in store.by_kind("kerberoast", "benign_fp")] == ["benign_fp"]
    store.set_status(t.exp_id, "archived")                      # 归档 → 不再 active
    assert store.by_kind("kerberoast", "threat") == []
    assert len(store.active_for_skill("kerberoast")) == 1


def test_store_bump_hit_and_override():
    store = InMemoryExperienceStore()
    t = _threat_exp()
    store.add(t)
    store.bump_hit(t.exp_id)
    store.bump_hit(t.exp_id)
    store.bump_override(t.exp_id)
    got = store.get(t.exp_id)
    assert got.hit_count == 2 and got.override_count == 1


def test_empty_store_degrades_to_no_experience():
    assert InMemoryExperienceStore().active_for_skill("kerberoast") == []


# ---- 进程内缓存 ----
def test_cache_memoizes_then_invalidates_on_write():
    store = InMemoryExperienceStore()
    e1 = _threat_exp()
    store.add(e1)
    cache = ExperienceCache(store)
    assert [e.exp_id for e in cache.active_for_skill("kerberoast")] == [e1.exp_id]   # 装载
    store.add(_threat_exp())                                     # 绕过缓存直接写底层
    assert len(cache.active_for_skill("kerberoast")) == 1        # 仍是缓存旧值(证明有缓存)
    e3 = cache.add(_threat_exp())                                # 经缓存写 → 失效该 skill
    assert e3 is not None
    assert len(cache.active_for_skill("kerberoast")) == 3        # 重载,含绕过写的那条


def test_cache_by_kind_and_status_change_invalidate():
    store = InMemoryExperienceStore()
    t = _threat_exp()
    store.add(t)
    cache = ExperienceCache(store)
    assert len(cache.by_kind("kerberoast", "threat")) == 1
    cache.set_status(t.exp_id, "archived")                       # 状态变 → 失效
    assert cache.by_kind("kerberoast", "threat") == []


def test_opengauss_module_imports_without_psycopg2_and_uses_text_json():
    # dev 机无 psycopg2:模块可 import(psycopg2 惰性),DDL 用 text 存 JSON(避 jsonb 方言)
    from soc_agent.experience import opengauss
    joined = " ".join(opengauss.ddl("soc"))
    assert "CREATE SCHEMA IF NOT EXISTS soc" in joined
    assert "soc.experience" in joined and "soc.cases" in joined
    assert "fingerprint text" in joined and "findings text" in joined
    assert "jsonb" not in joined
