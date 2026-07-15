"""server2 冒烟:openGauss 规则库真库 upsert/find_active/去重/状态/清理 全通(读 .env 的 OG_*)。

单机测过序列化/缓存/接口契约;这个在 server2 上验真 openGauss(建表+读写+去重)。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.patterns.factory import make_repository
from soc_agent.patterns.rule import PatternRule, VerdictTemplate, PrimitiveStepTemplate

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("og_enabled=%s host=%s db=%s user=%s" % (cfg.og_enabled, cfg.og_host, cfg.og_db, cfg.og_user))
assert cfg.og_enabled, "OG_HOST 未配 → 规则库仍是内存 fake;检查 .env"

repo = make_repository(cfg)                 # CachedPatternRepository(OpenGaussPatternRepository)
SH = "__smoke_test_kerberoast__"


def _cleanup():
    import psycopg2
    c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                         user=cfg.og_user, password=cfg.og_password)
    c.autocommit = True
    with c.cursor() as cur:
        cur.execute("DELETE FROM %s.patterns WHERE sig_hash=%%s" % cfg.og_schema, (SH,))
    c.close()


_cleanup()                                  # 先清残留(幂等:上一轮夭折留的行不污染本轮)
rule = PatternRule(skill="__smoke__", layer="incriminating", sig="enc=RC4;spn_fanout=>=5", sig_hash=SH,
                   verdict=VerdictTemplate("true_positive", confidence=0.9, canonical_rationale="smoke RC4 扇出"),
                   plan=[PrimitiveStepTemplate(order=1, primitive="disable_account",
                                               params={"sam": {"source": "entity_role", "role": "requester"}}, risk="high")],
                   status="active")
try:
    repo.upsert(rule)
    got = repo.find_active(SH)
    assert got is not None, "find_active 拿不到刚 upsert 的 active 规则"
    assert got.verdict.verdict == "true_positive"
    assert got.plan[0].params["sam"]["role"] == "requester", "计划模板序列化丢字段"
    repo.upsert(rule)                        # 再铸 → 去重 + hit_count++
    g2 = repo.get(SH)
    assert g2.stats.get("hit_count", 0) >= 2, "去重/计数不对(应 >=2)"
    repo.set_status(SH, "deprecated")
    assert repo.find_active(SH) is None, "deprecated 仍被 find_active 服务"
    print("OK: upsert/find_active/dedup(hit=%s)/status/cache 全通" % g2.stats.get("hit_count"))
finally:
    _cleanup()
    print("cleanup: 测试行已删")
print("SMOKE OK")
