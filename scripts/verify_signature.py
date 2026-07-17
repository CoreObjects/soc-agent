"""验证某 technique 的快通道签名在真数据上工作 —— 换实例双跑式报告(会真研判+回写这批告警)。

用法: .venv/bin/python scripts/verify_signature.py <technique> [n]
跑 n 条该 technique 的未研判告警,报告:快/慢通道占比、verdict 分布、pattern 收敛(去重)、
openGauss 规则条数、台账闭环(悬空应=0)。证明:首个形状慢通道判+沉淀,同形状后续【快通道 0-LLM】复用、
FP 洪水被先证伪夹掉。
"""
import os
import sys
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build_orchestrator, run_investigation
from soc_agent.config import Config
from soc_agent.skills_runtime import SkillRegistry

tech = sys.argv[1] if len(sys.argv) > 1 else "T1003.001"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 60

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
reg = SkillRegistry(cfg.skills_dir)
skill = next((s.name for s in reg.all() for t in (s.technique_ids or []) if t == tech), None)
has_sig = bool(skill and reg.by_name(skill).signature)
print("technique=%s  skill=%s  有签名=%s  n=%d  og=%s" % (tech, skill, has_sig, n, cfg.og_enabled))

graph, orch, repo = build_orchestrator(cfg)
try:
    rows = graph.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND $t IN coalesce(a.technique_ids,[]) "
        "RETURN a.alert_uid AS uid ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT $n", t=tech, n=n)
    print("取样未研判 %s: %d 条\n" % (tech, len(rows)))

    fast = slow = 0
    verdicts = Counter()
    for i, r in enumerate(rows, 1):
        res = run_investigation(graph, orch, r["uid"])
        v = res.verdict
        fast += res.path == "A"
        slow += res.path == "B"
        verdicts[v.verdict if v else "?"] += 1
        if i <= 12 or res.path == "B":            # 头 12 条 + 所有慢通道都打印(慢的少、值得看)
            print("  [%3d] path=%s verdict=%-14s pattern=%s uid=%s"
                  % (i, res.path, v.verdict if v else "?",
                     (v.pattern or "-")[:12] if v else "-", r["uid"][:12]))

    print("\n=== 汇总 ===")
    print("快通道(0 LLM) %d / 慢通道 %d" % (fast, slow))
    print("verdict 分布:", dict(verdicts))

    conv = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict) WHERE $t IN coalesce(a.technique_ids,[]) "
        "AND v.pattern_id IS NOT NULL RETURN v.pattern_id AS pid, v.verdict AS verd, "
        "v.sig AS sig, count(DISTINCT a) AS m ORDER BY m DESC LIMIT 10", t=tech)
    print("图收敛(pattern → verdict / 共享告警数 / 可读签名):")
    for c in conv:
        print("  %-12s %-14s ×%-5d %s" % (c["pid"][:12], c["verd"], c["m"], (c.get("sig") or "")[:70]))

    tot = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict) WHERE $t IN coalesce(a.technique_ids,[]) "
        "RETURN count(DISTINCT v) AS n", t=tech)[0]["n"]
    closed = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict)-[:LED_TO]->() WHERE $t IN coalesce(a.technique_ids,[]) "
        "RETURN count(DISTINCT v) AS n", t=tech)[0]["n"]
    print("台账闭环:Verdict %d,已闭环 %d,悬空 %d(应0)" % (tot, closed, tot - closed))

    if cfg.og_enabled and skill:
        import psycopg2
        c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                             user=cfg.og_user, password=cfg.og_password)
        with c.cursor() as cur:
            cur.execute("SELECT layer, status, count(*) FROM %s.patterns WHERE skill=%%s GROUP BY layer, status"
                        % cfg.og_schema, (skill,))
            print("openGauss %s 规则(去重后):" % skill, cur.fetchall())
        c.close()
    print("\nACCEPTANCE: 快通道>0 且 FP 洪水被夹(verdict 多为 false_positive)且 规则条数<<告警数 且 悬空=0 = 通过")
finally:
    graph.close()
