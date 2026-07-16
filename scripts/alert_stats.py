"""只读:统计图里【未研判】告警(无 CONCLUDED 出边)的分布 —— 给"签名铺开"排优先级。

按 technique 出数量,并标注:该 technique ① 有没有对应 skill(recipe+方法论)② 有没有 signature.py(快通道签名)。
→ 一眼分辨:量大 + 有skill无签名 = 加个 signature.py 就能收编的易 win;量大 + 无skill = 整套 skill 从头写。
纯 run_cypher 只读,不写图。用法(server2):.venv/bin/python scripts/alert_stats.py
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
from soc_agent.skills_runtime import SkillRegistry

cfg = Config.from_env(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
reg = SkillRegistry(cfg.skills_dir)

# technique → (skill 名, 有无 signature)
tech2skill = {}
for s in reg.all():
    for t in (s.technique_ids or []):
        tech2skill[t] = (s.name, s.signature is not None)
covered = {t for t, (_n, has_sig) in tech2skill.items() if has_sig}   # 已有签名的 technique(=daemon 范围闸默认放行的)

graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
try:
    total = graph.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() RETURN count(a) AS n")[0]["n"]
    by_tech = graph.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
        "UNWIND coalesce(a.technique_ids, ['(none)']) AS t "
        "RETURN t AS technique, count(DISTINCT a) AS n ORDER BY n DESC LIMIT 40")
    by_rule = graph.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
        "RETURN coalesce(a.rule_description,'(none)') AS rule, count(a) AS n ORDER BY n DESC LIMIT 20")

    print("=== 未研判告警总数: %d ===\n" % total)

    in_scope = sum(r["n"] for r in by_tech if r["technique"] in covered)
    print("范围闸默认放行(有签名)覆盖的未研判量: %d / %d  (%.1f%%)  —— 其余锁在闸外,等补签名\n"
          % (in_scope, total, 100.0 * in_scope / total if total else 0))

    print("按 technique(前 40):")
    print("  %-14s %8s  %-22s %s" % ("technique", "未研判", "对应 skill", "签名?"))
    print("  " + "-" * 60)
    for r in by_tech:
        t = r["technique"]
        skill, has_sig = tech2skill.get(t, (None, False))
        skill_s = skill or "—(无 skill,整套要写)"
        sig_s = "✅有" if has_sig else ("待写 signature.py" if skill else "—")
        print("  %-14s %8d  %-22s %s" % (t, r["n"], skill_s, sig_s))

    print("\n按 rule_description(前 20,给人看是啥告警):")
    for r in by_rule:
        print("  %8d  %s" % (r["n"], r["rule"]))
finally:
    graph.close()
