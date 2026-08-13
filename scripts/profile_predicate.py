"""WP10 前置:用 `PROFILE` 证明谓词放宽**没有**打掉索引命中。★只读。

计划里点名的风险:把 `event_code='4624'` 放宽成
`(e.event_code='4624' OR e.activity='auth.logon')` 之后,两个属性各有各的索引,
**OR 可能两个索引都不走**,退化成 `:Event` 全标签扫 —— 在 90 万事件上那是灾难,
而且它**不会报错**,只会让研判慢下来(又一次"不红、只是变差")。

★但先读代码会发现:这几条查询的锚点都是 `Alert {alert_uid}`(唯一约束)或
  `Account {sam}`(有索引),`event_code` 一律是**遍历之后的属性过滤**、从来不是寻址入口。
  照这个结构,放宽只是把一次属性比较变成两次,代价可忽略。
  —— 但这是推理。这个脚本是拿 PROFILE 去**证**它,而不是信它。

判据(每对查询):
  · 新形式的 dbHits 不得比旧形式显著高(阈值 1.5×,超了就要解释);
  · 执行计划里**不得出现** `:Event` 的 `NodeByLabelScan`(那就是全表扫);
  · 两边返回的行/值必须一致(放宽在本租户上行为应当不变)。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config                 # noqa: E402
from soc_agent.graph.client import Neo4jGraph       # noqa: E402


def _walk(plan, out):
    """把 PROFILE 计划树摊平成 [(算子, dbHits, rows)]。"""
    if plan is None:
        return out
    out.append((plan.get("operatorType", "?"), int(plan.get("dbHits") or 0),
                int(plan.get("rows") or 0)))
    for c in plan.get("children") or []:
        _walk(c, out)
    return out


def profile(graph, cypher, **params):
    with graph._driver.session() as s:              # 诊断脚本,直接用驱动拿 summary
        res = s.run("PROFILE " + cypher, **params)
        rows = [r.data() for r in res]
        prof = res.consume().profile
    ops = _walk(prof, [])
    return {"rows": rows, "ops": ops,
            "db_hits": sum(h for _, h, _ in ops),
            "label_scan_event": any(o == "NodeByLabelScan" and h > 0 for o, h, _ in ops)}


# 从图里挑**有代表性**的真实参数 —— 拿空参数 profile 出来的计划毫无意义
_PICK_ACCOUNT_HOST = """
MATCH (e:Event {event_code:'4624'})-[:BY]->(a:Account)
MATCH (e)-[:AUTHENTICATED_TO]->(h:Host)
RETURN a.sam AS sam, h.hostname AS host, count(*) AS n ORDER BY n DESC LIMIT 1
"""
_PICK_ACCOUNT_4769 = """
MATCH (e:Event {event_code:'4769'})-[:BY]->(a:Account)
RETURN a.sam AS sam, count(*) AS n ORDER BY n DESC LIMIT 1
"""
_PICK_ALERT = """
MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:$code})
RETURN a.alert_uid AS aid LIMIT 1
"""

CASES = [
    ("lateral_movement 登录基线计数",
     "MATCH (e:Event {event_code:'4624'})-[:BY]->(:Account {sam:$s}) "
     "MATCH (e)-[:AUTHENTICATED_TO]->(:Host {hostname:$h}) "
     "RETURN sum(coalesce(e.count,1)) AS logins",
     "MATCH (e:Event)-[:BY]->(:Account {sam:$s}) "
     "WHERE e.event_code='4624' OR e.activity='auth.logon' "
     "MATCH (e)-[:AUTHENTICATED_TO]->(:Host {hostname:$h}) "
     "RETURN sum(coalesce(e.count,1)) AS logins", "account_host"),
    ("kerberoast 该账号取票总量",
     "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
     "RETURN count(DISTINCT t) AS distinct_targets, sum(coalesce(e.count,1)) AS total",
     "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event)-[:REQUESTED]->(t) "
     "WHERE e.event_code='4769' OR e.activity='auth.ticket_request' "
     "RETURN count(DISTINCT t) AS distinct_targets, sum(coalesce(e.count,1)) AS total", "account_4769"),
    ("dcsync 告警锚点",
     "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4662'})-[:BY]->(actor:Account) "
     "RETURN actor.sam AS sam, e.event_time AS t",
     "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(actor:Account) "
     "WHERE e.event_code='4662' OR e.activity='directory.access' "
     "RETURN actor.sam AS sam, e.event_time AS t", "alert_4662"),
]


def main() -> int:
    cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空。")
        return 2
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        ah = g.run_cypher(_PICK_ACCOUNT_HOST)
        a69 = g.run_cypher(_PICK_ACCOUNT_4769)
        al = g.run_cypher(_PICK_ALERT, code="4662")
        params = {
            "account_host": {"s": (ah[0]["sam"] if ah else None), "h": (ah[0]["host"] if ah else None)},
            "account_4769": {"s": (a69[0]["sam"] if a69 else None)},
            "alert_4662": {"aid": (al[0]["aid"] if al else None)},
        }
        print("--- 用来 profile 的真实参数(挑事件最多的那个,计划才有代表性)---")
        for k, v in params.items():
            print(f"  {k}: {v}")
        print()

        bad = []
        for name, old_q, new_q, pk in CASES:
            p = params[pk]
            if any(v is None for v in p.values()):
                print(f"--- {name} ---\n  ⚠ 图里挑不到参数(该类事件可能没有数据),跳过\n")
                continue
            o, n = profile(g, old_q, **p), profile(g, new_q, **p)
            same = o["rows"] == n["rows"]
            ratio = (n["db_hits"] / o["db_hits"]) if o["db_hits"] else float("inf")
            print(f"--- {name} ---")
            print(f"  旧: dbHits={o['db_hits']:<8} 行={o['rows']}")
            print(f"  新: dbHits={n['db_hits']:<8} 行={n['rows']}")
            print(f"  倍率={ratio:.2f}×   结果一致={same}   新形式出现 Event 全标签扫={n['label_scan_event']}")
            print(f"  新形式算子链: {' → '.join(op for op, _, _ in n['ops'][:8])}")
            why = []
            if not same:
                why.append("结果不一致")
            if n["label_scan_event"]:
                why.append("退化成全标签扫")
            if ratio > 1.5:
                why.append(f"dbHits 涨了 {ratio:.1f}×")
            if why:
                bad.append((name, why))
                print(f"  ❌ {'; '.join(why)}")
            else:
                print("  ✅ 放宽没有代价")
            print()

        if bad:
            print("❌ 以下谓词**不能直接 OR 放宽**,要换写法(如拆成 UNION 两支):")
            for name, why in bad:
                print(f"   {name}: {'; '.join(why)}")
            return 1
        print("✅ 三条都可以直接 OR 放宽:索引命中未变、dbHits 无显著上涨、结果一致。")
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
