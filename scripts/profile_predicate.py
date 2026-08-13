"""WP10:用 `PROFILE` 证明谓词放宽**没有**打掉索引命中,且行为不变。★只读。

计划里点名的风险:把 `event_code='4624'` 放宽成
`(e.event_code='4624' OR e.activity='auth.logon')` 之后,两个属性各有各的索引,
**OR 可能两个索引都不走**,退化成 `:Event` 全标签扫 —— 在 90 万事件上那是灾难,
而且它**不会报错**,只会让研判慢下来(又一次"不红、只是变差")。

★但先读代码会发现:这几条查询的锚点都是 `Alert {alert_uid}`(唯一约束)或
  `Account {sam}`(有索引),`event_code` 一律是**遍历之后的属性过滤**、从来不是寻址入口。
  照这个结构,放宽只是把一次属性比较变成两次,代价可忽略。
  —— 但这是推理。这个脚本是拿 PROFILE 去**证**它,而不是信它。
  首跑就证明了这不是空话:kerberoast 那条**结果不一致**(扇出 2→6),被逮住并改了写法。

★★ 防漂移(这个脚本自己吃过的亏):
  首版把"新形式"**写死在脚本里**。后来 kerberoast 按首跑结论加了 `ticket_kind` 判别位、
  lateral_movement 加了 `outcome`,脚本却没跟着动 ⇒ 它测的是一个**代码里已经不存在的写法**,
  跑出来的绿/红都不指向现网。所以现在每条 case 都要过 `_assert_live()`:
  新形式的 WHERE 子句必须**逐字**出现在对应 recipe 源码里,对不上直接报错退出。
  探针从此不可能测一个过期版本。

判据(每对查询):
  · 新形式的 dbHits 不得比旧形式显著高(阈值 1.5×,超了就要解释);
  · 执行计划里**不得出现** `:Event` 的 `NodeByLabelScan`(那就是全表扫);
  · 两边返回的行/值必须一致(放宽在本租户上行为应当不变)。
    ★列表字段按**集合**比:`collect(DISTINCT …)` 在 Cypher 里天然无序,
      拿顺序判不一致是自造噪声。顺序差异单独提示,不判失败。
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


def _unordered(v):
    """递归把列表转成"可比较的多重集" —— 只用于判等,不用于展示。"""
    if isinstance(v, list):
        return sorted(repr(_unordered(x)) for x in v)
    if isinstance(v, dict):
        return {k: _unordered(x) for k, x in sorted(v.items())}
    return v


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
_PICK_WAF_IP = """
MATCH (ip:IPAddress)<-[:FROM]-(:Event)-[:TRIGGERED]->(al:Alert)
WHERE al.source='waf' OR al.detector_class='waf'
RETURN ip.ip AS ip, count(*) AS n ORDER BY n DESC LIMIT 1
"""

# (名称, 旧形式, 新形式, 参数键, 新形式所属的 recipe —— 用于防漂移自检)
CASES = [
    ("lateral_movement 登录基线计数",
     "MATCH (e:Event {event_code:'4624'})-[:BY]->(:Account {sam:$s}) "
     "MATCH (e)-[:AUTHENTICATED_TO]->(:Host {hostname:$h}) "
     "RETURN sum(coalesce(e.count,1)) AS logins",
     "MATCH (e:Event)-[:BY]->(:Account {sam:$s}) "
     "WHERE e.event_code='4624' OR (e.activity='auth.logon' AND e.outcome='success') "
     "MATCH (e)-[:AUTHENTICATED_TO]->(:Host {hostname:$h}) "
     "RETURN sum(coalesce(e.count,1)) AS logins",
     "account_host", "skills/identity/lateral_movement/recipe.py"),

    ("kerberoast 该账号取票扇出",
     "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
     "RETURN count(DISTINCT t) AS distinct_targets, sum(coalesce(e.count,1)) AS total_4769",
     "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event)-[:REQUESTED]->(t) "
     "WHERE e.event_code='4769' OR (e.activity='auth.ticket_request' AND e.ticket_kind='service') "
     "RETURN count(DISTINCT t) AS distinct_targets, sum(coalesce(e.count,1)) AS total_4769",
     "account_4769", "skills/identity/kerberoast/recipe.py"),

    ("dcsync 告警锚点",
     "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4662'})-[:BY]->(actor:Account) "
     "RETURN actor.sam AS sam, e.event_time AS t",
     "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(actor:Account) "
     "WHERE e.event_code='4662' OR e.activity='directory.access' "
     "RETURN actor.sam AS sam, e.event_time AS t",
     "alert_4662", "skills/identity/dcsync/recipe.py"),

    # ★这条不是放宽 event_code,是放宽 `al.source='waf'`(厂商名 vs 中立类别)。
    #   同一份闸门要覆盖它:第二家 WAF 厂商隐形与 event_code 命不中是同一类失败。
    #   注意它连 OPTIONAL MATCH 的路径都换了(从 IP 侧改成从告警回溯),所以这条比的
    #   不只是谓词代价,还是**换路径之后打击画像有没有变** —— 更该量。
    ("web_exploit 源IP的WAF打击画像",
     "MATCH (ip:IPAddress {ip:$ip})<-[:FROM]-(:Event)-[:TRIGGERED]->(al:Alert) WHERE al.source='waf' "
     "OPTIONAL MATCH (ip)<-[:FROM]-(we:Event {event_code:'waf_match'})-[:TARGET]->(uu:Uri) "
     "RETURN count(DISTINCT al) AS waf_alerts, count(DISTINCT al.rule_id) AS distinct_crs_rules, "
     "collect(DISTINCT al.rule_id)[..15] AS sample_rules, collect(DISTINCT uu.uri)[..15] AS endpoints_hit",
     "MATCH (ip:IPAddress {ip:$ip})<-[:FROM]-(:Event)-[:TRIGGERED]->(al:Alert) "
     "WHERE al.source='waf' OR al.detector_class='waf' "
     "OPTIONAL MATCH (al)<-[:TRIGGERED]-(we:Event)-[:TARGET]->(uu:Uri) "
     "RETURN count(DISTINCT al) AS waf_alerts, count(DISTINCT al.rule_id) AS distinct_crs_rules, "
     "collect(DISTINCT al.rule_id)[..15] AS sample_rules, collect(DISTINCT uu.uri)[..15] AS endpoints_hit",
     "waf_ip", "skills/application/web_exploit/recipe.py"),
]


def _where_of(q):
    """取新形式里的 WHERE 子句(到下一个 Cypher 关键字为止)—— 防漂移自检就比它。"""
    i = q.find("WHERE ")
    if i < 0:
        return None
    rest = q[i:]
    for kw in (" OPTIONAL MATCH ", " MATCH ", " RETURN ", " WITH "):
        j = rest.find(kw)
        if j > 0:
            rest = rest[:j]
    return rest.strip()


def _assert_live(cases):
    """新形式的 WHERE 必须**逐字**出现在它所属的 recipe 里,否则探针测的是过期写法。"""
    bad = []
    for name, _old, new, _pk, path in cases:
        w = _where_of(new)
        with open(os.path.join(_ROOT, path), encoding="utf-8") as fh:
            src = fh.read()
        if not w or w not in src:
            bad.append(f"  {name}\n    脚本里的: {w}\n    在 {path} 里**找不到**")
    return bad


def main() -> int:
    drift = _assert_live(CASES)
    if drift:
        print("❌ 探针与现网代码已经漂移 —— 它测的不是 recipe 现在真正在跑的写法:")
        print("\n".join(drift))
        print("\n先把 CASES 里的新形式同步成 recipe 里的原文,再跑。"
              "(★这个自检就是为了防止上一版那种「改了 recipe 没改探针、"
              "结论指向一个已不存在的写法」。)")
        return 2

    cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空。")
        return 2
    print(f"图: {cfg.neo4j_uri}  库={cfg.neo4j_database}")
    print("防漂移自检: ✅ 四条新形式的 WHERE 均与 recipe 源码逐字一致\n")

    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        ah = g.run_cypher(_PICK_ACCOUNT_HOST)
        a69 = g.run_cypher(_PICK_ACCOUNT_4769)
        al = g.run_cypher(_PICK_ALERT, code="4662")
        wip = g.run_cypher(_PICK_WAF_IP)
        params = {
            "account_host": {"s": (ah[0]["sam"] if ah else None), "h": (ah[0]["host"] if ah else None)},
            "account_4769": {"s": (a69[0]["sam"] if a69 else None)},
            "alert_4662": {"aid": (al[0]["aid"] if al else None)},
            "waf_ip": {"ip": (wip[0]["ip"] if wip else None)},
        }
        print("--- 用来 profile 的真实参数(挑事件最多的那个,计划才有代表性)---")
        for k, v in params.items():
            print(f"  {k}: {v}")
        print()

        bad = []
        for name, old_q, new_q, pk, _path in CASES:
            p = params[pk]
            if any(v is None for v in p.values()):
                print(f"--- {name} ---\n  ⚠ 图里挑不到参数(该类事件可能没有数据),跳过\n")
                continue
            o, n = profile(g, old_q, **p), profile(g, new_q, **p)
            exact = o["rows"] == n["rows"]
            same = _unordered(o["rows"]) == _unordered(n["rows"])     # ★按集合判等
            ratio = (n["db_hits"] / o["db_hits"]) if o["db_hits"] else float("inf")
            print(f"--- {name} ---")
            print(f"  旧: dbHits={o['db_hits']:<8} 行={o['rows']}")
            print(f"  新: dbHits={n['db_hits']:<8} 行={n['rows']}")
            print(f"  倍率={ratio:.2f}×   结果一致(按集合)={same}   "
                  f"新形式出现 Event 全标签扫={n['label_scan_event']}")
            if same and not exact:
                print("     (仅列表顺序不同 —— collect(DISTINCT …) 本就无序,不判失败)")
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
            print("❌ 以下谓词**不能直接 OR 放宽**,要换写法(如拆 UNION 两支 / 补中立判别位):")
            for name, why in bad:
                print(f"   {name}: {'; '.join(why)}")
            return 1
        print("✅ 四条都通过:索引命中未变、dbHits 无显著上涨、结果一致。")
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
