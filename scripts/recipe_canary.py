"""★recipe 硬编码字面量哨兵(只读)。

为什么需要:**recipe 是静默失败的**。Cypher 谓词匹配不上 → 返回 0 行 → `findings=[]` →
告警落深度 LLM 路径 → 唯一症状是成本慢慢变高。没有异常、没有日志、没人知道取证瞎了。

做法:**不硬抄字面量**(抄了必然漂移),而是从 `skills/**/recipe.py` 里扫出所有
  · `event_code:'XXXX'`(4 个 recipe 把 Windows 事件码当图谓词用)
  · `.source='XXX'` / `source:'XXX'`(如 web_exploit 的 `al.source='waf'`)
再逐个到图里数一数。任何一条数出 0,就是"这个 recipe 现在什么都取不到"。
新加的硬编码会自动被纳入守护 —— 这正是接新数据源时最容易悄悄失效的东西。

用法: cd ~/soc-agent && .venv/bin/python scripts/recipe_canary.py
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from soc_agent.config import Config          # noqa: E402
from soc_agent.graph.client import Neo4jGraph  # noqa: E402

# ★两种写法都要认:
#   · 映射字面量 `{event_code:'4769'}`
#   · **比较式** `WHERE e.event_code='4769'`
# WP10 把谓词从前者改成后者(为了 OR 上中立字段),只认前者的话,
# **WP10 亲手把自己碰过的那四个字面量全从守护名单里踢了出去** —— 实测只剩 1 条。
# 一个"新加的自动纳入守护"的哨兵,反而在最需要它的那次改动上失守,那就是白建。
_EVENT_CODE = re.compile(r"event_code\s*(?::|=|\s==\s)\s*'([^']+)'")
_ALERT_SRC = re.compile(r"\bal(?:ert)?\.source\s*(?::|=)\s*'([^']+)'")


def _strip_comments(text: str) -> str:
    """去掉 `#` 注释行再扫。

    ★不去掉的话,**注释里提到的字面量会被当成真查询**。WP10 放宽 `al.source='waf'` 时,
      我在旁边写了段解释、原样引了那条谓词 —— canary 立刻把它数成两处。
      这次凑巧那个值确实还在用、没出假警;但注释里提一个**查询中已不存在**的字面量,
      就会让 canary 去守一个没人用的东西,然后报"零行"假警。
    """
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def scan_literals():
    """→ {('event_code'|'alert_source', 值): [recipe 名, …]}(按出现顺序去重)。"""
    found = defaultdict(list)
    for p in sorted((ROOT / "skills").rglob("recipe.py")):
        text = _strip_comments(p.read_text(encoding="utf-8"))
        name = f"{p.parent.parent.name}/{p.parent.name}"
        for m in _EVENT_CODE.finditer(text):
            found[("event_code", m.group(1))].append(name)
        for m in _ALERT_SRC.finditer(text):
            found[("alert_source", m.group(1))].append(name)
    return found


QUERIES = {
    "event_code": ("MATCH (e:Event {event_code:$v}) RETURN count(e) AS n", "Event"),
    "alert_source": ("MATCH (a:Alert {source:$v}) RETURN count(a) AS n", "Alert"),
}

LOW_WATER = 100     # 低于此数 = 该 recipe 几乎没被真实数据验证过(警告,不失败)


def main():
    cfg = Config.from_env(dotenv_path=str(ROOT / ".env"))
    lits = scan_literals()
    if not lits:
        print("!! 一条硬编码字面量都没扫到 —— 正则或目录结构变了,先修哨兵本身")
        return 2

    graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    dead, thin = [], []
    try:
        total_ev = graph.run_cypher("MATCH (e:Event) RETURN count(e) AS n")[0]["n"]
        total_al = graph.run_cypher("MATCH (a:Alert) RETURN count(a) AS n")[0]["n"]
        print(f"图规模:Event={total_ev}  Alert={total_al}   (URI={cfg.neo4j_uri})")
        print(f"\n{'类型':13} {'字面量':12} {'图中条数':>10}  使用它的 recipe")
        print("-" * 78)
        for (kind, val), users in sorted(lits.items()):
            q, _ = QUERIES[kind]
            n = graph.run_cypher(q, v=val)[0]["n"]
            # ★"零行"是硬失败;但"只有个位数"同样危险 —— 实测 waf_match 在 88.6 万事件的图里只有 4 条,
            #   等于该 recipe 几乎没被真实数据验证过,且从 4 掉到 4(陈旧)用 >0 阈值看不出来。
            if n == 0:
                dead.append((kind, val, users))
                flag = "  ⚠ 零行!"
            elif n < LOW_WATER:
                thin.append((kind, val, users, n))
                flag = f"  ⚠ 低水位(<{LOW_WATER})"
            else:
                flag = ""
            print(f"{kind:13} {val:12} {n:>10}  {', '.join(sorted(set(users)))}{flag}")
    finally:
        graph.close()

    print()
    if thin:
        print(f"⚠ {len(thin)} 条字面量数据极少(<{LOW_WATER}),对应 recipe 基本未被真实数据检验:")
        for kind, val, users, n in thin:
            print(f"   · {kind}='{val}' 仅 {n} 条  ← {', '.join(sorted(set(users)))}")
        print("   含义:该源要么刚接、要么已停;'从 4 条掉到 4 条陈旧'用 >0 阈值发现不了。")
    if dead:
        print(f"❌ {len(dead)} 条字面量在图里取不到任何数据 —— 对应 recipe 现在是**静默瞎的**:")
        for kind, val, users in dead:
            print(f"   · {kind}='{val}'  ← {', '.join(sorted(set(users)))}")
        print("   处置:要么该数据源没接上,要么该 recipe 需要 pivot 化/放宽谓词(见 WP7/WP10)。")
        return 1
    print("✅ 所有硬编码字面量都能在图里取到数据")
    return 0


if __name__ == "__main__":
    sys.exit(main())
