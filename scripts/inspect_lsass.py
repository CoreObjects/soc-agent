"""只读:扒 LSASS 凭据转储(T1003.001)未研判告警的数据实形,给 signature.py 定先证伪特征。

聚合 = 按(源进程, granted_access, 是否安全代理, call_trace 含转储库)分桶计数 → 看 FP 洪水由啥构成、
先证伪该键在哪几个字段;再看 granted_access 含 0x10(PROCESS_VM_READ,读内存才与凭据窃取相关)的分布。
★security_agent / 转储库指纹用 recipe 同一套判定(将来 signature 也共享,不漂)。纯 run_cypher 只读。
"""
import os
import re
import sys
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
from soc_agent.recipe_lib import security_agent

_DUMP_LIB = re.compile(r"dbghelp|dbgcore|comsvcs|UNKNOWN|unbacked", re.I)
_VM_READ = 0x10


def _base(img):
    return (img or "?").replace("\\", "/").split("/")[-1].lower()


def _has_vm_read(granted):
    try:
        return bool(int(str(granted), 16) & _VM_READ)
    except (ValueError, TypeError):
        return None                                  # 非 16 进制 → 未知


cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
try:
    total = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1003.001' IN coalesce(a.technique_ids,[]) "
        "RETURN count(a) AS n")[0]["n"]
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1003.001' IN coalesce(a.technique_ids,[]) "
        "MATCH (a)<-[:TRIGGERED]-(e:Event)-[:BY]->(src:Process) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(tgt:Process) "
        "RETURN a.alert_uid AS uid, src.image AS src_image, "
        "e.granted_access AS granted, e.call_trace AS call_trace, tgt.image AS target")
    print("未研判 T1003.001 总数: %d;能锚定触发事件(EID10 BY 源进程)的: %d;锚不到(将来=伪签名): %d\n"
          % (total, len(rows), total - len(rows)))

    buckets = Counter()
    for r in rows:
        agent = security_agent(r.get("src_image"))
        dumplib = bool(_DUMP_LIB.search(r.get("call_trace") or ""))
        buckets[(_base(r.get("src_image")), r.get("granted") or "?",
                 "代理" if agent else "-", "转储库" if dumplib else "-")] += 1
    print("按(源进程, granted, 安全代理?, call_trace转储库?)分桶(前 25)——先证伪应能吃掉带『代理』且不带『转储库』的那些:")
    print("  %6s  %-26s %-10s %-6s %s" % ("数量", "源进程", "granted", "代理?", "转储库?"))
    for (src, granted, agent, dumplib), n in buckets.most_common(25):
        print("  %6d  %-26s %-10s %-6s %s" % (n, src[:26], granted, agent, dumplib))

    vm = Counter(_has_vm_read(r.get("granted")) for r in rows)
    print("\ngranted_access 含 0x10(PROCESS_VM_READ)分布(不含 0x10 基本是查询、偏良性):")
    for k in (True, False, None):
        if k in vm:
            lbl = {True: "含0x10(读内存,相关)", False: "不含0x10(仅查询,偏良性)", None: "非16进制/未知"}[k]
            print("  %6d  %s" % (vm[k], lbl))

    # 交叉:安全代理 × 是否转储库 —— 直接决定先证伪层能覆盖多少
    ax = Counter((("代理" if security_agent(r.get("src_image")) else "非代理"),
                  ("含转储库" if _DUMP_LIB.search(r.get("call_trace") or "") else "无转储库")) for r in rows)
    print("\n安全代理 × call_trace转储库 交叉(『代理+无转储库』= 头号 FP,先证伪主战场):")
    for k, n in ax.most_common():
        print("  %6d  源=%s, %s" % (n, k[0], k[1]))

    print("\n原始样本(前 5,看字段长啥样):")
    for r in rows[:5]:
        print("  uid=%s  src=%s  granted=%s  target=%s\n    call_trace=%s"
              % (r["uid"][:12], r.get("src_image"), r.get("granted"), r.get("target"),
                 (r.get("call_trace") or "")[:110]))
finally:
    g.close()
