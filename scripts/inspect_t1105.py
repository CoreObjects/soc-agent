"""只读:扒 Ingress Tool Transfer(T1105)未研判告警的数据实形,给 signature.py 定【通用】特征。

★红线:看清哪些【通用本体字段】能把 FP 洪水分开(落文件的进程 image=原始值/落地目录类/文件后缀/是否落地即执行),
具体"哪个进程掉文件是良性"留给慢通道学,不写厂商/工具名单。
输出:① 全量按【落文件进程】计数(谁在掉)② 抽样按(进程, 落地目录类, 后缀, 落地即执行?)分桶 ③ 命中已知供给/自检
噪声(ansible/策略探针)占比(这些是慢通道要判的良性,不做签名 key)④ 原始样本。
"""
import os
import sys
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
from soc_agent.recipe_lib import decode_chain, provisioning_noise

_TRANSIENT = ("/temp/", "/tmp/", "/appdata/", "/public/", "/programdata/", "windows/temp", "/downloads/")


def base(img):
    return (img or "?").replace("\\", "/").split("/")[-1].lower()


def drop_class(path):
    p = (path or "").lower().replace("\\", "/")
    if not p:
        return "(no-file)"
    if any(s in p for s in _TRANSIENT):
        return "user_transient"                       # 恶意常用可写目录(Temp/AppData/Public/ProgramData…)
    if "/program files" in p or p.startswith("c:/windows/") or "/windows/system32" in p:
        return "program_or_system"
    return "other"


def file_ext(path):
    b = (path or "").replace("\\", "/").split("/")[-1]
    return ("." + b.rsplit(".", 1)[1].lower()) if "." in b else "(none)"


cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
try:
    total = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1105' IN coalesce(a.technique_ids,[]) "
        "RETURN count(a) AS n")[0]["n"]
    anchored = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1105' IN coalesce(a.technique_ids,[]) "
        "MATCH (a)<-[:TRIGGERED]-(e:Event)-[:BY]->(w:Process) RETURN count(DISTINCT a) AS n")[0]["n"]
    print("未研判 T1105 总数: %d;能锚定(有 BY 源进程)的: %d;锚不到: %d\n" % (total, anchored, total - anchored))

    print("① 全量按【落文件的进程 image】计数(谁在掉文件)—— 前 25:")
    for r in g.run_cypher(
            "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1105' IN coalesce(a.technique_ids,[]) "
            "MATCH (a)<-[:TRIGGERED]-(e:Event)-[:BY]->(w:Process) "
            "RETURN w.image AS writer, count(*) AS n ORDER BY n DESC LIMIT 25"):
        print("  %8d  %s" % (r["n"], r["writer"]))

    lim = 2500
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND 'T1105' IN coalesce(a.technique_ids,[]) "
        "MATCH (a)<-[:TRIGGERED]-(e:Event)-[:BY]->(w:Process) "
        "OPTIONAL MATCH (e)-[:WROTE]->(f:File) "
        "OPTIONAL MATCH (par:Process)-[:SPAWNED]->(w) "
        "OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process) "
        "WITH a, w, par, collect(DISTINCT f.path) AS files, collect(DISTINCT c.image) AS spawned "
        "RETURN w.image AS writer, w.command_line AS cmdline, par.image AS parent, files, spawned "
        "LIMIT $lim", lim=lim)

    buckets = Counter()
    noise_hits = 0
    for r in rows:
        files = r.get("files") or []
        f0 = files[0] if files else None
        executed = bool(set(r.get("spawned") or []) & set(files))     # 落地文件被 SPAWNED 执行(结构信号)
        buckets[(base(r.get("writer")), drop_class(f0), file_ext(f0), "执行" if executed else "-")] += 1
        blob = "\n".join(filter(None, [r.get("cmdline")] + files + (decode_chain(r.get("cmdline")) or [])))
        if provisioning_noise(blob):
            noise_hits += 1

    print("\n② 抽样 %d 条,按(落文件进程, 落地目录类, 后缀, 落地即执行?)分桶(前 25):" % len(rows))
    print("  %6s  %-24s %-16s %-8s %s" % ("数量", "进程", "落地目录", "后缀", "执行?"))
    for (w, loc, ext, ex), n in buckets.most_common(25):
        print("  %6d  %-24s %-16s %-8s %s" % (n, w[:24], loc, ext, ex))

    print("\n③ 命中已知供给/自检噪声(ansible/策略探针 __PSScriptPolicyTest_)的占比(这些是慢通道判的良性,★不做签名 key):")
    print("   %d / %d  (%.1f%%)" % (noise_hits, len(rows), 100.0 * noise_hits / len(rows) if rows else 0))

    print("\n④ 原始样本(前 6):")
    for r in rows[:6]:
        print("  writer=%s  parent=%s\n    files=%s\n    cmdline=%s"
              % (r.get("writer"), r.get("parent"), (r.get("files") or [])[:3],
                 (r.get("cmdline") or "")[:120]))
finally:
    g.close()
