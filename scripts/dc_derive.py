"""能不能从遥测推导出"哪台主机是 DC"?★只读 —— 不写图、不调 LLM。

起因:`dcsync.actor_is_dc` 零点火,4180 条 dcsync 卡在 suspicious(还有约 3.4 万条在积压里)。
第 6 段已经定位到断点:`Domain.netbios`/`Domain.dc`/`Host.is_dc` **全是空的**,
从来没有任何东西往里写过 —— 而 `graph_model` 把这三个字段都声明了。

那"哪台是 DC"能不能不靠人工名单、从已有数据推出来?图模型自己给了线索
(graph_model.json:118):`4769(TGS) 的 secondary: ON_HOST→DC`。
**签发 Kerberos 票据的主机就是 DC** —— 行为推导、厂商中立、不硬编码实例。

但推导成立有前提,这个脚本就是去量它们(前两轮我猜错两次,这次全部实测):
  [1] KDC 事件(4768/4769)在不在图里、挂没挂 ON_HOST
  [2] 挂到了哪几台主机 —— 干净的话应该正好是那几台 DC,而不是满图都是
  [3] 交叉验证:4662(目录复制)落在哪些主机上 —— 它同样只记在 DC 上,两边应该重合
  [4] ★决定性一问:推出来的 DC 集合,和卡住的那些 actor(kingslanding$ 等)对不对得上
  [5] 顺带:Host.role / Host.is_dc 现状(policy_from_graph 的 NEVER-TOUCH 也查它们)

★ [4] 的短名归一**必须复用 dcsync recipe 里那份 `_short`**,不能另写。
  两份归一逻辑一漂,这里报"对得上"而线上仍然点不着火 —— 又是一个不报错的假绿。
"""
import argparse
import importlib.util
import os
import pathlib
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config                                  # noqa: E402
from soc_agent.graph.client import Neo4jGraph                        # noqa: E402

# ★直接从 recipe 文件里取 `_short`,与线上同一份实现
_RSPEC = importlib.util.spec_from_file_location(
    "dcsync_recipe", pathlib.Path(_ROOT) / "skills" / "identity" / "dcsync" / "recipe.py")
_RECIPE = importlib.util.module_from_spec(_RSPEC)
_RSPEC.loader.exec_module(_RECIPE)
_short = _RECIPE._short

_KDC_WHERE = "(e.event_code IN ['4768','4769','4771'] OR e.activity='auth.ticket_request')"
_DIR_WHERE = "(e.event_code='4662' OR e.activity='directory.access')"

_KDC_COVER = f"""
MATCH (e:Event) WHERE {_KDC_WHERE}
OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host)
RETURN coalesce(e.event_code,'(无)') AS code, coalesce(e.activity,'(无)') AS act,
       count(*) AS n, sum(CASE WHEN h IS NULL THEN 1 ELSE 0 END) AS no_host
ORDER BY n DESC
"""

_KDC_HOSTS = f"""
MATCH (e:Event)-[:ON_HOST]->(h:Host) WHERE {_KDC_WHERE}
RETURN h.hostname AS hostname, count(*) AS n,
       collect(DISTINCT e.event_code) AS codes ORDER BY n DESC
"""

_DIR_HOSTS = f"""
MATCH (e:Event)-[:ON_HOST]->(h:Host) WHERE {_DIR_WHERE}
RETURN h.hostname AS hostname, count(*) AS n ORDER BY n DESC
"""

_STUCK_ACTORS = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
WHERE coalesce(c.path, v.path) = 'B'
MATCH (e:Event)-[:TRIGGERED]->(a)
MATCH (e)-[:BY]->(actor:Account)
RETURN actor.sam AS sam, actor.domain AS domain, count(*) AS n ORDER BY n DESC LIMIT 20
"""

_HOST_ROLES = """
MATCH (h:Host)
RETURN coalesce(h.role,'(空)') AS role, coalesce(toString(h.is_dc),'(空)') AS is_dc,
       count(*) AS n, collect(h.hostname)[0..6] AS sample ORDER BY n DESC
"""

_ALL_HOSTS = "MATCH (h:Host) RETURN count(*) AS n"


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def main(argv=None):
    ap = argparse.ArgumentParser(description="能不能从遥测推导 Host.is_dc(只读)")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=args.dotenv)
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        print("########## [1] KDC 事件在不在、挂没挂 ON_HOST ##########")
        rows = g.run_cypher(_KDC_COVER)
        tot = sum(r["n"] for r in rows)
        nohost = sum(r["no_host"] for r in rows)
        if not rows:
            print("  ⚠ 图里一条 4768/4769/auth.ticket_request 都没有 —— 这条推导路走不通,到此为止。")
            return 1
        for r in rows:
            print(f"    code={str(r['code']):8} activity={str(r['act']):22} "
                  f"{r['n']:>8} 条,其中无 ON_HOST {r['no_host']}")
        print(f"  合计 {tot} 条,无 ON_HOST {nohost}  ({_pct(nohost, tot):.1f}%)")
        if nohost == tot:
            print("  ⚠ **全都没挂 ON_HOST** ⇒ 推不出主机,这条路走不通。")
            return 1
        print()

        print("########## [2] KDC 事件落在哪几台主机 ##########")
        print("  ★干净的话应该只有那几台 DC。要是满图主机都在,说明 ON_HOST 挂的不是 KDC 而是发起方。")
        kdc_hosts = g.run_cypher(_KDC_HOSTS)
        n_all = (g.run_cypher(_ALL_HOSTS) or [{}])[0].get("n", 0)
        for r in kdc_hosts:
            print(f"    {r['n']:>8}  {str(r['hostname']):44} codes={r['codes']}")
        print(f"  → {len(kdc_hosts)} 台 / 图里共 {n_all} 台主机")
        if n_all and len(kdc_hosts) > max(3, n_all * 0.5):
            print("  ⚠ 占比过半 ⇒ 不像'只有 DC 记 KDC 事件',这条判据可能不成立,别据此写 is_dc。")
        print()

        print("########## [3] 交叉验证:4662(目录复制)落在哪几台 ##########")
        print("  ★它同样只记在 DC 上。两组主机应当高度重合;不重合说明其中一组的 ON_HOST 语义不是我以为的那样。")
        dir_hosts = g.run_cypher(_DIR_HOSTS)
        for r in dir_hosts:
            print(f"    {r['n']:>8}  {r['hostname']}")
        a = {r["hostname"] for r in kdc_hosts}
        b = {r["hostname"] for r in dir_hosts}
        print(f"  两组交集 {len(a & b)} 台;只在 KDC 组 {sorted(a - b)};只在 4662 组 {sorted(b - a)}")
        print()

        print("########## [4] ★决定性:推出的 DC 能不能和卡住的 actor 对上 ##########")
        print("  短名归一复用 dcsync recipe 的 `_short`(同一份实现,不另写)。")
        derived = {}
        for r in kdc_hosts:
            s = _short(r["hostname"])
            if s:
                derived.setdefault(s, []).append(r["hostname"])
        print(f"  推出的 DC 短名集合:{sorted(derived)}")
        stuck = g.run_cypher(_STUCK_ACTORS)
        hit = miss = 0
        for r in stuck:
            s = _short(r["sam"])
            ok = s in derived
            hit, miss = (hit + r["n"], miss) if ok else (hit, miss + r["n"])
            mark = "✅ 对上" if ok else "❌ 对不上"
            print(f"    {r['n']:>7}  sam={str(r['sam']):20} 短名={str(s):16} "
                  f"domain={str(r['domain']):16} {mark}")
        tot_stuck = hit + miss
        print(f"  ⇒ **{hit}/{tot_stuck}({_pct(hit, tot_stuck):.1f}%)的卡死告警,其 actor 就是推出来的 DC**")
        if tot_stuck and _pct(hit, tot_stuck) >= 95:
            print("  ⇒ 推导成立:把 is_dc 写进图,dcsync 这批就能拿到'头号良性'finding、不再全判 suspicious。")
        elif tot_stuck:
            print("  ⇒ 对不上的那部分要单独看:要么它们真不是 DC(那 suspicious 判得对),")
            print("     要么主机名形态不一致(FQDN vs 短名 vs NetBIOS)。")
        print()

        print("########## [5] 现状:Host.role / Host.is_dc ##########")
        print("  ★policy_from_graph 的 NEVER-TOUCH 自动化查的就是这两个字段。")
        for r in g.run_cypher(_HOST_ROLES):
            print(f"    role={str(r['role']):24} is_dc={str(r['is_dc']):8} {r['n']:>5} 台  "
                  f"例:{r['sample']}")
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
