"""深度通道到底学到了什么:sediment 的收敛率 + 它前面那两道免费闸门。★只读,不调 LLM、不写库。

起因是我先猜错了一次:以为 `exam.sediment` 每条 FALLTHROUGH 都要烧一次 27b 去蒸馏,
于是提议"把收敛检查提到 distill 之前"。实际上 `distill.py` 在调 LLM **之前**就有两道免费退出:

    第 51 行  verdict 不在 (TP, FP, benign) → return None        ← suspicious 一次都不烧
    第 59 行  没有非元 finding                → return None
    第 65 行  才轮到 llm.chat

所以真正会烧 LLM 的只有"TP/FP/benign 且有实证据"的那批。这个脚本先把这个分母量出来,
再在分母里量收敛率 —— 别再拿猜的数去做优化决策。

★量出来的收敛率是**前瞻**的,不是回溯的:比对的是**当前**经验库,而每条告警当初研判时
  库比现在小。所以它回答的是"以后能省多少",不是"过去白烧了多少"。

★第三段才是重点:深度通道 99% 以上的结论是 suspicious,而 suspicious **不沉淀**。
  也就是最贵的那条通道**什么都没学到**。missing_evidence 的频次表说明它到底缺什么。
"""
import argparse
import os
import sys
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config                                  # noqa: E402
from soc_agent.experience.matching import experience_fires           # noqa: E402
from soc_agent.forensics import Finding                              # noqa: E402
from soc_agent.graph.client import Neo4jGraph                        # noqa: E402

# distill 认得的终局 verdict(distill.py:51);其余(suspicious)连 LLM 都不会碰
_DISTILLABLE = ("true_positive", "false_positive", "benign")

_VERDICTS_B = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict)
WHERE coalesce(c.path, v.path) = 'B'
RETURN v.verdict AS verdict, count(*) AS n ORDER BY n DESC
"""

_UIDS_B = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict)
WHERE coalesce(c.path, v.path) = 'B' AND v.verdict IN $vs
RETURN a.alert_uid AS uid, v.verdict AS verdict
"""

_MISSING = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
UNWIND coalesce(c.missing_evidence, []) AS m
RETURN m AS missing, count(*) AS n ORDER BY n DESC LIMIT $lim
"""

_MISSING_NONE = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
RETURN count(*) AS total,
       sum(CASE WHEN size(coalesce(c.missing_evidence, [])) = 0 THEN 1 ELSE 0 END) AS empty
"""

# ★卡在 suspicious 的是哪些 skill —— 按 Finding.skill 归属
_SUSP_BY_SKILL = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
WHERE coalesce(c.path, v.path) = 'B'
OPTIONAL MATCH (a)-[:HAS_FINDING]->(f:Finding)
WITH a, head(collect(DISTINCT f.skill)) AS skill
RETURN coalesce(skill, '(无 finding)') AS skill, count(*) AS n ORDER BY n DESC
"""

# ★★决定性的一问:这些卡住的告警,recipe 到底给出了哪些 finding?
#   若"头号良性"那类白 finding **点火了**却仍judge suspicious ⇒ 数据齐、结论也齐,
#     是那句**无条件**的 blind_spots 在否决它(改声明即可);
#   若压根没点火 ⇒ 是图里缺建模(如 Domain.dc 为空,recipe 比不出"actor 是不是本域 DC")。
#   两种诊断指向完全不同的修法,不测就只能猜。
_SUSP_FINDINGS = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
WHERE coalesce(c.path, v.path) = 'B'
MATCH (a)-[:HAS_FINDING]->(f:Finding)
RETURN f.skill AS skill, f.finding_id AS fid, coalesce(f.polarity,'?') AS pol, count(*) AS n
ORDER BY skill, n DESC
"""


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def kind_of(verdict):
    """distill.py:53 —— 由 verdict 直接导出,**不需要蒸**。收敛检查要用它。"""
    return "threat" if verdict == "true_positive" else "benign_fp"


def load_cases(case_store, uids):
    """把 openGauss cases 里属于这批 uid 的行捞出来:{uid: (skill, verdict, [Finding])}。"""
    if not uids:
        return {}
    out = {}
    with case_store.conn.cursor() as cur:
        cur.execute(f"SELECT alert_uid, skill, verdict, findings FROM {case_store.t}")
        for uid, skill, verdict, fj in cur.fetchall():
            if uid in uids:
                import json
                fs = [Finding.from_dict(d) for d in (json.loads(fj) if fj else [])]
                out[uid] = (skill, verdict, fs)
    return out


_DOMAINS = "MATCH (d:Domain) RETURN d.netbios AS netbios, d.fqdn AS fqdn, d.dc AS dc ORDER BY d.netbios"
_DC_HOSTS = ("MATCH (h:Host) WHERE coalesce(h.is_dc,false) "
             "RETURN h.hostname AS hostname ORDER BY h.hostname LIMIT 20")
_STUCK_ACTORS = """
MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'suspicious'})
WHERE coalesce(c.path, v.path) = 'B'
MATCH (e:Event)-[:TRIGGERED]->(a)
MATCH (e)-[:BY]->(actor:Account)
RETURN actor.sam AS sam, actor.domain AS domain, count(*) AS n ORDER BY n DESC LIMIT 15
"""


def dcsync_gap(graph):
    """`dcsync.actor_is_dc` 零点火 → 逐环节定位断在哪。

    recipe 里 `actor_dc = actor_machine and _actor_is_dc(actor_sam, dc_host)`,而 `dc_host` 来自
    `MATCH (d:Domain {netbios: actor.domain}) RETURN d.dc`。要点火得四环全通:
      ① actor.domain 有值 → ② 图里有 :Domain{netbios=该值} → ③ 该节点 dc 有值 → ④ 短名比对上
    **任何一环断了结果都是"0 次点火",而且都不报错** —— 所以必须逐环节看,不能猜。
    """
    print("########## [6] ★`dcsync.actor_is_dc` 零点火 —— 断在哪一环 ##########")
    doms = graph.run_cypher(_DOMAINS)
    print(f"  ② 图里的 :Domain 节点({len(doms)} 个):")
    if not doms:
        print("     (一个都没有)← 断在这:recipe 的 Domain 查询必然空,dc_host 恒 None")
    for d in doms:
        flag = "" if d.get("dc") else "   ← ③ 断在这:dc 属性为空"
        print(f"     netbios={str(d.get('netbios')):16} fqdn={str(d.get('fqdn')):32} "
              f"dc={d.get('dc')}{flag}")

    hosts = [r["hostname"] for r in graph.run_cypher(_DC_HOSTS)]
    print(f"  ★替代数据源:带 is_dc=true 的 :Host({len(hosts)} 台):{hosts or '(无)'}")
    if hosts and not any(d.get("dc") for d in doms):
        print("     ⇒ 图里**其实知道**哪些主机是 DC(policy_from_graph 的 NEVER-TOUCH 就靠它),")
        print("       只是 dcsync recipe 走的是 Domain.dc 这条空路。改比对目标即可,不用补采集。")

    print("  ① 卡住的告警里,发起复制的账号(actor.sam / actor.domain):")
    for r in graph.run_cypher(_STUCK_ACTORS):
        dm = r.get("domain")
        flag = "   ← ① 断在这:账号没带域" if not dm else ""
        print(f"     {r['n']:>7}  sam={str(r['sam']):22} domain={dm}{flag}")
    print("  ④ 若 ①②③ 都有值却仍不点火 ⇒ 是短名归一没对上(netbios 大小写 / FQDN vs 短名)。")


def main(argv=None):
    ap = argparse.ArgumentParser(description="深度通道的学习产出 + sediment 收敛率(只读)")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=args.dotenv)
    graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        rows = graph.run_cypher(_VERDICTS_B)
        by_verdict = {r["verdict"]: r["n"] for r in rows}
        total_b = sum(by_verdict.values())

        print("########## [1] 谁会走到 sediment 的 LLM ##########")
        print(f"  path=B(真跑了深度研判)总数  {total_b}")
        for v, n in sorted(by_verdict.items(), key=lambda kv: -kv[1]):
            note = "★distill 第51行直接 return,**零 LLM**" if v not in _DISTILLABLE else "会往下走"
            print(f"    {str(v):16} {n:>7}  ({_pct(n, total_b):5.1f}%)  {note}")
        distillable = sum(n for v, n in by_verdict.items() if v in _DISTILLABLE)
        print(f"  ⇒ 可能烧 LLM 蒸馏的分母 = {distillable}  ({_pct(distillable, total_b):.2f}%)")
        if total_b and _pct(distillable, total_b) < 5:
            print("  ★分母这么小 ⇒ 「把收敛检查提到 distill 之前」这个优化**不值得做**。")
        print()

        uid_rows = graph.run_cypher(_UIDS_B, vs=list(_DISTILLABLE))
        uids = {r["uid"]: r["verdict"] for r in uid_rows}

        print("########## [2] 收敛率(只在上面那个分母里量)##########")
        if not uids:
            print("  分母是 0 —— 没有终局到 TP/FP/benign 的深度研判,收敛率无从谈起。")
        elif not cfg.og_enabled:
            print("  OG_HOST 没配 → 拿不到 cases 语料,跳过。")
        else:
            from soc_agent.experience.opengauss import open_stores
            exp_store, case_store, _pc, _memo = open_stores(cfg)
            cases = load_cases(case_store, set(uids))
            print(f"  分母 {len(uids)} 条,其中在 cases 语料里找得到的 {len(cases)} 条")
            conv, nodata, notconv = 0, 0, 0
            per_skill = Counter()
            for uid, (skill, verdict, findings) in cases.items():
                real = [f for f in findings if not str(f.finding_id).startswith("_")]
                if not real:
                    nodata += 1          # distill.py:59 也会直接 return —— 同样零 LLM
                    continue
                k = kind_of(verdict)
                hit = any(p.kind == k and experience_fires(p, findings)[0]
                          for p in exp_store.active_for_skill(skill))
                if hit:
                    conv += 1
                    per_skill[skill] += 1
                else:
                    notconv += 1
            base = conv + notconv
            print(f"    无实证据(第59行也零 LLM)  {nodata}")
            print(f"    已有经验覆盖 → 本可跳过     {conv}")
            print(f"    确实要蒸                    {notconv}")
            print(f"  ⇒ **收敛率 {_pct(conv, base):.1f}%**(在 {base} 条真会调 LLM 的里面)")
            print(f"  ⇒ 提前检查能省的 27b 调用 ≈ {conv} 次")
            if per_skill:
                print("    按 skill:" + "、".join(f"{s}={n}" for s, n in per_skill.most_common()))
        print()

        print("########## [3] ★真正的问题:最贵的通道学到了什么 ##########")
        n_susp = by_verdict.get("suspicious", 0)
        print(f"  深度研判 {total_b} 条,其中 suspicious {n_susp}  ({_pct(n_susp, total_b):.1f}%)")
        print("  ★suspicious **不沉淀经验**(distill 第51行)⇒ 这部分 27b 花完之后,")
        print("    经验库一条也没长。dcsync 那类'复用率 0%'的 skill,根源多半就在这。")
        mn = graph.run_cypher(_MISSING_NONE)
        if mn:
            t, e = mn[0]["total"], mn[0]["empty"] or 0
            print(f"  suspicious 里 missing_evidence **空着**的:{e}/{t}  ({_pct(e, t):.1f}%)")
            print("    ★空的最麻烦:模型说'存疑'却没说缺什么 —— 既结不了案,也指不出补什么遥测。")
        print(f"  missing_evidence 频次(前 {args.top});这就是'要能结案还缺什么'的清单:")
        for r in graph.run_cypher(_MISSING, lim=args.top):
            print(f"    {r['n']:>7}  {r['missing']}")
        print()

        print("########## [4] 卡在 suspicious 的是哪些 skill ##########")
        for r in graph.run_cypher(_SUSP_BY_SKILL):
            print(f"    {str(r['skill']):26} {r['n']:>7}  ({_pct(r['n'], n_susp):5.1f}%)")
        print()

        print("########## [5] ★这些卡住的告警,recipe 到底给出了什么 finding ##########")
        print("  白(white)=良性豁免 / 红(red)=攻击迹象 / 中性(neutral)=触发本身")
        print("  ★读法:**白 finding 点火了却仍判 suspicious** ⇒ 数据和结论都齐了,")
        print("    是 recipe 那句**无条件**的 blind_spots 在否决它(把声明改成条件性的即可);")
        print("    ★**白 finding 压根没点火** ⇒ 图里缺建模(如 Domain.dc 为空,")
        print("      recipe 比不出 'actor 是不是本域 DC')⇒ 那是入图侧的事。")
        cur_skill, fired = None, set()
        for r in graph.run_cypher(_SUSP_FINDINGS):
            if r["skill"] != cur_skill:
                cur_skill = r["skill"]
                print(f"    -- {cur_skill} --")
            fired.add(r["fid"])
            print(f"       {r['n']:>7}  [{str(r['pol']):7}] {r['fid']}")
        print()

        if "dcsync.replication_request" in fired and "dcsync.actor_is_dc" not in fired:
            dcsync_gap(graph)
        return 0
    finally:
        graph.close()


if __name__ == "__main__":
    sys.exit(main())
