"""WP7 真机闸门:pivot 化前后,三个 recipe 在**真实告警**上的取证产物逐条对比。★全程只读。

判据设计(为什么这么比):
  · 不去"照着重打一遍旧查询字面量"再比行 —— 那比的是我抄得对不对,不是代码改没改行为。
    这里**直接从 git 取出迁移前的 recipe 源码**,在同一进程里当另一个模块加载,
    对**同一条真实告警**跑新旧两版 `collect()`,逐条对 `Forensics` 做差。
  · 唯一允许的差异是**事先声明**的三项(与 WP5/WP6 的 DECLARED 白名单同一套纪律):
        findings 新增 `_coverage.absent`  /  context 新增 `主语(pivot)`  /  bindings 新增 `src_ip`
    出现任何第四种差异 = 失败,不解释。
  · ★同时要证"这个比对有区分力":旧版**产出过非空 findings** 的样本必须 ≥ 阈值,
    否则两边都在空转,"零差异"只是"都没干活"(WP6 栽过一次,这次前置成硬门)。

顺带量出被修的那个 bug 有多大:旧版静默返回空 findings 的告警占比 —— 那些正是
"不报错、给出一个自信的空结论"的样本。
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_agent.config import Config               # noqa: E402
from soc_agent.graph.client import Neo4jGraph     # noqa: E402
from soc_agent.models import Alert                # noqa: E402
from soc_agent.skills_runtime import SkillRegistry  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RECIPES = {
    "c2_beacon": "skills/network/c2_beacon/recipe.py",
    "suspicious_outbound": "skills/network/suspicious_outbound/recipe.py",
    "webshell": "skills/application/webshell/recipe.py",
}

# ★唯一允许的新增(声明式白名单;多一样都算失败)
NEW_FINDING_IDS = {"_coverage.absent"}
NEW_CTX_KEYS = {"主语(pivot)"}
NEW_BINDINGS = {"src_ip"}


def load_old(path, rev):
    """把 `rev` 版本的 recipe 源码落到临时文件并加载成模块(不污染工作区)。"""
    src = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, check=True).stdout
    fd, tmp = tempfile.mkstemp(suffix=".py", prefix="oldrecipe_")
    with os.fdopen(fd, "wb") as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location("old_" + path.replace("/", "_"), tmp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def diff(old_fo, new_fo):
    """返回 [异常差异描述];声明过的三项新增不算差异。"""
    out = []
    o, n = old_fo.to_dict(), new_fo.to_dict()

    def by_id(d):
        return {f["finding_id"]: f for f in d["findings"]}

    ofs, nfs = by_id(o), by_id(n)
    added = set(nfs) - set(ofs)
    removed = set(ofs) - set(nfs)
    if removed:
        out.append(f"findings 少了 {sorted(removed)}")
    if added - NEW_FINDING_IDS:
        out.append(f"findings 多了未声明的 {sorted(added - NEW_FINDING_IDS)}")
    for fid in set(ofs) & set(nfs):
        if ofs[fid] != nfs[fid]:
            out.append(f"finding {fid} 内容变了: {ofs[fid]} -> {nfs[fid]}")

    ob, nb = o["bindings"], n["bindings"]
    if set(ob) - set(nb):
        out.append(f"bindings 少了 {sorted(set(ob) - set(nb))}")
    if set(nb) - set(ob) - NEW_BINDINGS:
        out.append(f"bindings 多了未声明的 {sorted(set(nb) - set(ob) - NEW_BINDINGS)}")
    for k in set(ob) & set(nb):
        if ob[k] != nb[k]:
            out.append(f"binding {k} 变了: {ob[k]!r} -> {nb[k]!r}")

    oc, nc = o["context"], n["context"]
    if set(oc) - set(nc):
        out.append(f"context 少了 {sorted(set(oc) - set(nc))}")
    if set(nc) - set(oc) - NEW_CTX_KEYS:
        out.append(f"context 多了未声明的 {sorted(set(nc) - set(oc) - NEW_CTX_KEYS)}")
    for k in set(oc) & set(nc):
        if json.dumps(oc[k], sort_keys=True, default=str) != json.dumps(nc[k], sort_keys=True, default=str):
            out.append(f"context[{k}] 变了")

    if old_fo.blind_spots != new_fo.blind_spots:
        out.append("blind_spots 变了")
    return out


def sample_alerts(g, limit, anchored):
    """分层抽样。

    ★首跑教训:按"最近 800 条告警"随便抽,只有 205 条能走到 process 分支 —— 闸门自己判了
      无区分力。零回归这个断言说的是 **process 分支**,那就该抽真正走这条分支的样本;
      这不是挑好看的数据,而是让样本对准被断言的那件事。随机层单独留着看覆盖度故事。
    """
    if anchored:
        q = ("MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)-[:BY]->(:Process) "
             "RETURN DISTINCT a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n")
    else:
        q = ("MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
             "RETURN DISTINCT a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n")
    return [Alert.from_node(r["a"]) for r in g.run_cypher(q, n=limit)]


def diagnose_unresolvable(g, limit):
    """★量清楚"解析不出主语"的告警到底是什么 —— 首跑里它占了 74%,不查明白就不知道
    这是"这些告警本来就不该给这三个 recipe 看"还是"我的主语阶梯缺了一级"。"""
    print("=== 主语解析不出来的那部分,到底是什么 ===")
    rows = g.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
        "WHERE NOT (e)-[:BY]->() AND NOT (e)-[:FROM]->() "
        "RETURN e.event_code AS code, e.activity AS activity, e.source AS source, "
        "count(*) AS n, sum(CASE WHEN (e)-[:ON_HOST]->(:Host) THEN 1 ELSE 0 END) AS with_host "
        "ORDER BY n DESC LIMIT 15")
    print("  ① 既无 BY 也无 FROM 的触发事件(按 event_code):")
    for r in rows:
        print(f"     code={r['code']!r:>10} activity={r['activity']!r:<22} source={r['source']!r:<12}"
              f" n={r['n']:<7} 其中带 ON_HOST={r['with_host']}")
    if not rows:
        print("     (无)")

    rows2 = g.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)-[:BY]->(s) "
        "WHERE NOT any(l IN labels(s) WHERE l IN ['Process','IPAddress','Account','Host']) "
        "RETURN labels(s) AS labels, count(*) AS n ORDER BY n DESC LIMIT 10")
    print("  ② BY 指向了主语闭集之外的标签(有的话就是阶梯缺了一级):")
    for r in rows2:
        print(f"     labels={r['labels']} n={r['n']}")
    if not rows2:
        print("     (无 —— 闭集覆盖了所有 BY 端)")

    rows3 = g.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
        "WHERE NOT (e)-[:BY]->() AND NOT (e)-[:FROM]->() AND NOT (e)-[:ON_HOST]->(:Host) "
        "RETURN count(DISTINCT a) AS n")
    print(f"  ③ 三级阶梯(BY→FROM→ON_HOST)全落空的告警数: {rows3[0]['n'] if rows3 else '?'}")
    print()


def run_stratum(g, reg, alerts, rev, label):
    """对一批告警跑新旧两版 collect 并逐条比对。返回 (全过?, 旧版非空样本数)。"""
    print(f"########## {label}:{len(alerts)} 条 ##########\n")
    ok_all, nonempty_min = True, None
    for name, path in RECIPES.items():
        old = load_old(path, rev)
        new = reg.by_name(name).recipe
        bad, crashes, nonempty, old_empty, pivots = [], [], 0, 0, {}
        for a in alerts:
            try:
                ofo = old.collect(g, a, {})
            except Exception as e:
                # ★旧版自己崩的样本不判失败:那不是新代码的回归,而是没法比。单独报出来。
                crashes.append((a.alert_uid, f"{type(e).__name__}: {e}"))
                continue
            nfo = new(g, a, {})
            # ★"解析不出主语"与"主语解析出来了但本 recipe 不支持"必须分开计 ——
            #   接新源时前者=阶梯缺级(要改 pivot.py),后者=缺支持(要改 recipe),两回事。
            pv = nfo.context.get("主语(pivot)") or {}
            k = pv.get("kind") or "无主语"
            if pv.get("supported") is False:
                k = f"{k}(不支持)"
            pivots[k] = pivots.get(k, 0) + 1
            if ofo.findings:
                nonempty += 1
                d = diff(ofo, nfo)
                if d:
                    bad.append((a.alert_uid, d))
            else:
                old_empty += 1
                # 旧版静默返回空的那些:新版**必须**要么给出结论、要么明说报缺
                if not nfo.findings:
                    bad.append((a.alert_uid, ["旧版空 findings,新版既没结论也没报缺 —— 静默照旧"]))
        nonempty_min = nonempty if nonempty_min is None else min(nonempty_min, nonempty)
        ok = not bad
        ok_all &= ok
        print(f"--- {name} ---")
        print(f"  主语分布 {pivots}")
        print(f"  旧版非空 findings {nonempty} 条 / 旧版静默返回空 {old_empty} 条"
              f"({100.0 * old_empty / max(1, len(alerts)):.1f}%)")
        print(f"  {'✅' if ok else '❌'} 异常差异 {len(bad)} 条")
        for uid, d in bad[:10]:
            print(f"     {uid}: {d}")
        if len(bad) > 10:
            print(f"     ...另有 {len(bad) - 10} 条")
        if crashes:
            print(f"  ⚠ 旧版自身异常 {len(crashes)} 条(不判失败:没法比,但要看):")
            for uid, e in crashes[:5]:
                print(f"     {uid}: {e}")
        print()
    return ok_all, (nonempty_min or 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="HEAD", help="迁移前的 git 版本")
    ap.add_argument("--limit", type=int, default=800, help="锚定层(走 process 分支)样本上限")
    ap.add_argument("--random-limit", type=int, default=400, help="随机层样本上限(看覆盖度故事)")
    ap.add_argument("--min-nonempty", type=int, default=500,
                    help="★锚定层里,**每个** recipe 旧版都必须在这么多条上产出过非空 findings,"
                         "否则判本次比对无区分力")
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=os.path.join(ROOT, ".env"))
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    reg = SkillRegistry(os.path.join(ROOT, "skills"))
    try:
        print(f"对比基线 rev={args.rev}\n")
        diagnose_unresolvable(g, args.limit)

        anchored = sample_alerts(g, args.limit, anchored=True)
        if not anchored:
            print("⛔ 图里没有「触发事件带 BY→Process」的告警 —— 零回归断言无从验证")
            return 2
        ok_a, nonempty = run_stratum(g, reg, anchored, args.rev,
                                     "锚定层(触发事件带 BY→Process,直接压 process 分支)")

        rnd = sample_alerts(g, args.random_limit, anchored=False)
        ok_b, _ = run_stratum(g, reg, rnd, args.rev, "随机层(最近告警,看覆盖度是否被如实说出)")

        if nonempty < args.min_nonempty:
            print(f"⛔ 锚定层里最少的那个 recipe 旧版只在 {nonempty} 条上产出过非空 findings"
                  f"(<{args.min_nonempty})⇒ 本次比对**无区分力**,判结论无效,不是通过。"
                  f"加大 --limit 重跑。")
            return 2
        ok = ok_a and ok_b
        print(f"⇒ WP7 真机行为对等 {'✅ 通过' if ok else '❌ 失败'}"
              f"(有区分力:锚定层每个 recipe 旧版非空样本 ≥ {nonempty})")
        return 0 if ok else 1
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
