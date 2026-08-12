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


def sample_alerts(g, limit):
    """取最近的真实告警(带触发事件的优先 —— 否则新旧都只能报瞎,比对没信息量)。"""
    rows = g.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
        "RETURN a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n", n=limit)
    return [Alert.from_node(r["a"]) for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="HEAD", help="迁移前的 git 版本(默认 HEAD=尚未提交本次改动时)")
    ap.add_argument("--limit", type=int, default=800)
    ap.add_argument("--min-nonempty", type=int, default=500,
                    help="旧版必须在这么多条上产出过非空 findings,否则判本次比对无区分力")
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=os.path.join(ROOT, ".env"))
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    reg = SkillRegistry(os.path.join(ROOT, "skills"))
    try:
        alerts = sample_alerts(g, args.limit)
        print(f"取到 {len(alerts)} 条真实告警(均带触发事件)  对比基线 rev={args.rev}\n")
        if not alerts:
            print("⛔ 图里没有带触发事件的告警,比对无从做起")
            return 2

        overall_ok, total_nonempty = True, 0
        for name, path in RECIPES.items():
            old = load_old(path, args.rev)
            new = reg.by_name(name).recipe
            bad, nonempty, old_silent_empty, pivots = [], 0, 0, {}
            for a in alerts:
                try:
                    ofo = old.collect(g, a, {})
                except Exception as e:                       # 旧版自己崩的样本不参与比对
                    bad.append((a.alert_uid, [f"旧版异常 {type(e).__name__}: {e}"]))
                    continue
                nfo = new(g, a, {})
                k = (nfo.context.get("主语(pivot)") or {}).get("kind")
                pivots[k] = pivots.get(k, 0) + 1
                if ofo.findings:
                    nonempty += 1
                    d = diff(ofo, nfo)
                    if d:
                        bad.append((a.alert_uid, d))
                else:
                    old_silent_empty += 1
                    if "_coverage.absent" not in nfo.finding_ids() and not nfo.findings:
                        bad.append((a.alert_uid, ["旧版空 findings,新版既没结论也没报缺 —— 静默照旧"]))
            total_nonempty = max(total_nonempty, nonempty)
            ok = not bad
            overall_ok &= ok
            print(f"--- {name} ---")
            print(f"  主语分布 {pivots}")
            print(f"  旧版产出非空 findings: {nonempty} 条;旧版静默返回空: {old_silent_empty} 条"
                  f"({100.0 * old_silent_empty / max(1, len(alerts)):.1f}% ← 这就是被修的那个洞)")
            print(f"  {'✅' if ok else '❌'} 差异 {len(bad)} 条")
            for uid, d in bad[:10]:
                print(f"     {uid}: {d}")
            if len(bad) > 10:
                print(f"     ...另有 {len(bad) - 10} 条")
            print()

        if total_nonempty < args.min_nonempty:
            print(f"⛔ 旧版仅在 {total_nonempty} 条上产出过非空 findings(<{args.min_nonempty}),"
                  f"本次比对**无区分力**(两边都在空转时零差异什么都不证明)⇒ 判结论无效,不是通过。")
            return 2
        print(f"⇒ WP7 真机行为对等 {'✅ 通过' if overall_ok else '❌ 失败'}"
              f"(有区分力:旧版非空样本 {total_nonempty} ≥ {args.min_nonempty})")
        return 0 if overall_ok else 1
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
