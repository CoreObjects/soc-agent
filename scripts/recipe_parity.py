"""行集一致闸门:改动前后,**任意 recipe** 在同一批真实告警上的取证产物逐条对比。★全程只读。

为什么需要它(与复用率闸门的分工)
--------------------------------
`replay-reuse.sh` 量的是"已沉淀经验还认不认得出来",它只护得住**有已研判语料**的 skill。
真机实测:16 个 skill 里 **10 个一条已研判语料都没有**(adcs / c2_beacon / webshell /
suspicious_outbound / web_exploit / registry_persistence / 4 个 generic)——
而这些恰恰是 WP10 要改谓词的重点。对它们,复用率闸门是**全绿的空转**。

这个闸门补的就是那一半:它不需要告警被判过,只要求"同一条告警,改前改后 recipe 吐出的
东西逐字相同"。两道闸门加起来才覆盖得住。

判据设计(沿用 WP7 pivot 闸门验证过的那套,只是不再写死三个 recipe)
------------------------------------------------------------------
· **不照抄旧查询字面量再比行** —— 那比的是我抄得对不对,不是代码改没改行为。
  直接 `git show <rev>:<path>` 取出旧版源码,在同一进程里当另一个模块加载,
  对**同一条真实告警**跑新旧两版 `collect()`,逐条对 `Forensics` 做差。
· **默认零容忍**:任何差异都算失败。要放行的新增必须**在命令行显式声明**
  (`--allow-new-findings` / `--allow-new-ctx` / `--allow-new-bindings`),
  与 WP5/WP6 的 DECLARED 白名单同一套纪律 —— 白名单是拿来"声明"的,不是拿来"兜底"的。
  ★WP10 的谓词放宽在**本租户上行集应当完全不变**(activity 已由 WP4 回填成与 event_code
    一一对应),所以严格相等就是正确的默认;真出现差异,那正是要看的东西。
· ★**必须先证明这个比对有区分力**:旧版**产出过非空 findings** 的样本数要 ≥ 阈值,
  否则两边都在空转,"零差异"只等于"都没干活"(WP6 栽过一次,WP7 前置成硬门,这里继承)。
  达不到阈值 → 报「证据不足」,**不算通过**(三态,与 pack-certify 同)。

★测哪些 recipe:默认**自动取 `<rev>..HEAD` 之间改动过的**那些。
  每个 PR 只改一条 recipe,闸门就只跑那一条 —— 既快,又不会拿没改的东西凑绿灯。
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_agent.config import Config                 # noqa: E402
from soc_agent.forensics import Forensics           # noqa: E402
from soc_agent.graph.client import Neo4jGraph       # noqa: E402
from soc_agent.models import Alert                  # noqa: E402
from soc_agent.skills_runtime import SkillRegistry  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git(*args) -> str:
    return subprocess.run(["git", "-C", ROOT, *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def changed_recipes(rev) -> list:
    """`rev..HEAD` 之间改动过的 recipe.py(仓库相对路径)。"""
    out = git("diff", "--name-only", f"{rev}..HEAD", "--", "skills")
    return sorted(p for p in out.splitlines() if p.endswith("/recipe.py"))


def load_old(path, rev):
    """把 `rev` 版本的 recipe 源码落到临时文件并加载成模块(不污染工作区)。"""
    src = subprocess.run(["git", "-C", ROOT, "show", f"{rev}:{path}"],
                         capture_output=True, check=True).stdout
    fd, tmp = tempfile.mkstemp(suffix=".py", prefix="oldrecipe_")
    with os.fdopen(fd, "wb") as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location("old_" + path.replace("/", "_"), tmp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def diff(old_fo, new_fo, *, new_findings=(), new_ctx=(), new_bindings=()) -> list:
    """返回 [异常差异描述]。只有**显式声明过**的新增不算差异;少任何东西一律算。"""
    nf, nc, nb = set(new_findings), set(new_ctx), set(new_bindings)
    out = []
    o, n = old_fo.to_dict(), new_fo.to_dict()

    def by_id(d):
        return {f["finding_id"]: f for f in d["findings"]}

    ofs, nfs = by_id(o), by_id(n)
    if set(ofs) - set(nfs):
        out.append(f"findings 少了 {sorted(set(ofs) - set(nfs))}")
    if set(nfs) - set(ofs) - nf:
        out.append(f"findings 多了未声明的 {sorted(set(nfs) - set(ofs) - nf)}")
    for fid in set(ofs) & set(nfs):
        if ofs[fid] != nfs[fid]:
            out.append(f"finding {fid} 内容变了")

    ob, nbd = o["bindings"], n["bindings"]
    if set(ob) - set(nbd):
        out.append(f"bindings 少了 {sorted(set(ob) - set(nbd))}")
    if set(nbd) - set(ob) - nb:
        out.append(f"bindings 多了未声明的 {sorted(set(nbd) - set(ob) - nb)}")
    for k in set(ob) & set(nbd):
        if ob[k] != nbd[k]:
            out.append(f"binding {k} 变了: {ob[k]!r} -> {nbd[k]!r}")

    oc, ncx = o["context"], n["context"]
    if set(oc) - set(ncx):
        out.append(f"context 少了 {sorted(set(oc) - set(ncx))}")
    if set(ncx) - set(oc) - nc:
        out.append(f"context 多了未声明的 {sorted(set(ncx) - set(oc) - nc)}")
    for k in set(oc) & set(ncx):
        if json.dumps(oc[k], sort_keys=True, default=str) != \
           json.dumps(ncx[k], sort_keys=True, default=str):
            out.append(f"context[{k}] 变了")

    if old_fo.blind_spots != new_fo.blind_spots:
        out.append("blind_spots 变了")
    return out


_POOL = ("MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
         "RETURN DISTINCT a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n")


def alert_pool(g, n) -> list:
    return [Alert.from_node(r["a"]) for r in g.run_cypher(_POOL, n=int(n))]


def check_one(g, reg, path, rev, pool, min_nonempty, allow) -> dict:
    """对一条 recipe 跑新旧对比。返回 {state, compared, nonempty, diffs}。

    ★样本不预先按 skill 挑,而是**跑一遍旧版、留下产出非空的那些** ——
      因为路由是 LLM 做的,离线无从知道哪条告警"属于"哪个 skill;
      而对"改前改后是否一致"这个断言来说,**任何能让它干活的告警都是合法输入**。
    """
    skill_name = os.path.basename(os.path.dirname(path))
    skill = reg.by_name(skill_name)
    if skill is None or skill.recipe is None:
        return {"state": "跳过", "why": f"registry 里没有可用的 {skill_name}(recipe 加载失败?)",
                "compared": 0, "nonempty": 0, "diffs": []}
    try:
        old = load_old(path, rev)
    except subprocess.CalledProcessError:
        return {"state": "跳过", "why": f"{rev} 里没有这个文件(新增的 recipe,无从对比)",
                "compared": 0, "nonempty": 0, "diffs": []}
    if not hasattr(old, "collect"):
        return {"state": "跳过", "why": "旧版没有 collect()", "compared": 0, "nonempty": 0, "diffs": []}

    compared = nonempty = 0
    diffs = []
    for alert in pool:
        seed = g.seed(alert)
        try:
            of = Forensics.coerce(old.collect(g, alert, seed))
            nf_ = Forensics.coerce(skill.recipe(g, alert, seed))
        except Exception as e:                     # 一条炸不该毁掉整轮,但要记下来
            diffs.append(f"{alert.alert_uid}: 跑挂了 {type(e).__name__}: {e}")
            continue
        compared += 1
        # ★区分力只认"旧版真的产出过东西"的样本 —— 空对空的相等不证明任何事
        real = [f for f in of.findings if not str(f.finding_id).startswith("_")]
        if real:
            nonempty += 1
        d = diff(of, nf_, **allow)
        if d:
            diffs.append(f"{alert.alert_uid}: " + "; ".join(d))
        if nonempty >= min_nonempty and compared >= min_nonempty:
            break

    if diffs:
        state = "有差异"
    elif nonempty < min_nonempty:
        state = f"证据不足(旧版只在 {nonempty} 条上产出过东西,<{min_nonempty})"
    else:
        state = "ok"
    return {"state": state, "compared": compared, "nonempty": nonempty, "diffs": diffs}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", required=True, help="对比基线 git rev(通常是改动前的提交)")
    ap.add_argument("--skills", default="", help="只测这些(逗号分隔);默认=rev..HEAD 改动过的 recipe")
    ap.add_argument("--pool", type=int, default=1200, help="候选告警池大小(按到达倒序)")
    ap.add_argument("--min-nonempty", type=int, default=30,
                    help="旧版至少要在这么多条上产出过非空 findings,否则判「证据不足」")
    ap.add_argument("--allow-new-findings", default="")
    ap.add_argument("--allow-new-ctx", default="")
    ap.add_argument("--allow-new-bindings", default="")
    args = ap.parse_args()

    def csv(x):
        return tuple(v.strip() for v in x.split(",") if v.strip())

    allow = {"new_findings": csv(args.allow_new_findings),
             "new_ctx": csv(args.allow_new_ctx),
             "new_bindings": csv(args.allow_new_bindings)}

    paths = ([f"skills/{s.strip()}/recipe.py" if "/" in s else s.strip()
              for s in args.skills.split(",") if s.strip()]
             if args.skills else changed_recipes(args.rev))
    if args.skills:                       # 允许只给 skill 名,自己去 registry 找路径
        reg0 = SkillRegistry(os.path.join(ROOT, "skills"))
        fixed = []
        for p in paths:
            name = os.path.basename(os.path.dirname(p))
            sk = reg0.by_name(name)
            fixed.append(os.path.relpath(str(sk.path / "recipe.py"), ROOT).replace("\\", "/")
                         if sk else p)
        paths = fixed

    print(f"基线 rev = {args.rev}")
    print(f"待测 recipe({'手工指定' if args.skills else 'rev..HEAD 改动过的'}):")
    for p in paths:
        print(f"  {p}")
    if not paths:
        print("  (无 —— 这次没改任何 recipe,本闸门无事可做)")
        return 0
    print()

    cfg = Config.from_env(dotenv_path=os.path.join(ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空 —— .env 没读到或没配。")
        return 2
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        reg = SkillRegistry(os.path.join(ROOT, "skills"))
        pool = alert_pool(g, args.pool)
        print(f"候选告警池 {len(pool)} 条(按到达倒序)\n")
        results = {}
        for p in paths:
            r = check_one(g, reg, p, args.rev, pool, args.min_nonempty, allow)
            results[p] = r
            print(f"--- {p} ---")
            print(f"  比对 {r['compared']} 条 / 旧版非空 {r['nonempty']} 条 → {r['state']}")
            for d in r["diffs"][:10]:
                print(f"     {d}")
            if len(r["diffs"]) > 10:
                print(f"     …还有 {len(r['diffs']) - 10} 条")
            if r.get("why"):
                print(f"     {r['why']}")
            print()
    finally:
        g.close()

    bad = [p for p, r in results.items() if r["state"] == "有差异"]
    weak = [p for p, r in results.items() if r["state"].startswith("证据不足")]
    if bad:
        print(f"❌ **行集不一致**:{bad}")
        print("   声明过的新增之外的任何差异都算失败。要么改回去,要么把新增显式声明进命令行"
              "(并想清楚它为什么该被放行)。")
        return 1
    if weak:
        print(f"⚠ **证据不足,不算通过**:{weak}")
        print("   旧版在样本上几乎没产出过东西 ⇒ 两边都在空转,零差异不证明任何事。")
        print("   加大 --pool,或换一批更可能让它干活的告警。")
        return 3
    print("✅ 全部行集一致,且样本有区分力。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
