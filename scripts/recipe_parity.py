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


_ORDER = "[顺序] "          # 仅顺序不同的差异前缀 —— 报出来但不判失败


def _unordered(v):
    """递归把列表变成**可比的无序形式**,用来判断"两边内容是否相同、只是顺序不同"。

    ★只用于**分类**,不用于判等:真正的判等仍然是逐字比较。
      这样"内容变了"照抓,而 Cypher `collect()` 的天然无序不会把闸门刷成噪声。
    """
    if isinstance(v, list):
        return sorted((json.dumps(_unordered(x), sort_keys=True, default=str, ensure_ascii=False)
                       for x in v))
    if isinstance(v, dict):
        return {k: _unordered(x) for k, x in v.items()}
    return v


def slot_of(msg: str) -> str:
    """从差异描述里抽出它属于哪个「槽位」(context[X] / finding X / binding X / blind_spots)。

    用来做**噪声抵消**:同一份旧代码跑两遍如果这个槽位就已经不一致,
    那它在新旧对比里的差异也不能算到改动头上。
    """
    m = msg.replace(_ORDER, "")
    for pre in ("context[", "finding ", "binding ", "findings ", "bindings "):
        if m.startswith(pre):
            rest = m[len(pre):]
            return pre + (rest.split("]")[0] if pre.endswith("[") else rest.split(" ")[0])
    return m.split(" ")[0]


def diff(old_fo, new_fo, *, new_findings=(), new_ctx=(), new_bindings=(),
         ignore_slots=()) -> list:
    """返回 [异常差异描述]。只有**显式声明过**的新增不算差异;少任何东西一律算。

    `ignore_slots`:已被证明**该 recipe 自己跑两遍就不一致**的槽位 —— 那是它本身的
    不确定性,不是本次改动造成的,不该算在改动头上(但会被单独报出来)。
    """
    nf, nc, nb = set(new_findings), set(new_ctx), set(new_bindings)
    ignore = set(ignore_slots)
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
        a = json.dumps(oc[k], sort_keys=True, default=str, ensure_ascii=False)
        b = json.dumps(ncx[k], sort_keys=True, default=str, ensure_ascii=False)
        if a == b:
            continue
        # ★只说"变了"没用:每 PR 都要跑的闸门,必须让人**当场看出变成什么**,
        #   否则红了还得另写脚本去捞(首跑就卡在这)。
        detail = f"\n        旧: {a[:300]}\n        新: {b[:300]}"
        if _unordered(oc[k]) == _unordered(ncx[k]):
            # ★**仅顺序不同**要与"内容不同"分开。Cypher 的 `collect(DISTINCT …)` 本就无序,
            #   换一条遍历路径顺序就变 —— 拿它当失败,以后每个 PR 都会被这种噪声刷屏,
            #   真正的差异反而被埋掉。但也**不能悄悄吞掉**:有些列表的顺序是有意义的
            #   (时间线之类),所以照常打出来,只是不判失败,由人看一眼。
            out.append(f"{_ORDER}context[{k}] 仅顺序不同(内容相同){detail}")
        else:
            out.append(f"context[{k}] 内容变了{detail}")

    if old_fo.blind_spots != new_fo.blind_spots:
        out.append("blind_spots 变了")
    return [d for d in out if slot_of(d) not in ignore]


_POOL = ("MATCH (a:Alert)<-[:TRIGGERED]-(e:Event) "
         "RETURN DISTINCT a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n")

# ★按 skill 定向取样:台账里记着**每条告警当初是用哪个 skill 判的**
#   (`(:Alert)-[:HAS_FINDING]->(:Finding {skill})`)—— 那就是这条 recipe 真正干过活的告警。
#   不用它的话,通用池("最近 N 条告警")对冷门 skill 可能一条都不沾:
#   kerberoast 首跑就是 1200 条里**旧版非空 0 条**、判「证据不足」,
#   而同一时刻 replay-reuse 明确报着它有 219 条已研判告警 —— 样本明明有,是我取偏了。
_POOL_BY_SKILL = ("MATCH (a:Alert)-[:HAS_FINDING]->(f:Finding {skill:$skill}) "
                  "RETURN DISTINCT a{.*} AS a ORDER BY a.arrival_ms DESC LIMIT $n")


def alert_pool(g, n) -> list:
    return [Alert.from_node(r["a"]) for r in g.run_cypher(_POOL, n=int(n))]


def alert_pool_for(g, skill_name, n) -> list:
    """这条 recipe **当初真的判过**的告警(来自图台账)。冷门 skill 全靠它才有样本。"""
    return [Alert.from_node(r["a"])
            for r in g.run_cypher(_POOL_BY_SKILL, skill=skill_name, n=int(n))]


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

    # ★定向样本优先,通用池兜底(按 uid 去重、保持顺序)。
    targeted = alert_pool_for(g, skill_name, max(min_nonempty * 4, 100))
    seen, use = set(), []
    for a in list(targeted) + list(pool):
        if a.alert_uid not in seen:
            seen.add(a.alert_uid)
            use.append(a)
    print(f"    样本:定向(台账里用过本 skill 的){len(targeted)} 条 + 通用池兜底 → 共 {len(use)} 条")

    compared = nonempty = 0
    diffs, unstable = [], []
    for alert in use:
        seed = g.seed(alert)
        try:
            # ★★**把新版夹在两次旧版中间**跑:旧 → 新 → 旧。
            #   噪声底 = 头尾两次**旧版**的差异 ⇒ 它覆盖的是**整个测量窗口**。
            #
            #   为什么不是"先跑两遍旧版再跑新版":那样噪声底只覆盖前半段。
            #   图是活的 —— `该账号↔该主机基线` 里的登录次数是 `sum(e.count)`,
            #   robb.stark 有 20 万次登录、新事件持续在进;只要有一条 4624 落在
            #   "第二次旧版"与"新版"之间,漂移就会被算到改动头上。
            #   实测就是这么翻车的:同样的代码连跑两轮,一轮 web_exploit 红、
            #   一轮 lateral_movement 红,**结论在两次运行之间翻转** —— 那不是改动的问题,
            #   是测量方法漏掉了后半段的漂移。
            #
            #   另一类噪声(查询本身没有确定序,如 `base[0]` 取多行结果第一行、
            #   `collect(…)[..N]` 在无序集合上切片)同样被这个夹心结构覆盖。
            of = Forensics.coerce(old.collect(g, alert, seed))
            nf_ = Forensics.coerce(skill.recipe(g, alert, seed))
            of2 = Forensics.coerce(old.collect(g, alert, seed))
        except Exception as e:                     # 一条炸不该毁掉整轮,但要记下来
            diffs.append(f"{alert.alert_uid}: 跑挂了 {type(e).__name__}: {e}")
            continue
        compared += 1
        noisy = {slot_of(d) for d in diff(of, of2, **allow)}
        if noisy:
            unstable.append(f"{alert.alert_uid}: {sorted(noisy)}")
        # ★区分力只认"旧版真的产出过东西"的样本 —— 空对空的相等不证明任何事
        real = [f for f in of.findings if not str(f.finding_id).startswith("_")]
        if real:
            nonempty += 1
        d = diff(of, nf_, ignore_slots=noisy, **allow)
        if d:
            diffs.append(f"{alert.alert_uid}: " + "; ".join(d))
        if nonempty >= min_nonempty and compared >= min_nonempty:
            break

    hard = [d for d in diffs if _ORDER not in d]
    soft = [d for d in diffs if _ORDER in d]
    if hard:
        state = "有差异"
    elif soft and nonempty >= min_nonempty:
        state = f"ok(但有 {len(soft)} 条**仅顺序不同**,已列出供人过目)"
    elif nonempty < min_nonempty:
        state = f"证据不足(旧版只在 {nonempty} 条上产出过东西,<{min_nonempty})"
    else:
        state = "ok"
    return {"state": state, "compared": compared, "nonempty": nonempty,
            "diffs": (hard + soft) if (hard or soft) else [], "unstable": unstable}


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
            for d in r["diffs"][:6]:
                print(f"     {d}")
            if len(r["diffs"]) > 6:
                print(f"     …还有 {len(r['diffs']) - 6} 条(形态多半相同,先看上面这几条)")
            # ★噪声底**无论有没有都要打**:沉默是有歧义的 ——
            #   分不清"夹心结构吸收了漂移"还是"这一跑碰巧没漂"。
            print(f"     噪声底(同一旧版首尾两次之差):{len(r.get('unstable') or [])} 条")
            if r.get("unstable"):
                print(f"     ★同一份**旧代码**在测量窗口内自己就变了 {len(r['unstable'])} 条 ——"
                      f"与本次改动无关(已从判定里抵消):")
                for u in r["unstable"][:4]:
                    print(f"        {u}")
                print("        (两类成因:①**图在动** —— 如 sum(e.count) 这种活计数,新事件持续在进;"
                      "②**查询没有确定序** —— `base[0]` 取多行结果第一行、`collect(…)[..N]` 切无序集合。"
                      "①无需修;②值得单独修。)")
            if r.get("why"):
                print(f"     {r['why']}")
            print()
    finally:
        g.close()

    bad = [p for p, r in results.items() if r["state"] == "有差异"]
    order_only = [p for p, r in results.items() if "仅顺序不同" in r["state"]]
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
    if order_only:
        print(f"ℹ️ {order_only} 只有**顺序**变了、内容逐条相同 —— 不判失败。")
        print("   (Cypher 的 collect() 本就无序;但请扫一眼上面列出的新旧值,")
        print("    确认那个顺序对你要表达的东西确实无所谓。)")
    print("✅ 全部行集一致(内容层面),且样本有区分力。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
