"""Phase 0:路由记忆的**逐键定性 + 估值**(只读,不调 LLM、不写图)。

回答两个**不同**的问题,别混:

  ① 估值:值不值得做 —— 有多少告警能算出键(= 能被记住的路由调用上限)、要学多少个键。
  ② 定性:哪些键**天生有歧义**、必须永远走 LLM —— 这些用 `--seed` 预先播成负例。

★**这一关验的是"memo ≡ 现有 router",不是"router 选得对"。**
  一个键下历史 skill 全一致,只能说明 router 一直给同一个答案,不能说明那个答案对。
  Phase 1 的目标就定义成「保持现有行为不变、把重复计算消掉」——
  router 的语义正确性是另一条线(要人工标注的 skill 真值集),不在这里。

★**判据是逐键的,不是全局的**。"能不能安全缓存"是每个键各自的属性:
  100 个键里 99 个唯一、1 个有歧义 ⇒ 全局唯一率 99% 看着很好,但那 1 个歧义键
  可能恰好覆盖 30% 的告警。**安全属性不能求平均。** 反过来,5% 的键有歧义
  也不该否掉整个方案:稳定的那 95% 照样省钱。

★**键的计算必须 import,不能在这里重写一份 Cypher 版**。量的键和跑的键一旦是两份实现,
  这份报告就在描述一个不存在的系统 —— 而且不会报错。所以:Cypher 只做**原始字段**的分组
  (便宜、结果集小),`route_key()` 在 Python 侧算,与生产同一个函数。

★为什么定性只能用**已研判**告警:未研判的告警没有 skill,而 path=S(签名复用 / 浅层终局)
  的告警**根本没走过路由**,自然也没有 findings、没有 skill —— 把它们排除掉是正确的,
  不是样本损失。图刚重置过,已研判量还很小,所以每个键的**样本数**必须跟着结论一起报,
  样本不足的一律记 `insufficient`,交给运行时的 candidate 门去把关,别在这里硬下结论。
"""
import argparse
import os
import sys
from collections import Counter, defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config                                  # noqa: E402
from soc_agent.experience.route_memo import route_key                # noqa: E402
from soc_agent.graph.client import Neo4jGraph                        # noqa: E402
from soc_agent.models import Alert                                   # noqa: E402

# 定性门槛。要判一个键"天生有歧义",**次数和比例都得够**:
#   · 只看次数:样本越大越容易误判 —— 2511 条 dcsync 里混 6 条别的(0.2%)会被判成歧义,
#     等于为了 6 条放弃 2511 条的收益。固定次数门槛不随样本量缩放。
#   · 只看比例:小样本会误判 —— 4 条里 1 条不同就是 25%,而那很可能只是 router 抖了一下。
MIN_SAMPLES = 4            # 少于这么多已研判样本 → insufficient(不下结论)
MIN_MINORITY = 2           # 少数派至少出现这么多次(挡单个离群值)
MIN_MINORITY_RATIO = 0.05  # 且至少占这么大比例(挡大样本下的长尾)

# ★`skewed`(次数够但比例极低)是**可以 memo 的**,这一点值得说清楚:
#   memo 返回的是多数派答案,而 router 本来就有 (1-少数派比例) 的概率给这个答案 ——
#   换句话说,在这种键上 router 自己就是飘的,memo 只是把它**钉成确定的**。
#   代价有界且可算(= 少数派比例),报告里逐条把这个"预计误路由率"打出来,让人看得见再决定。
#   ★但运行时的稀疏复核**指望不上**:少数派占 0.2% 时,复核点落在它身上的概率也是 0.2%。
#     所以这个决定只能在这里、由人看着数字做,不能推给运行时。

# 估值判据:有键的告警占比。低于它说明省不下多少,不值得为此加一层状态机。
PASS_KEYED_RATIO = 0.60

_AGG = """
MATCH (a:Alert)
OPTIONAL MATCH (e:Event)-[:TRIGGERED]->(a)
WITH a, head(collect(e)) AS ev
OPTIONAL MATCH (a)-[:HAS_FINDING]->(f:Finding)
WITH a, ev, head(collect(DISTINCT f.skill)) AS skill
RETURN a.source AS source, a.sensor AS sensor, a.rule_id AS rule_id,
       coalesce(a.technique_ids, []) AS technique_ids,
       ev.event_code AS event_code, ev.activity AS activity,
       skill, count(*) AS n
"""


class _A:
    """route_key 只按属性读 alert,给它一个 duck-typed 行就够(不必造真 Alert)。"""
    __slots__ = ("source", "sensor", "rule_id", "technique_ids")

    def __init__(self, row):
        self.source = row.get("source")
        self.sensor = row.get("sensor")
        self.rule_id = row.get("rule_id")
        self.technique_ids = row.get("technique_ids") or []


def _seed_of(row):
    return {"event": {"event_code": row.get("event_code"), "activity": row.get("activity")}}


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def minority_ratio(skills: Counter) -> float:
    """少数派占比 = memo 若记住多数派答案,预计的误路由率。单一 skill → 0。"""
    total = sum(skills.values())
    if total <= 0 or len(skills) <= 1:
        return 0.0
    return (total - skills.most_common(1)[0][1]) / total


def classify(skills: Counter):
    """一个键下已研判告警的 skill 分布 → 定性。"""
    total = sum(skills.values())
    if total < MIN_SAMPLES:
        return "insufficient"
    if len(skills) == 1:
        return "eligible"
    minority_n = total - skills.most_common(1)[0][1]
    if minority_n >= MIN_MINORITY and minority_ratio(skills) >= MIN_MINORITY_RATIO:
        return "ambiguous"
    return "skewed"


def collect(graph):
    """跑聚合查询 → 按 route_key 归并。返回 (per_key, totals)。"""
    rows = graph.run_cypher(_AGG)
    per_key = defaultdict(lambda: {"alerts": 0, "judged": 0, "skills": Counter(),
                                   "level": None, "samples": []})
    totals = {"alerts": 0, "judged": 0, "keyed": 0, "keyed_r": 0, "keyed_t": 0,
              "no_key": 0, "no_rule_id": 0, "rule_ids": set()}
    for row in rows:
        n = int(row.get("n") or 0)
        totals["alerts"] += n
        a = _A(row)
        if not (str(a.rule_id or "").strip()):
            totals["no_rule_id"] += n
        else:
            totals["rule_ids"].add(str(a.rule_id).strip().casefold())
        k = route_key(a, _seed_of(row))
        if k is None:
            totals["no_key"] += n
            continue
        totals["keyed"] += n
        totals["keyed_r" if k.startswith("r|") else "keyed_t"] += n
        e = per_key[k]
        e["alerts"] += n
        e["level"] = k[0]
        skill = row.get("skill")
        if skill:                       # 只有走过路由的(有 findings 的)才算定性样本
            e["judged"] += n
            e["skills"][skill] += n
            totals["judged"] += n
    return per_key, totals


def report(per_key, totals, top=40):
    n_all = totals["alerts"]
    print("########## [1] 估值:能省多少 ##########")
    print(f"  告警总数            {n_all}")
    print(f"  能算出键            {totals['keyed']}  ({_pct(totals['keyed'], n_all):.1f}%)"
          "   ← 可被记住的路由调用上限")
    print(f"    ├ r| 级(rule_id)    {totals['keyed_r']}  ({_pct(totals['keyed_r'], n_all):.1f}%)")
    print(f"    └ t| 级(technique)  {totals['keyed_t']}  ({_pct(totals['keyed_t'], n_all):.1f}%)")
    print(f"  两级键全落空(兜底)  {totals['no_key']}  ({_pct(totals['no_key'], n_all):.1f}%)"
          "   ← 永远走 LLM")
    k = len(per_key)
    print(f"  不同键数            {k}   键基数/告警数 = {_pct(k, n_all):.3f}%")
    print(f"  学习成本            ≈ {k * 2} 次 LLM(每键 2 次:candidate 门要不同告警确认一次)")
    print(f"                      摊到 {n_all} 条告警 ≈ {(k * 2 / n_all if n_all else 0):.4f} 次/条")
    print()

    print("########## [2] 逐键定性(只能用已研判、且走过路由的告警)##########")
    print(f"  可用样本 {totals['judged']} / 告警 {n_all}  ({_pct(totals['judged'], n_all):.1f}%)")
    print(f"  ★样本就这么多,别过度解读。path=S(签名复用/浅层终局)的告警没走过路由,")
    print(f"    本来就不该进这个样本;图刚重置过,已研判量还小。")
    print(f"  ★门槛:样本 < {MIN_SAMPLES} 记 insufficient;判 ambiguous 要**次数和比例都够**"
          f"(少数派 ≥{MIN_MINORITY} 次 且 ≥{MIN_MINORITY_RATIO * 100:.0f}%)。")
    print(f"    次数够但比例极低 → skewed:**仍可 memo**,代价是"
          f"「预计误路由率」= 少数派占比(逐条列在下面)。")
    print(f"    ★这类键的运行时稀疏复核指望不上(少数派占 0.2% 时复核撞上它的概率也是 0.2%),")
    print(f"      所以是留是弃只能看着下面的数字由人定。")
    buckets = defaultdict(lambda: {"keys": 0, "alerts": 0})
    for k_, e in per_key.items():
        c = classify(e["skills"])
        e["verdict"] = c
        buckets[c]["keys"] += 1
        buckets[c]["alerts"] += e["alerts"]
    for name, note in (("eligible", "可安全 memo"), ("ambiguous", "★天生有歧义 → --seed 播成负例"),
                       ("skewed", "长尾偏斜 → 仍可 memo,代价见逐条的「误路由」"),
                       ("insufficient", "证据不足 → 交给运行时 candidate 门")):
        b = buckets.get(name) or {"keys": 0, "alerts": 0}
        print(f"    {name:13} {b['keys']:5} 个键,覆盖告警 {b['alerts']:8}"
              f"  ({_pct(b['alerts'], n_all):5.1f}%)  {note}")
    print()
    print(f"  逐键明细(按覆盖告警数降序,前 {top}):")
    print(f"    {'定性':<13} {'样本':>5} {'覆盖':>9} {'误路由':>7}  {'键':<40} skill 分布")
    for k_, e in sorted(per_key.items(), key=lambda kv: -kv[1]["alerts"])[:top]:
        dist = "/".join(f"{s}({c})" for s, c in e["skills"].most_common()) or "—(无样本)"
        mr = minority_ratio(e["skills"])
        mrs = f"{mr * 100:.2f}%" if mr else "—"
        print(f"    {e['verdict']:<13} {e['judged']:>5} {e['alerts']:>9} {mrs:>7}  {k_:<40} {dist}")
    if len(per_key) > top:
        print(f"    …… 还有 {len(per_key) - top} 个键未列出(完整表用 --top 0)")
    print()

    print("########## [3] rule_id 稳不稳(第一级键的地基)##########")
    print(f"  没有 rule_id 的告警  {totals['no_rule_id']}  ({_pct(totals['no_rule_id'], n_all):.1f}%)"
          "   ← 这些退到 technique 级")
    nr = len(totals["rule_ids"])
    print(f"  rule_id 唯一值数     {nr}")
    print(f"  ★若这个数与告警数同量级,说明 rule_id 自己也含变量(像 rule_description 那样),"
          f"第一级键就废了。当前 = 告警数的 {_pct(nr, n_all):.3f}%")
    print()

    amb = [k_ for k_, e in per_key.items() if e["verdict"] == "ambiguous"]
    ok = _pct(totals["keyed"], n_all) >= PASS_KEYED_RATIO * 100
    print("########## [4] 结论 ##########")
    print(f"  估值判据:能算出键的告警 {_pct(totals['keyed'], n_all):.1f}%  "
          f"(阈值 {PASS_KEYED_RATIO * 100:.0f}%)  → {'PASS ✅' if ok else 'FAIL ❌'}")
    print(f"  建议播成负例的键:{len(amb)} 个" + ("(用 --seed 写入)" if amb else ""))
    for k_ in amb[:20]:
        print(f"    {k_}   {dict(per_key[k_]['skills'])}")
    if not ok:
        print("  ❌ 有键覆盖率不够 —— 记忆层省不下多少,别为它加一层状态机。")
        print("     先看 [3]:是不是 rule_id 缺失太多、而 technique 也没有。")
    return amb, ok


def do_seed(cfg, keys):
    """只播负例:把 ambiguous 键写进 route_memo。★绝不播 active(见 route_memo 模块文档)。"""
    from soc_agent.experience.opengauss import open_stores
    from soc_agent.experience.route_memo import seed_ambiguous
    stores = open_stores(cfg)
    memo_store = stores[3]
    n = seed_ambiguous(memo_store, keys, created_by="route-profile")
    print(f"  已播负例 {n} 条(status=ambiguous,这些键此后恒走 LLM)")
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase 0:路由记忆逐键定性 + 估值(只读)")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    ap.add_argument("--top", type=int, default=40, help="逐键明细列多少行;0=全列")
    ap.add_argument("--seed", action="store_true",
                    help="把定性为 ambiguous 的键播进 route_memo(只播负例;需 Phase 1 的表已建)")
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=args.dotenv)
    graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        per_key, totals = collect(graph)
        if not totals["alerts"]:
            print("  ⚠ 图里一条 :Alert 都没有 —— 没什么可量的。")
            return 2
        amb, ok = report(per_key, totals, top=(len(per_key) if args.top == 0 else args.top))
        if args.seed:
            print()
            print("########## [5] 播种(只播负例)##########")
            if not amb:
                print("  没有定性为 ambiguous 的键,不播。")
            else:
                do_seed(cfg, amb)
        return 0 if ok else 1
    finally:
        graph.close()


if __name__ == "__main__":
    sys.exit(main())
