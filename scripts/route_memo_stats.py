"""【Phase 2】路由记忆的观测:省了多少、学得稳不稳、哪些键学不动。★只读。

最要紧的一个数是 **`sum(hit_count)` = 省掉的深度模型调用次数** —— 记忆层的全部意义就在它上面,
其余都是"这个数可不可信"的旁证。

★`ambiguous` / `unstable` 的键**必须逐条列出**(带它们各自吃掉多少告警)。
  它们是两件事的唯一信号:
    · ambiguous —— **键太粗、少一个区分字段**,要去改 `route_key()`;
    · unstable  —— **环境在漂**(模型/skill registry/recipe/数据源),要去查什么变了。
  只报个计数等于没报:一个覆盖 30% 告警的歧义键和一个覆盖 3 条的,处理优先级差着量级。

覆盖数从图上算(按 `route_key` 归并告警),直接复用 `route_profile.collect()` ——
★别在这里另写一份键或另写一份聚合:两份实现一漂,这份报告描述的就是一个不存在的系统。
"""
import argparse
import importlib.util
import os
import pathlib
import sys
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.config import Config                                  # noqa: E402
from soc_agent.experience.route_memo import (CONFIRM_REQUIRED,       # noqa: E402
                                             DISAGREE_CAP, RELEARN_CAP, VERIFY_AT)
from soc_agent.graph.client import Neo4jGraph                        # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "route_profile", pathlib.Path(__file__).resolve().parent / "route_profile.py")
_RP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RP)

_ORDER = ("active", "candidate", "archived", "ambiguous", "unstable")
_NOTE = {
    "active": "已转正,命中即零 LLM",
    "candidate": "学习中(还没被复用过)",
    "archived": "曾稳定后漂了,允许重学",
    "ambiguous": "★天生有歧义 → 去给 route_key() 加区分字段",
    "unstable": f"★重学 {RELEARN_CAP} 轮仍震荡 → 查环境变了什么",
}


def _pct(a, b):
    return (100.0 * a / b) if b else 0.0


def report(memos, cover=None, total_alerts=0, top=30):
    if not memos:
        print("  记忆库是空的 —— poller 还没跑过,或 route_memo 表刚建。")
        return
    by_status = Counter(m.status for m in memos)
    hits = sum(m.hit_count for m in memos)
    verifies = sum(m.verify_count for m in memos)
    overrides = sum(m.override_count for m in memos)

    print("########## [1] 省了多少(这是记忆层的全部意义)##########")
    print(f"  零 LLM 命中总数   {hits}   ← 省掉的深度模型路由调用次数")
    if total_alerts:
        print(f"  图里告警总数      {total_alerts}")
        print(f"  覆盖率            {_pct(hits, total_alerts):.1f}%(命中数/告警数;"
              "poller 才跑到哪算到哪,不是稳态值)")
    print(f"  条目数            {len(memos)}   学习成本 ≈ {len(memos) * CONFIRM_REQUIRED} 次 LLM")
    print()

    print("########## [2] 学得稳不稳 ##########")
    for st in _ORDER:
        n = by_status.get(st, 0)
        print(f"  {st:<12} {n:>6}   {_NOTE[st]}")
    other = set(by_status) - set(_ORDER)
    for st in sorted(other):
        print(f"  {st:<12} {by_status[st]:>6}   ⚠ 未知状态")
    settled = by_status.get("active", 0) + by_status.get("archived", 0)
    print(f"  candidate 转正率  {_pct(settled, len(memos)):.1f}%"
          f"(转正需 {CONFIRM_REQUIRED} 条**不同**告警给出同一答案)")
    if verifies:
        print(f"  稀疏复核          做了 {verifies} 次,不一致 {overrides} 次 "
              f"→ 一致率 {_pct(verifies - overrides, verifies):.1f}%")
    else:
        print(f"  稀疏复核          还没到复核点(单键命中要够 {VERIFY_AT[0]} 次才复核第一回)")
    print()

    print("########## [3] ★学不动的键(必须逐条看,别只看计数)##########")
    bad = [m for m in memos if m.status in ("ambiguous", "unstable")]
    if not bad:
        print("  没有。所有键要么已转正、要么还在学。")
    else:
        bad.sort(key=lambda m: -((cover or {}).get(m.route_key, 0)))
        print(f"    {'状态':<11} {'吃掉告警':>9} {'占比':>7} {'分歧':>5} {'重学':>5}  键")
        for m in bad[:top]:
            c = (cover or {}).get(m.route_key, 0)
            print(f"    {m.status:<11} {c:>9} {_pct(c, total_alerts):>6.1f}% "
                  f"{m.disagree_count:>5} {m.relearn_count:>5}  {m.route_key}")
        if len(bad) > top:
            print(f"    …… 还有 {len(bad) - top} 个未列出")
        print(f"  ★ambiguous 判据 = candidate 阶段分歧 ≥ {DISAGREE_CAP} 次。占比高的优先处理:"
              "去看这个键下的告警到底分成了哪几类,给 route_key() 补上那个区分字段。")
    print()

    print(f"########## [4] 命中最多的键(前 {top})##########")
    hot = sorted([m for m in memos if m.hit_count], key=lambda m: -m.hit_count)[:top]
    if not hot:
        print("  还没有任何命中 —— 都还在 candidate 阶段(第一次的答案本来就不许复用)。")
    for m in hot:
        print(f"    {m.hit_count:>8} 次  {m.skill or '(none)':<24} {m.route_key}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase 2:路由记忆观测(只读)")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--no-graph", action="store_true",
                    help="不连图;代价是没有「这个键吃掉多少告警」,只剩记忆表本身")
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=args.dotenv)
    if not cfg.og_enabled:
        print("  OG_HOST 没配 → 记忆层在内存里,进程一停就没了,没什么可统计的。")
        return 2
    from soc_agent.experience.opengauss import open_stores
    memo_store = open_stores(cfg)[3]
    memos = memo_store.all()

    cover, total = None, 0
    if not args.no_graph:
        graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
        try:
            per_key, totals = _RP.collect(graph)
            cover = {k: e["alerts"] for k, e in per_key.items()}
            total = totals["alerts"]
        finally:
            graph.close()
    report(memos, cover=cover, total_alerts=total, top=args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
