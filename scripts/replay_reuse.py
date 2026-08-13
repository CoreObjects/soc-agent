"""语料保全闸门:重放已研判告警,量**自动复用率**,改动前后对比。

WP10 的硬闸门就是这个 —— 计划原文:「重放 ≥500 条已研判告警,**自动复用率 ≥ 改前基线**」。
放宽 recipe 谓词、给 Finding.attrs 加字段这类改动,失败方式**不是报错**,
而是指纹悄悄不再命中、系统默默退回全量 LLM 研判,唯一症状是成本漂移。
所以必须有个能在改动前后跑、拿数字说话的东西。

三条设计约束(每条都对应一个会让闸门失去意义的坑):
  1. **零副作用**:只跑「取证 → 经验比对」,不调 LLM、不写台账、不沉淀经验。
     跑一遍就改变系统状态的闸门,第二遍量的就不是同一件事了。
  2. **走生产同一条代码路径**:直接复用 `collect_forensics` 与 `consult`,不另写一份判定逻辑 ——
     另写一份,量的就是那份复制品,不是生产。
  3. **样本确定**:按 alert_uid 排序取前 N,不随机。基线与候选必须是同一批告警。

  ★skill 不重新路由(那要调 LLM):从台账 `(:Alert)-[:HAS_FINDING]->(:Finding {skill})`
    取当时实际用的那个 —— 既省 LLM,又比重新路由更忠实。

诚实说明一处**做不到的**:图是活的(新事件持续入图),同一条告警隔一段时间重放,
取证结果可能本就不同。所以本工具除了报总数,还**逐条列出翻转的告警** ——
让"是改动造成的"还是"图漂造成的"看得见,而不是藏在一个聚合数字里。
"""
import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build_pipeline, collect_forensics          # noqa: E402
from soc_agent.config import Config                                  # noqa: E402
from soc_agent.experience.consult import (consult,                   # noqa: E402
                                          coverage_partition_enabled)
from soc_agent.graph import coverage                                 # noqa: E402
from soc_agent.models import Alert                                   # noqa: E402

# 已研判且能拿到当时 skill 的告警,按 uid 定序 —— 基线/候选必须是同一批
_PICK = """
MATCH (a:Alert)-[:CONCLUDED]->(:Verdict)
MATCH (a)-[:HAS_FINDING]->(f:Finding)
WITH a, head(collect(DISTINCT f.skill)) AS skill
WHERE skill IS NOT NULL
RETURN a.alert_uid AS uid, skill AS skill
ORDER BY uid
LIMIT $n
"""


def replay(pl, limit):
    rows = pl.graph.run_cypher(_PICK, n=int(limit))
    sig = coverage.get(pl.graph).signature
    per_alert, tally, per_skill = {}, {}, {}
    for i, r in enumerate(rows, 1):
        uid, skill_name = r["uid"], r["skill"]
        skill = pl.router.registry.by_name(skill_name)
        if skill is None:                       # skill 改过名/被删 —— 如实记,不静默跳过
            per_alert[uid] = "SKILL_GONE"
            tally["SKILL_GONE"] = tally.get("SKILL_GONE", 0) + 1
            continue
        node = pl.graph.get_alert(uid)
        if node is None:
            per_alert[uid] = "ALERT_GONE"
            tally["ALERT_GONE"] = tally.get("ALERT_GONE", 0) + 1
            continue
        alert = Alert.from_node(node)
        seed = pl.graph.seed(alert)
        fo = collect_forensics(pl.graph, alert, seed, skill)          # ★生产同一函数,只读
        rep = consult(skill.name, fo.findings, pl.exp_store, coverage_sig=sig)
        per_alert[uid] = rep.decision
        tally[rep.decision] = tally.get(rep.decision, 0) + 1
        d = per_skill.setdefault(skill.name, {})
        d[rep.decision] = d.get(rep.decision, 0) + 1
        if i % 25 == 0:
            print(f"  …已重放 {i}/{len(rows)}")
    return {"coverage_sig": sig, "partition_on": coverage_partition_enabled(),
            "total": len(rows), "tally": tally, "per_skill": per_skill,
            "per_alert": per_alert}


def _rate(res) -> float:
    auto = res["tally"].get("AUTO_TP", 0) + res["tally"].get("AUTO_FP", 0)
    judged = auto + res["tally"].get("FALLTHROUGH", 0)
    return (auto / judged) if judged else 0.0


def report(res, base=None) -> int:
    print(f"\n--- 重放 {res['total']} 条(覆盖度签名 {res['coverage_sig'] or '(未测)'};"
          f"分区开关 {'开' if res['partition_on'] else '关'})---")
    for k in ("AUTO_TP", "AUTO_FP", "FALLTHROUGH", "SKILL_GONE", "ALERT_GONE"):
        if res["tally"].get(k):
            print(f"  {k:<12} {res['tally'][k]}")
    print(f"  ★自动复用率 = {_rate(res):.1%}")
    print("\n  按 skill:")
    for name, d in sorted(res["per_skill"].items()):
        auto = d.get("AUTO_TP", 0) + d.get("AUTO_FP", 0)
        tot = auto + d.get("FALLTHROUGH", 0)
        print(f"    {name:<24} {auto}/{tot}" + (f"  ({auto / tot:.0%})" if tot else ""))
    if base is None:
        print("\n  (没给基线 —— 这一份就是基线,用 --save 存下来,改完之后 --baseline 对比)")
        return 0

    print(f"\n--- 与基线对比(基线 {base['total']} 条,复用率 {_rate(base):.1%})---")
    flips = [(u, base["per_alert"].get(u), d) for u, d in res["per_alert"].items()
             if base["per_alert"].get(u) not in (None, d)]
    lost = [f for f in flips if f[1] in ("AUTO_TP", "AUTO_FP") and f[2] == "FALLTHROUGH"]
    gained = [f for f in flips if f[1] == "FALLTHROUGH" and f[2] in ("AUTO_TP", "AUTO_FP")]
    print(f"  翻转 {len(flips)} 条:丢掉复用 {len(lost)} / 新增复用 {len(gained)}")
    # ★逐条列出来:图是活的,重放本就有漂移。列出来才分得清"改动造成的"还是"图漂"。
    for u, was, now in lost[:15]:
        print(f"    ✗ {u}  {was} → {now}")
    if len(lost) > 15:
        print(f"    …还有 {len(lost) - 15} 条")
    drop = _rate(base) - _rate(res)
    print(f"  复用率 {_rate(base):.1%} → {_rate(res):.1%}(变化 {-drop:+.1%})")
    if drop > 0.0:
        print("\n  ❌ **复用率下降 = 语料保全闸门不通过。**")
        print("     这类失败不会报错,只会让系统默默退回全量 LLM 研判 —— 必须查清再合。")
        print("     先看上面丢掉复用的那几条:是指纹不再命中(改动造成),还是图变了(漂移)?")
        return 1
    print("\n  ✅ 复用率未下降,语料保全闸门通过。")
    return 0


def check_corpus(exp_store) -> int:
    """经验库为空 ⇒ **当场停**,不许出基线。返回 0=可继续,2=停。

    ★首跑就栽在这:openGauss 连不上(5432 refused),`build_pipeline` 打了句 warn
      就降级成内存空库继续跑,于是吐出一份"复用率 0.0%"的基线 —— 看着像模像样。
      而拿 0% 当基线,之后**任何**改动都不会低于它 = 语料保全闸门变成**永远绿灯**。
      降级运行的结果比没有结果更危险,所以这里宁可什么都不给。
    """
    try:
        n = len(exp_store.all())
    except Exception as e:
        print(f"❌ 读不到经验库:{type(e).__name__}: {e}")
        return 2
    if n == 0:
        print("❌ **经验库是空的** —— 这份重放量不出任何东西(空库必然 100% FALLTHROUGH)。")
        print("   最常见原因:openGauss 没起来,pipeline 降级成了内存空库(上面应有 [warn] 行)。")
        print("   语料保全闸门的前提就是有语料;拿 0% 当基线 = 之后任何改动都通过,闸门形同虚设。")
        # ★这是**重启后必然复发**的一种失败(openGauss 那个 podman 容器没有重启策略),
        #   所以别只说"把它起来",直接给能粘贴的命令,连身份一起写清。
        print("   ★openGauss 是 **podman 容器**(rootful,soc 用户看不到它)。宿主机一重启它就")
        print("     停在 Exited(0) 不动 —— 这是连不上 5432 的头号原因,不用排查磁盘/OOM/配置。")
        print("     **以 root 身份**跑:  podman start opengauss && sleep 15 && ss -tln | grep 5432")
        print("     根治(免得下次重启再来一遍):")
        print("       podman update --restart=always opengauss")
        print("       systemctl enable --now podman-restart.service")
        return 2
    print(f"经验库:{n} 条经验")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=500, help="重放条数(计划要求 ≥500)")
    ap.add_argument("--save", help="把本次结果存成基线 JSON")
    ap.add_argument("--baseline", help="与这份基线对比;复用率下降则退出码 1")
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空 —— .env 没读到或没配。")
        return 2
    pl = build_pipeline(cfg)
    try:
        # ★经验库为空 ⇒ **当场停**,不许出基线。
        #   首跑就栽在这:openGauss 连不上(5432 refused),`build_pipeline` 打了句 warn
        #   就降级成内存空库继续跑,于是吐出一份"复用率 0.0%"的基线 —— 看着像模像样。
        #   而拿 0% 当基线,之后**任何**改动都不会低于它 = 语料保全闸门变成永远绿灯。
        #   降级运行的结果比没有结果更危险,所以这里宁可什么都不给。
        rc = check_corpus(pl.exp_store)
        if rc:
            return rc
        # ★零副作用:全程只有 collect_forensics(只读)与 consult(只读),
        #   不碰 write_result / sediment / snapshot_case。跑多少遍系统状态都不变。
        res = replay(pl, args.limit)
    finally:
        pl.close()
    base = None
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as f:
            base = json.load(f)
    rc = report(res, base)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=1)
        print(f"\n  基线已存:{args.save}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
