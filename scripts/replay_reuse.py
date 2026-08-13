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

# ★★按 skill **分层**抽样,不是按 uid 取前 N。
#
# 首跑的教训:取前 200 条,结果全落在 lateral_movement(159)+dcsync(41)两个 skill 上,
# 而 WP10 要改的是 c2_beacon / webshell / suspicious_process 等**六条 recipe 的谓词** ——
# 这批样本里**一条都没有**。于是我改坏 c2_beacon 的指纹,闸门照样 98.5% 绿灯放行。
# **一个对被改对象无覆盖的闸门,等于没有闸门。**
# (同样的错 WP7 的 pivot 闸门也犯过一次:样本没落在要断言的那条分支上。)
#
# 每个 skill 各取 `per_skill` 条,uid 定序保证基线/候选是同一批。
_PICK = """
MATCH (a:Alert)-[:CONCLUDED]->(:Verdict)
MATCH (a)-[:HAS_FINDING]->(f:Finding)
WITH a, head(collect(DISTINCT f.skill)) AS skill
WHERE skill IS NOT NULL
WITH skill, a.alert_uid AS uid ORDER BY uid
WITH skill, collect(uid) AS uids
RETURN skill, size(uids) AS total, uids[0..$per] AS picked
ORDER BY skill
"""


def replay(pl, per_skill_cap, registry_names=(), fixed_sample=None):
    sig = coverage.get(pl.graph).signature
    if fixed_sample:
        # ★--compare 走这里:**原样重放基线那一批告警**,不重新抽样。
        #   否则基线与候选是两个不同的总体,复用率一升一降都无从解释
        #   (真机首跑就撞上:基线 PER_SKILL=30/145 条 vs 候选默认 60/265 条,
        #    率从 58.6% 升到 62.3%,纯粹是多抽的样本里高复用 skill 占比更大;
        #    而"翻转 0 条"也是假的 —— 多出来的 120 条根本没参与比对)。
        rows = [{"uid": u, "skill": sk} for u, sk in sorted(fixed_sample.items())]
        have, strata, blind = {}, [], []
        print(f"--- 原样重放基线样本({len(rows)} 条,不重新抽样)---")
        print()
    else:
        strata = pl.graph.run_cypher(_PICK, per=int(per_skill_cap))
        have = {r["skill"]: int(r["total"]) for r in strata}
        rows = [{"uid": u, "skill": r["skill"]} for r in strata for u in (r["picked"] or [])]
        print(f"--- 分层抽样(每 skill 最多 {per_skill_cap} 条)---")
        for r in strata:
            print(f"  {r['skill']:<24} 已研判 {r['total']:>5} 条 → 抽 {len(r['picked'] or [])}")
        # ★把**闸门盖不到的 skill** 明说出来:它们没有已研判语料,这个闸门对它们零保护。
        blind = sorted(set(registry_names or ()) - set(have))
        if blind:
            print(f"  ⚠ **闸门盖不到**(无已研判语料,改动它们不会被这个闸门发现):{', '.join(blind)}")
        print(f"  合计 {len(rows)} 条")
        print()
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
            "per_alert": per_alert, "available": have, "uncovered": blind,
            # ★把"这一批到底是哪些告警"钉进基线 —— --compare 时原样重放它,
            #   而不是按参数重新抽一遍(见 main 里的说明)。
            "sample": {r["uid"]: r["skill"] for r in rows}}


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
    ap.add_argument("--per-skill", type=int, default=60,
                    help="每个 skill 最多抽几条(★分层抽样;别用总数封顶,否则大头 skill 会吃满配额)")
    ap.add_argument("--save", help="把本次结果存成基线 JSON")
    ap.add_argument("--baseline", help="与这份基线对比;复用率下降则退出码 1")
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空 —— .env 没读到或没配。")
        return 2

    # ★对比模式下**先把基线读进来**,并用它钉死样本 —— 基线与候选必须是同一批告警。
    #   真机首跑就栽在这:基线 PER_SKILL=30(145 条)、候选用了默认 60(265 条),
    #   复用率 58.6%→62.3% 看着像"变好了",其实只是多抽的样本里高复用 skill 占比更大;
    #   而"翻转 0 条"更是假的 —— 多出来的 120 条压根没参与比对。
    #   **跨样本集的对比会给出一个自信的错数字**,比不比更糟。
    base = None
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as f:
            base = json.load(f)
        if not base.get("sample"):
            print("❌ 这份基线是**旧格式**(没记下它抽了哪些告警),无法保证同批对比。")
            print("   重新出一份基线再来:bash scripts/replay-reuse.sh")
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
        names = [x.name for x in pl.router.registry.all()]
        res = replay(pl, args.per_skill, registry_names=names,
                     fixed_sample=(base or {}).get("sample"))
    finally:
        pl.close()
    rc = report(res, base)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=1)
        print(f"\n  基线已存:{args.save}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
