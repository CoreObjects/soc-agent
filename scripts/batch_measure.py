"""真告警批量定量验:经验层"越用越省"—— 沉淀行数(收敛)vs AUTO 命中率 vs LLM 节省。

在 reset 后的干净态上,按到达序回放一批未研判告警,逐条走 run_pipeline
(取证 → 经验比对 → AUTO 复用 / FALLTHROUGH 研判+沉淀)。度量:
- 研判(FALLTHROUGH)vs 复用(AUTO_TP/AUTO_FP)条数、AUTO 命中率;
- 沉淀经验行数(= 学到的模式数,应随规模**收敛**、非线性增长);
- LLM 调用:实际 vs "若每条都研判"的基线 → 节省%。
逐条打印"累计 AUTO 率"曲线(收敛可见)。

★会写台账 + 沉淀经验(真跑),先 `bash scripts/reset_pristine.sh` 起干净态。
★FALLTHROUGH 每条约 4 次 LLM(9b 每次 ~40s);限流条数控制时长。

用法: bash scripts/batch_measure.sh [条数=20] [--tech T1558.003]
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build_pipeline, run_pipeline
from soc_agent.config import Config

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))

argv = sys.argv[1:]
tech = None
if "--tech" in argv:
    i = argv.index("--tech")
    tech = argv[i + 1]
    del argv[i:i + 2]
limit = int(argv[0]) if argv else 20

if not cfg.og_enabled:
    print("⛔ OG_HOST 未配 —— 先跑通 og_probe 再来。")
    sys.exit(2)

pl = build_pipeline(cfg)
if pl.exp_store.store.__class__.__name__ != "OpenGaussExperienceStore":
    print("⛔ 经验库降级为内存(OG 连不上)—— 量测无意义,先修 openGauss。")
    sys.exit(2)

calls = {"n": 0}
_orig = pl.llm.chat


def _counting(*a, **k):
    calls["n"] += 1
    return _orig(*a, **k)


pl.llm.chat = _counting


def exp_rows():
    return len(pl.exp_store.all())


where = "WHERE NOT (a)-[:CONCLUDED]->() "
params = {"n": limit}
if tech:
    where += "AND $tech IN coalesce(a.technique_ids,[]) "
    params["tech"] = tech
rows = pl.graph.run_cypher(
    "MATCH (a:Alert) " + where
    + "RETURN a.alert_uid AS uid, coalesce(a.technique_ids,['(none)'])[0] AS tech "
      "ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT $n", **params)

scope = ("tech=%s" % tech) if tech else "全类"
print("# 批量定量验:%d 条未研判告警(到达序回放,%s)  起始沉淀行=%d\n" % (len(rows), scope, exp_rows()))

stats = {"FALLTHROUGH": 0, "AUTO_TP": 0, "AUTO_FP": 0}
per_tech = {}            # tech -> [总, 研判, 复用]
ft_llm = []              # FALLTHROUGH 各条 LLM 次数(算基线单价)
# FALLTHROUGH 分诊:verdict × 是否沉淀 —— 看 tail 到底是"存疑不沉淀(正常)"还是"该沉淀却被 exam 拒"
ft_break = {}            # (verdict, sedimented?) -> 计数
llm_total = 0
try:
    for i, r in enumerate(rows, 1):
        uid, t = r["uid"], r["tech"]
        calls["n"] = 0
        before = exp_rows()
        try:
            _res, report, _picked = run_pipeline(pl, uid, mode="recipe")
        except Exception as e:
            print("  [%3d] %-16s ERROR %s" % (i, t[:16], str(e)[:70]))
            continue
        c = calls["n"]
        llm_total += c
        d = report.decision
        after = exp_rows()
        vd = _res.verdict.verdict if _res.verdict else "(none)"
        sed = after > before
        stats[d] = stats.get(d, 0) + 1
        pt = per_tech.setdefault(t, [0, 0, 0])
        pt[0] += 1
        if d == "FALLTHROUGH":
            pt[1] += 1
            ft_llm.append(c)
            key = (vd, "沉淀" if sed else "未沉淀")
            ft_break[key] = ft_break.get(key, 0) + 1
        else:
            pt[2] += 1
        auto = stats["AUTO_TP"] + stats["AUTO_FP"]
        print("  [%3d] %-16s %-12s verdict=%-14s %s LLM=%d  沉淀行=%d  累计AUTO率=%.0f%%"
              % (i, t[:16], d, vd, ("沉淀+1" if sed else "     "), c, exp_rows(), 100.0 * auto / i))

    N = len(rows)
    F = stats["FALLTHROUGH"]
    A = stats["AUTO_TP"] + stats["AUTO_FP"]
    R = exp_rows()
    avg_ft = (sum(ft_llm) / len(ft_llm)) if ft_llm else 0.0
    baseline = N * avg_ft                                   # 若每条都研判(无经验复用)
    saved = (1 - llm_total / baseline) * 100 if baseline else 0.0
    print("\n=== 汇总 ===")
    print("总告警 %d | 研判(FALLTHROUGH) %d | 复用(AUTO_TP %d + AUTO_FP %d = %d) | AUTO命中率 %.0f%%"
          % (N, F, stats["AUTO_TP"], stats["AUTO_FP"], A, 100.0 * A / N if N else 0))
    print("沉淀经验行数 %d(= 学到的模式数;收敛比 R/N=%.2f,越小越省)" % (R, R / N if N else 0))
    print("LLM 调用:实际 %d | 全研判基线 %d(=%d×%.1f) | 节省 %.0f%%"
          % (llm_total, round(baseline), N, avg_ft, saved))
    print("\n各技战术(总/研判/复用):")
    for t, (n, f, a) in sorted(per_tech.items(), key=lambda x: -x[1][0]):
        print("  %-16s 共%-4d 研判%-4d 复用%-4d AUTO率%.0f%%" % (t[:16], n, f, a, 100.0 * a / n if n else 0))
    print("\nFALLTHROUGH 分诊(verdict × 是否沉淀 —— suspicious/未沉淀=存疑正常;TP/FP+未沉淀=被 exam 拒,该查):")
    for (vd, sd), n in sorted(ft_break.items(), key=lambda x: -x[1]):
        print("  verdict=%-14s %-6s × %d" % (vd, sd, n))
finally:
    pl.close()
print("\n# done")
