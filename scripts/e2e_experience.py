"""server2 端到端:第二类经验闭环真机验证。

① 一条 kerberoast 告警走完整流水线(取证 → LLM 研判 →[TP 则组处置]→ 蒸馏 → 生死线考试 → 入 openGauss active)。
② 同一告警二次研判 → consult 命中经验 → path-A 自动结论 + 复用剧本(研判/处置 0 LLM,只剩 routing)。
③ 断言:经验库=openGauss(非内存降级)、沉淀出 active 经验、图台账出现 path=A、二次研判 LLM 调用骤降。

逐项 ✅/❌,末尾给通过数 + 退出码。跑前建议先 `bash scripts/reset_pristine.sh` 起干净态。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build_pipeline, run_pipeline
from soc_agent.config import Config

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
oks = []


def check(name, ok, detail=""):
    oks.append(bool(ok))
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ((" — " + detail) if detail else ""))


if not cfg.og_enabled:
    print("⛔ OG_HOST 未配 —— 先跑通 og_probe(建 openGauss 库/表)再来。")
    sys.exit(2)

pl = build_pipeline(cfg)
is_og = (pl.exp_store.store.__class__.__name__ == "OpenGaussExperienceStore")
check("经验库=openGauss(非内存降级)", is_og, "store=%s" % pl.exp_store.store.__class__.__name__)

# LLM 调用计数器(装在共享的 QwenClient 实例上;investigators/composer/router 都用它)
calls = {"n": 0}
_orig = pl.llm.chat


def _counting(*a, **k):
    calls["n"] += 1
    return _orig(*a, **k)


pl.llm.chat = _counting

try:
    rows = pl.graph.run_cypher(
        "MATCH (a:Alert) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) AND NOT (a)-[:CONCLUDED]->() "
        "RETURN a.alert_uid AS uid LIMIT 8")
    uids = [r["uid"] for r in rows]
    check("图里有未研判 kerberoast 告警", bool(uids), "候选 %d 条" % len(uids))

    sedimented_uid = None
    for uid in uids:
        before = len(pl.exp_store.active_for_skill("kerberoast"))
        calls["n"] = 0
        result, report, picked = run_pipeline(pl, uid, mode="recipe")
        pass1_calls = calls["n"]
        after = len(pl.exp_store.active_for_skill("kerberoast"))
        print("  · pass1 %s: decision=%s verdict=%s LLM=%d exp:%d→%d"
              % (uid[:10], report.decision, result.verdict.verdict if result.verdict else None,
                 pass1_calls, before, after))
        if after > before:                       # 完整研判后沉淀出经验
            sedimented_uid = uid
            break
    check("完整研判后沉淀出 active 经验(入 openGauss)", sedimented_uid is not None,
          "uid=%s" % (sedimented_uid[:10] if sedimented_uid else "无(候选都 suspicious?换更多候选)"))

    if sedimented_uid:
        calls["n"] = 0
        result2, report2, picked2 = run_pipeline(pl, sedimented_uid, mode="recipe")
        pass2_calls = calls["n"]
        print("  · pass2 %s: decision=%s path=%s LLM=%d"
              % (sedimented_uid[:10], report2.decision, result2.path, pass2_calls))
        check("二次研判命中经验(AUTO_*)", report2.decision in ("AUTO_TP", "AUTO_FP"),
              "decision=%s" % report2.decision)
        check("二次研判走快路径 path=A", result2.path == "A", "path=%s" % result2.path)
        check("二次研判 LLM 骤降(≤routing 1 次,研判/处置 0)", pass2_calls <= 1,
              "pass2 LLM=%d" % pass2_calls)
        pa = pl.graph.run_cypher(
            "MATCH (a:Alert {alert_uid:$u})-[c:CONCLUDED]->() WHERE c.path='A' RETURN count(c) AS n",
            u=sedimented_uid)[0]["n"]
        check("图台账出现 path=A 的 CONCLUDED", pa >= 1, "path=A 边=%d" % pa)

    act = pl.exp_store.active_for_skill("kerberoast")
    check("openGauss 有 active kerberoast 经验", len(act) >= 1,
          "active=%d kinds=%s" % (len(act), [e.kind for e in act]))
finally:
    pl.close()

n, k = len(oks), sum(oks)
print("\n=== E2E-EXPERIENCE: %d/%d 通过 %s ===" % (k, n, "" if k == n else "★有失败,见上"))
sys.exit(0 if k == n else 1)
