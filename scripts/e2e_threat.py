"""server2:第二类经验【威胁分支】真机验证。

前置:① GOAD 上先跑 `deploy/setup/42-kerberoast-user.sh`(普通用户 jon.snow 域内 roast → 造 TP 告警)
      ② 等 ingest 把告警入图 ③ 建议先 `bash scripts/reset_pristine.sh`(清空经验/案例,让 pass1 考试无干扰)。

① 找一条请求者=jon.snow(普通用户/域内)的未研判 kerberoast 告警 → pass1 完整研判 → 期望判 TP →
   蒸出【威胁指纹 + DSL 规则 + 处置剧本】入 openGauss active。
② 同告警 pass2 → consult 威胁双门(指纹∧规则)命中 → AUTO_TP、path=A、复用剧本组处置(proposed)、研判/处置 0 LLM。
断言逐项 ✅/❌,末尾通过数 + 退出码。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build_pipeline, run_pipeline
from soc_agent.config import Config

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
REQ = os.environ.get("THREAT_REQ", "jon.snow")           # 目标请求者(普通用户;可用环境变量换)
oks = []


def check(name, ok, detail=""):
    oks.append(bool(ok))
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ((" — " + detail) if detail else ""))


if not cfg.og_enabled:
    print("⛔ OG_HOST 未配 —— 先跑通 og_probe 再来。")
    sys.exit(2)

pl = build_pipeline(cfg)
check("经验库=openGauss(非内存降级)", pl.exp_store.store.__class__.__name__ == "OpenGaussExperienceStore",
      "store=%s" % pl.exp_store.store.__class__.__name__)

calls = {"n": 0}
_orig = pl.llm.chat


def _counting(*a, **k):
    calls["n"] += 1
    return _orig(*a, **k)


pl.llm.chat = _counting

try:
    rows = pl.graph.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) AND NOT (a)-[:CONCLUDED]->() AND req.sam=$req "
        "RETURN DISTINCT a.alert_uid AS uid LIMIT 5", req=REQ)
    uids = [r["uid"] for r in rows]
    check("找到请求者=%s 的未研判 kerberoast 告警" % REQ, bool(uids),
          "候选 %d(无?先在 GOAD 跑 42-kerberoast-user.sh 并等 ingest)" % len(uids))

    threat_uid = None
    for uid in uids:
        before = len(pl.exp_store.by_kind("kerberoast", "threat"))
        calls["n"] = 0
        result, report, picked = run_pipeline(pl, uid, mode="recipe")
        after = len(pl.exp_store.by_kind("kerberoast", "threat"))
        print("  · pass1 %s: decision=%s verdict=%s dispositions=%d threat经验:%d→%d LLM=%d"
              % (uid[:10], report.decision, result.verdict.verdict if result.verdict else None,
                 len(result.dispositions or []), before, after, calls["n"]))
        if after > before:
            threat_uid = uid
            check("pass1 判 TP 并蒸出威胁经验", result.verdict.verdict == "true_positive",
                  "verdict=%s" % result.verdict.verdict)
            check("pass1 组了处置剧本(Composer 挑原语绑 attacker_account)", bool(result.dispositions),
                  "steps=%d actions=%s" % (len(result.dispositions or []),
                                           [d.action for d in (result.dispositions or [])]))
            break

    if threat_uid is None:
        check("完整研判后蒸出威胁经验", False, "候选都没判 TP(qwen 判 FP/suspicious?看上面 pass1 verdict)")
    else:
        te = [e for e in pl.exp_store.by_kind("kerberoast", "threat")][0]
        check("威胁经验带 DSL 规则", te.rule is not None, "rule=%s" % (str(te.rule)[:70]))
        check("威胁经验带处置剧本模板", bool(te.playbook), "steps=%d" % len(te.playbook or []))

        calls["n"] = 0
        r2, rep2, _ = run_pipeline(pl, threat_uid, mode="recipe")
        print("  · pass2 %s: decision=%s path=%s dispositions=%d LLM=%d"
              % (threat_uid[:10], rep2.decision, r2.path, len(r2.dispositions or []), calls["n"]))
        check("pass2 威胁双门命中 → AUTO_TP", rep2.decision == "AUTO_TP", "decision=%s" % rep2.decision)
        check("pass2 走快路径 path=A", r2.path == "A", "path=%s" % r2.path)
        check("pass2 复用剧本组出处置(proposed)", bool(r2.dispositions),
              "dispositions=%d" % len(r2.dispositions or []))
        check("pass2 研判/处置 0 LLM(≤routing 1 次)", calls["n"] <= 1, "LLM=%d" % calls["n"])
        pa = pl.graph.run_cypher(
            "MATCH (a:Alert {alert_uid:$u})-[c:CONCLUDED]->() WHERE c.path='A' RETURN count(c) AS n",
            u=threat_uid)[0]["n"]
        check("图台账出现 path=A 的 CONCLUDED", pa >= 1, "path=A 边=%d" % pa)
        rp = pl.graph.run_cypher(
            "MATCH (a:Alert {alert_uid:$u})-[:CONCLUDED]->(:Verdict)-[:LED_TO]->(:ResponsePlan)-[:STEP]->(d:Disposition) "
            "RETURN count(d) AS n", u=threat_uid)[0]["n"]
        check("台账写了处置计划(proposed,待 respond_cli 人审)", rp >= 1, "disposition 台账=%d" % rp)
finally:
    pl.close()

n, k = len(oks), sum(oks)
print("\n=== E2E-THREAT: %d/%d 通过 %s ===" % (k, n, "" if k == n else "★有失败,见上"))
sys.exit(0 if k == n else 1)
