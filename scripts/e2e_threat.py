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
    # 宽松匹配请求者(ingest 可能存 jon.snow / jon.snow@NORTH... / NORTH\jon.snow)
    rows = pl.graph.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) AND NOT (a)-[:CONCLUDED]->() "
        "AND toLower(req.sam) CONTAINS toLower($req) "
        "RETURN DISTINCT a.alert_uid AS uid, req.sam AS req_sam, req.domain AS req_domain LIMIT 5", req=REQ)
    uids = [r["uid"] for r in rows]
    check("找到请求者含 %s 的未研判 kerberoast 告警" % REQ, bool(uids),
          "候选 %d %s" % (len(uids), [(r["req_sam"], r["req_domain"]) for r in rows]))
    if not uids:
        # 诊断:看看图里未研判 T1558.003 告警的请求者都长啥样(判断是 ingest 没跑 / 还是 sam 形态不同)
        diag = pl.graph.run_cypher(
            "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
            "WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) AND NOT (a)-[:CONCLUDED]->() "
            "RETURN req.sam AS sam, req.domain AS dom, count(*) AS n ORDER BY n DESC LIMIT 10")
        print("  ↳ 诊断:未研判 kerberoast 请求者样本 = %s" % [(d["sam"], d["dom"], d["n"]) for d in diag])

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

        # ── Fix 2 真机验证:按 VID(=命中经验 origin_case_id)从图台账捞回原始上下文 ──
        # 证真 Cypher 对真 schema 生效(★summary/rationale 在 CONCLUDED 边;处置形状;__no_op__ 过滤)。
        led = pl.graph.recall_ledger(threat_uid)
        check("recall_ledger 按 VID 捞回台账", led is not None,
              "keys=%s" % (sorted(led.keys()) if led else None))
        if led:
            check("台账含 Verdict 结论", led.get("verdict") == "true_positive",
                  "verdict=%s" % led.get("verdict"))
            check("台账含结论理由(★取自 CONCLUDED 边)", bool(led.get("summary") or led.get("rationale")),
                  "summary=%s" % (str(led.get("summary"))[:60]))
            check("台账含真处置(非 __no_op__)", bool(led.get("dispositions")),
                  "disp=%s" % [d.get("action") for d in (led.get("dispositions") or [])])
        # 证真 Experience 带来源 VID + note 列 round-trip(note 迁移列真机可读)
        te2 = [e for e in pl.exp_store.by_kind("kerberoast", "threat")][0]
        check("威胁经验存了来源告警 VID(origin_case_id)", bool(te2.origin_case_id),
              "origin_case_id=%s" % te2.origin_case_id)
        check("openGauss note 列可读(round-trip 不报错)", hasattr(te2, "note"),
              "note=%s" % (str(te2.note)[:40] if te2.note else None))
finally:
    pl.close()

n, k = len(oks), sum(oks)
print("\n=== E2E-THREAT: %d/%d 通过 %s ===" % (k, n, "" if k == n else "★有失败,见上"))
sys.exit(0 if k == n else 1)
