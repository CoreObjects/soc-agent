"""Phase 1 E2E(agent 侧):找候选 TP kerberoast 告警 → 逐个研判(快慢通道+composer)→
列台账里待审(proposed)的响应计划。由 e2e_response.sh 跑 + push feedback。

候选 = 非机器账号($ 结尾)请求者的 kerberoast 告警(更可能被判 TP、触发 composer 组处置)。
FP(机器账号跨域引荐)不组处置,是对的 —— 所以专挑普通用户的取票告警。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.cli import build_orchestrator, run_investigation
from soc_agent.response import ledger

MAX_TRY = int(os.environ.get("E2E_MAX_TRY", "8"))     # 最多试几条
STOP_AFTER = int(os.environ.get("E2E_STOP_AFTER", "2"))  # 出几个带计划的 TP 就停

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("neo4j=%s og=%s enabled=%s llm=%s" % (cfg.neo4j_uri, cfg.og_host, cfg.og_enabled, cfg.llm_api_base))
graph, orch, repo = build_orchestrator(cfg)
try:
    cand = graph.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "WHERE 'T1558.003' IN a.technique_ids AND NOT coalesce(req.sam,'') ENDS WITH '$' "
        "RETURN DISTINCT a.alert_uid AS uid, req.sam AS requester LIMIT 25")
    print("候选(非机器账号请求者)kerberoast 告警: %d" % len(cand))
    plans_made = 0
    for c in cand[:MAX_TRY]:
        r = run_investigation(graph, orch, c["uid"])
        v = r.verdict
        disp = ", ".join("%s→%s" % (d.action, d.target) for d in (r.dispositions or [])) or "无"
        print("  [%s] req=%s path=%s → %s (conf=%.2f) 处置: %s"
              % (c["uid"][:12], c["requester"], r.path, v.verdict if v else "?",
                 v.confidence if v else 0, disp))
        if v and v.verdict == "true_positive" and r.dispositions:
            plans_made += 1
            if plans_made >= STOP_AFTER:
                break

    print("\n=== 台账待审(proposed)响应计划 ===")
    lc, lp = ledger.q_list_plans("proposed")
    plans = graph.run_cypher(lc, **lp)
    if not plans:
        print("(无)——上面若全是 FP/suspicious 则正常;需要一条被判 TP 的普通用户扫票告警")
    for pl in plans:
        print("● plan %s  verdict=%s" % (pl["plan_id"], pl.get("verdict")))
        if pl.get("rationale"):
            print("  依据: %s" % (pl["rationale"] or "")[:160])
        sc, sp = ledger.q_plan_steps(pl["plan_id"])
        for s in sorted(graph.run_cypher(sc, **sp), key=lambda x: x.get("order") or 0):
            print("    %s. %s  target=%s  params=%s  risk=%s"
                  % (s.get("order"), s.get("primitive"), s.get("target"), s.get("params"), s.get("risk")))
    print("\n下一步:server2 上 `.venv/bin/python -m soc_agent.respond_cli approve <plan_id>` 批准,"
          "再到靶场那台 `bash deploy/setup/60-response-run.sh` 执行。")
finally:
    graph.close()
