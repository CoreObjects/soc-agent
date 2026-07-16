"""Phase 1 全闭环(经 HTTP appliance,全在 server2):
找TP kerberoast → 研判组计划 → approve → execute(HTTP真做/DRY干跑)→ 验台账(executed+rollback_handle)
→ rollback(HTTP)→ 验台账(rolled_back)。由 e2e_full.sh 跑 + push feedback。

DRY(appliance --dry-run)下:机制全跑通但不碰真机,零风险验管道;切真做只需靶场重起服务去掉 DRY。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent import respond_cli
from soc_agent.cli import build_orchestrator, run_investigation
from soc_agent.config import Config
from soc_agent.response import ledger
from soc_agent.response.appliance_client import ApplianceClient

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
client = ApplianceClient(cfg.response_url, cfg.response_token)
if not client.enabled:
    print("⛔ 未配 RESPONSE_URL(处置面 appliance)—— 在 ~/soc-agent/.env 配 RESPONSE_URL/RESPONSE_TOKEN")
    sys.exit(1)
try:
    h = client.health()
    print("appliance health: %s  (dry_run=%s)" % (h, h.get("dry_run")))
except Exception as e:
    print("⛔ 连不上 appliance:%s(检查 RESPONSE_URL/端口放行/--noproxy)" % e)
    sys.exit(1)


def _steps(graph, pid):
    c, p = ledger.q_plan_steps(pid)
    return sorted(graph.run_cypher(c, **p), key=lambda x: x.get("order") or 0)


graph, orch, repo = build_orchestrator(cfg)
try:
    # 保护账号(禁了会瘫靶场/无意义)—— demo 优先挑非保护账号的请求者,好看到完整 disable+回退
    PROTECTED = {"vagrant", "krbtgt", "administrator", "domain admins", "enterprise admins"}
    cand = graph.run_cypher(
        "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "WHERE 'T1558.003' IN a.technique_ids AND NOT coalesce(req.sam,'') ENDS WITH '$' "
        "RETURN DISTINCT a.alert_uid AS uid, req.sam AS requester LIMIT 60")
    from collections import Counter
    reqs = Counter((c["requester"] or "?") for c in cand)
    print("候选(非机器账号请求者)kerberoast: %d;请求者分布: %s" % (len(cand), dict(reqs)))
    # 非保护账号排前面,优先investigate
    cand.sort(key=lambda c: (c["requester"] or "").lower() in PROTECTED)
    plan_id = None
    tp_protected = None
    for c in cand[:12]:
        r = run_investigation(graph, orch, c["uid"])
        v = r.verdict
        disp = ", ".join("%s→%s" % (d.action, d.target) for d in (r.dispositions or [])) or "无"
        print("  [%s] req=%s → %s 处置:%s" % (c["uid"][:12], c["requester"],
                                              v.verdict if v else "?", disp))
        if v and v.verdict == "true_positive" and r.dispositions:
            if (c["requester"] or "").lower() not in PROTECTED:
                plan_id = c["uid"]
                break                                    # 非保护账号的 TP:能看到完整 disable
            tp_protected = tp_protected or c["uid"]      # 保护账号 TP:兜底(展示服务端护栏拦截)
    plan_id = plan_id or tp_protected
    if not plan_id:
        print("\n没找到 TP+计划的告警(这批可能都是机器账号跨域票=FP)。")
        sys.exit(0)

    print("\n=== TP 计划 plan_id=%s ===" % plan_id)
    for s in _steps(graph, plan_id):
        print("  %s. %s target=%s params=%s" % (s.get("order"), s.get("primitive"),
                                                s.get("target"), s.get("params")))

    now, lease = respond_cli._now(), respond_cli._lease()
    print("\n[approve]", "OK" if respond_cli.approve(graph, plan_id, "e2e", now) else "失败")

    print("[execute] 经 appliance 逐步执行:")
    res = respond_cli.run_plan(graph, client, plan_id, respond_cli._now(), respond_cli._lease())
    for s in res.get("steps", []):
        print("    %s. %s→%s : %s %s" % (s["order"], s["primitive"], s.get("target"),
                                         s["status"], s.get("error") or ""))
    print("  → 计划 %s" % ("executed" if res.get("ok") else "failed"))

    print("[验台账] 执行后每步:")
    for s in _steps(graph, plan_id):
        print("    %s. %s status=%s execution_id=%s handle=%s" % (
            s.get("order"), s.get("primitive"), s.get("status"),
            s.get("rollback_handle") and "有", s.get("rollback_handle")))

    print("[rollback] 经 appliance 逆序回退:")
    rb = respond_cli.rollback_plan(graph, client, plan_id, respond_cli._now(), respond_cli._lease())
    if rb.get("error"):
        print("    %s" % rb["error"])
    for s in rb.get("steps", []):
        print("    step %s : %s %s" % (s["order"], s["status"], s.get("error") or ""))
    print("  → 计划 %s" % ("rolled_back" if rb.get("ok") else "rollback_failed"))

    print("[验台账] 回退后每步:")
    for s in _steps(graph, plan_id):
        print("    %s. %s status=%s" % (s.get("order"), s.get("primitive"), s.get("status")))
    print("\n闭环走完。DRY 下机制通=可切真做(靶场重起服务去掉 DRY);真做后清理用 `bash scripts/reset_pristine.sh`。")
finally:
    graph.close()
