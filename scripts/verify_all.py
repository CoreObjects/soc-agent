"""验证回退后【所有保留功能】在真机可用:处置面连通 + 护栏派生 + 慢研判端到端 + 第三类图台账。

在 server2 跑(有 .env)。会真研判 2-3 条告警(出 verdict + 写 per-alert 台账,系统正常行为);
处置只验【连通】(health),不动靶场。逐项打 ✅/❌,末尾给通过数 + 退出码。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent.cli import build, choose_investigator, investigate_alert
from soc_agent.config import Config
from soc_agent.disposition import policy_from_graph
from soc_agent.graph.client import build_constraints
from soc_agent.models import Alert
from soc_agent.response.appliance_client import ApplianceClient

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
oks = []


def check(name, ok, detail=""):
    oks.append(bool(ok))
    print(("  [PASS] " if ok else "  [FAIL] ") + name + (("  — " + detail) if detail else ""))


# A. 处置面 appliance 连通(执行子系统;dry,不动靶场)
try:
    client = ApplianceClient(cfg.response_url, cfg.response_token)
    if not client.enabled:
        check("处置面 appliance 连通", False, "未配 RESPONSE_URL")
    else:
        h = client.health()
        check("处置面 appliance 连通(执行子系统)", True, "dry_run=%s" % h.get("dry_run"))
except Exception as e:
    check("处置面 appliance 连通", False, "连不上: %s" % str(e)[:90])

graph, router, agent_inv, recipe_inv = build(cfg)
try:
    # B. 护栏策略从图派生(DC/CA NEVER-TOUCH)
    try:
        pol = policy_from_graph(graph)
        check("护栏策略从图派生", isinstance(pol, dict),
              "protected_hosts=%d protected_accounts=%d"
              % (len(pol.get("protected_hosts") or []), len(pol.get("protected_accounts") or [])))
    except Exception as e:
        check("护栏策略从图派生", False, str(e)[:90])

    # C. 慢研判端到端(挑真告警 → 出 verdict → 写 per-alert 台账);覆盖 router + 两种研判器 + 两类 skill
    runs = [("T1558.003", "kerberoast", "recipe"),
            ("T1003.001", "lsass_dump", "recipe"),
            ("T1558.003", "kerberoast", "auto")]     # auto = AgentInvestigator 自主循环
    done = set()
    for tech, label, mode in runs:
        rows = graph.run_cypher(
            "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND $t IN coalesce(a.technique_ids,[]) "
            "AND NOT a.alert_uid IN $done RETURN a.alert_uid AS uid LIMIT 1", t=tech, done=list(done))
        if not rows:
            check("慢研判 %s[%s]" % (label, mode), False, "图里无未研判 %s 告警" % tech)
            continue
        uid = rows[0]["uid"]
        done.add(uid)
        try:
            node = graph.get_alert(uid)
            alert = Alert.from_node(node)
            seed = graph.seed(alert)
            skill = router.route(alert, seed)
            inv, picked = choose_investigator(skill, mode, agent_inv, recipe_inv)
            result = investigate_alert(graph, inv, uid, skill)   # 内含 write_result(写台账)
        except Exception as e:
            check("慢研判 %s[%s] (%s)" % (label, mode, uid[:10]), False, "异常: %s" % str(e)[:100])
            continue
        v = result.verdict
        ok = v is not None and v.verdict in ("true_positive", "false_positive", "benign", "suspicious")
        check("慢研判 %s[%s→%s] (%s)" % (label, mode, picked, uid[:10]), ok,
              "skill=%s verdict=%s" % (getattr(skill, "name", None), v.verdict if v else None))
        # 第三类台账:per-alert CONCLUDED→Verdict(verdict_id、无 pattern_id)+ LED_TO 闭环
        t = graph.run_cypher(
            "MATCH (a:Alert {alert_uid:$u})-[:CONCLUDED]->(v:Verdict) "
            "OPTIONAL MATCH (v)-[:LED_TO]->(x) "
            "RETURN v.verdict_id AS vid, v.verdict AS verd, v.pattern_id AS pid, "
            "collect(DISTINCT coalesce(x.step_key, labels(x)[0]))[0..3] AS led", u=uid)
        r = t[0] if t else {}
        tok = bool(r.get("vid")) and r.get("pid") is None and bool(r.get("led"))
        check("  ↳ 第三类台账(verdict_id、无 pattern_id、LED_TO 闭环)", tok,
              "vid=%s verd=%s pid=%s led=%s" % ((r.get("vid") or "")[:8], r.get("verd"), r.get("pid"), r.get("led")))
finally:
    graph.close()

# D. 台账约束:有 verdict_id/plan_id/step_key、无第二类 pattern_id 收敛键
cs = " ".join(build_constraints())
check("台账约束(verdict_id/plan_id/step_key,无 pattern_id)",
      "v.verdict_id IS UNIQUE" in cs and "p.plan_id IS UNIQUE" in cs
      and "d.step_key IS UNIQUE" in cs and "pattern_id" not in cs)

n, k = len(oks), sum(oks)
print("\n=== VERIFY-ALL: %d/%d 通过 %s ===" % (k, n, "" if k == n else "★有失败,见上"))
sys.exit(0 if k == n else 1)
