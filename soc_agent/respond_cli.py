"""respond CLI —— 分析师人审 gate:列待批计划、批准/驳回、请求回退。

人审是硬 gate:range-runner 只跑 status=approved 的计划;没人 approve 就永远不真做。
守卫失败(状态不符/计划不存在)→ 返回 False,绝不谎报成功。

用法(server2):
  python -m soc_agent.respond_cli list                 # 列待批(proposed)计划 + 步骤
  python -m soc_agent.respond_cli list --status executed
  python -m soc_agent.respond_cli approve <plan_id> [--by analyst]
  python -m soc_agent.respond_cli reject  <plan_id> [--reason ...]
  python -m soc_agent.respond_cli rollback <plan_id>   # 请求回退(executed → rollback_requested)
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from .config import Config
from .graph.client import Neo4jGraph
from .response import ledger
from .response.appliance_client import ApplianceClient


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lease(seconds=300):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _step_params(s):
    p = s.get("params")
    if isinstance(p, str):
        try:
            return json.loads(p)
        except Exception:
            return {}
    return p or {}


def _rw(graph, spec):
    c, p = spec
    return graph.run_write(c, **p)


def _rc(graph, spec):
    c, p = spec
    return graph.run_cypher(c, **p)


def run_plan(graph, client, plan_id, now, lease_until, runner_id="server2-respond"):
    """server2 直接经 appliance HTTP 执行一个 approved 计划(免去靶场跑 runner)。
    CAS 领取(approved→executing)→ 逐步 client.execute → 回写 status+rollback_handle → 计划终态。"""
    if not _rw(graph, ledger.q_claim(plan_id, runner_id, now, lease_until, "approved", "executing")):
        return {"ok": False, "error": "计划非 approved 或已被领取"}
    ok, steps = True, []
    for s in _rc(graph, ledger.q_plan_steps(plan_id)):
        res = client.execute(s.get("primitive"), _step_params(s))
        st = res.get("status")
        rh = res.get("rollback_handle")
        _rw(graph, ledger.q_record_step(
            plan_id, s.get("order"), st, res.get("execution_id"),
            json.dumps(rh, ensure_ascii=False) if rh else None, res.get("error"), now))
        steps.append({"order": s.get("order"), "primitive": s.get("primitive"),
                      "target": s.get("target"), "status": st, "error": res.get("error")})
        if st != "executed":
            ok = False
            break
    _rw(graph, ledger.q_finish_plan(plan_id, "executed" if ok else "failed", now))
    return {"ok": ok, "steps": steps}


def rollback_plan(graph, client, plan_id, now, lease_until, runner_id="server2-respond"):
    """server2 直接经 appliance HTTP 逆序回退一个 executed 计划。"""
    if not _rw(graph, ledger.q_claim(plan_id, runner_id, now, lease_until, "executed", "rolling_back")):
        return {"ok": False, "error": "计划非 executed 或已被领取"}
    ok, steps = True, []
    for s in _rc(graph, ledger.q_rollbackable_steps(plan_id)):     # 已逆序
        h = s.get("rollback_handle")
        h = json.loads(h) if isinstance(h, str) else h
        res = client.rollback(h or {})
        st = res.get("status")
        if st == "executed":
            _rw(graph, ledger.q_mark_step_rolled_back(plan_id, s.get("order"), now))
        steps.append({"order": s.get("order"), "status": st, "error": res.get("error")})
        if st != "executed":
            ok = False
            break
    _rw(graph, ledger.q_finish_plan(plan_id, "rolled_back" if ok else "rollback_failed", now))
    return {"ok": ok, "steps": steps}


def list_plans(graph, status="proposed"):
    """列某状态的计划,每个附带有序步骤(供人审查看)。"""
    c, p = ledger.q_list_plans(status)
    plans = graph.run_cypher(c, **p)
    for plan in plans:
        sc, sp = ledger.q_plan_steps(plan["plan_id"])
        plan["steps"] = graph.run_cypher(sc, **sp)
    return plans


def _write_true(graph, cypher, params):
    """执行守卫式状态转移;有行返回 = 转移成功。"""
    rows = graph.run_write(cypher, **params)
    return bool(rows)


def approve(graph, plan_id, approver, now):
    return _write_true(graph, *ledger.q_approve(plan_id, approver, now))


def reject(graph, plan_id, now, reason=None):
    return _write_true(graph, *ledger.q_reject(plan_id, now, reason))


def request_rollback(graph, plan_id, now):
    return _write_true(graph, *ledger.q_request_rollback(plan_id, now))


# ---- 展示 ----
def _fmt_step(s):
    tgt = s.get("target")
    params = s.get("params")
    try:
        params = json.loads(params) if isinstance(params, str) else params
    except Exception:
        pass
    return f"    {s.get('order')}. {s.get('primitive')}(target={tgt}, params={params}, risk={s.get('risk')})"


def _print_plans(plans):
    if not plans:
        print("(无)")
        return
    for pl in plans:
        print(f"● plan {pl['plan_id']}  status={pl.get('status')}  verdict={pl.get('verdict')}")
        if pl.get("rationale"):
            print(f"  依据: {pl['rationale']}")
        for s in sorted(pl.get("steps") or [], key=lambda x: x.get("order") or 0):
            print(_fmt_step(s))
        if pl.get("claimed_by"):
            print(f"  (已被 {pl['claimed_by']} 领取)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="respond", description="SOC 处置计划人审")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("list", help="列计划")
    pl.add_argument("--status", default="proposed")
    ap_a = sub.add_parser("approve", help="批准计划")
    ap_a.add_argument("plan_id")
    ap_a.add_argument("--by", default="analyst")
    ap_r = sub.add_parser("reject", help="驳回计划")
    ap_r.add_argument("plan_id")
    ap_r.add_argument("--reason", default=None)
    ap_e = sub.add_parser("execute", help="执行已批准计划(经 appliance HTTP,免去靶场跑 runner)")
    ap_e.add_argument("plan_id")
    ap_rb = sub.add_parser("rollback", help="回退已执行计划(appliance 直接回退;无 appliance 则挂 range-runner 意图)")
    ap_rb.add_argument("plan_id")
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=".env")
    client = ApplianceClient(cfg.response_url, cfg.response_token)
    graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        if args.cmd == "list":
            _print_plans(list_plans(graph, args.status))
        elif args.cmd == "approve":
            ok = approve(graph, args.plan_id, args.by, _now())
            print(f"{'✅ 已批准' if ok else '⚠️ 未变更(计划不存在或非 proposed)'}: {args.plan_id}")
            if ok and client.enabled:
                print(f"  执行:  python -m soc_agent.respond_cli execute {args.plan_id}")
            return 0 if ok else 1
        elif args.cmd == "reject":
            ok = reject(graph, args.plan_id, _now(), args.reason)
            print(f"{'已驳回' if ok else '⚠️ 未变更'}: {args.plan_id}")
            return 0 if ok else 1
        elif args.cmd == "execute":
            if not client.enabled:
                print("⚠️ 未配 RESPONSE_URL(处置面 appliance)。要么配上,要么走队列通道:靶场 `bash deploy/setup/60-response-run.sh`")
                return 1
            r = run_plan(graph, client, args.plan_id, _now(), _lease())
            if r.get("error"):
                print(f"⚠️ {r['error']}: {args.plan_id}")
                return 1
            for s in r["steps"]:
                print(f"  {s['order']}. {s['primitive']}→{s.get('target')} : {s['status']}"
                      + (f"  ({s['error']})" if s.get("error") else ""))
            print(f"{'✅ 执行完成' if r['ok'] else '⚠️ 部分失败(计划=failed)'}: {args.plan_id}")
            return 0 if r["ok"] else 1
        elif args.cmd == "rollback":
            if client.enabled:
                r = rollback_plan(graph, client, args.plan_id, _now(), _lease())
                if r.get("error"):
                    print(f"⚠️ {r['error']}: {args.plan_id}")
                    return 1
                for s in r["steps"]:
                    print(f"  step {s['order']}: {s['status']}" + (f"  ({s['error']})" if s.get("error") else ""))
                print(f"{'✅ 已回退' if r['ok'] else '⚠️ 回退部分失败'}: {args.plan_id}")
                return 0 if r["ok"] else 1
            ok = request_rollback(graph, args.plan_id, _now())
            print(f"{'已请求回退(等 range-runner 执行)' if ok else '⚠️ 未变更(需 executed 状态)'}: {args.plan_id}")
            return 0 if ok else 1
    finally:
        graph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
