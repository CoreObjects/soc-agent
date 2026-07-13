"""处置层 · P5a 提议时护栏(不真做,只把提议整成安全的)。

三件事:
  ① NEVER-TOUCH 硬拒:传感器进程(security_agent)、受保护主机(DC/网关,config)、
     受保护账号(krbtgt/Domain Admins 等)—— 命中 → 降级为 escalate(交人工),绝不自伤。
  ② 目标类型解析:action 与 target 类型必须匹配(isolate_host 要主机、kill_process 要进程…),
     明显不符(如 isolate_host 目标是文件路径)→ 降级为 escalate。
  ③ 高危 gated / 低危 auto 分级 + 审计。
真执行(真做/模拟/回退)是 P5b,需 server2 可触达控制面,另做。纯逻辑,可单测。
"""
import os
import re

from ..models import Disposition
from ..recipe_lib import security_agent

__all__ = ["apply_guardrail", "default_policy", "policy_from_graph", "GATED_ACTIONS"]

# 高危(需人工确认才可执行)vs 低危/无操作(可自动)
GATED_ACTIONS = {"disable_account", "isolate_host", "kill_process", "block_ip",
                 "reset_password", "revoke_sessions", "quarantine_file"}

# action → 期望目标实体类型
_EXPECT = {
    "isolate_host": "host", "kill_process": "process", "quarantine_file": "file",
    "disable_account": "account", "reset_password": "account", "revoke_sessions": "account",
    "block_ip": "ip",
}
# 会作用到"进程/主机/文件"的动作 —— 只对这些查传感器 NEVER-TOUCH
_TOUCHES_ENDPOINT = {"kill_process", "isolate_host", "quarantine_file"}

_PATH = re.compile(r"^[A-Za-z]:[\\/]|\\")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def default_policy():
    """NEVER-TOUCH 策略。受保护主机(DC/网关/mgmt)走 env(server2 .env 配,不入公开仓);
    受保护账号默认含 AD 通用高危账号(禁用即灾难)。"""
    def _split(v):
        return [x.strip() for x in (v or "").split(",") if x.strip()]
    return {
        "protected_hosts": _split(os.environ.get("DISPOSITION_PROTECTED_HOSTS")),
        "protected_accounts": (_split(os.environ.get("DISPOSITION_PROTECTED_ACCOUNTS"))
                               or ["krbtgt", "administrator", "domain admins",
                                   "enterprise admins", "domain controllers"]),
    }


# 角色→NEVER-TOUCH 的高价值主机(补图第二弹给 Host 补的 role/is_dc)
_PROTECTED_ROLES = ["certificate_authority"]


def policy_from_graph(graph):
    """在 default_policy 上叠加图里 DC/CA 主机 → NEVER-TOUCH 按角色自动(免手维护 env 名单)。
    图不可用则退回默认策略(不崩)。"""
    pol = default_policy()
    try:
        rows = graph.run_cypher(
            "MATCH (h:Host) WHERE h.is_dc = true OR h.role IN $roles "
            "RETURN collect(DISTINCT h.hostname) AS hosts", roles=_PROTECTED_ROLES)
        extra = (rows[0].get("hosts") if rows else None) or []
    except Exception:
        extra = []
    pol["protected_hosts"] = list(dict.fromkeys(
        [*pol.get("protected_hosts", []), *[h for h in extra if h]]))
    return pol


def _looks_like(target, kind):
    """宽松类型判:只否决明显不符的(路径当主机/账号、非 IP 当 IP),模糊的放过。"""
    t = (target or "").strip()
    if not t:
        return True
    is_path = bool(_PATH.search(t))
    is_ip = bool(_IPV4.match(t))
    if kind == "ip":
        return is_ip
    if kind == "process":
        return is_path or t.lower().endswith(".exe")
    if kind == "file":
        return is_path
    if kind in ("host", "account"):
        return not is_path and not is_ip
    return True


def _never_touch(action, target, policy):
    """命中 NEVER-TOUCH 返回原因串,否则 None。"""
    t = (target or "")
    tl = t.lower().strip()
    if action in _TOUCHES_ENDPOINT:
        agent = security_agent(t)
        if agent:
            return f"目标是安全/监控代理({agent})——绝不 kill/隔离传感器"
    for h in policy.get("protected_hosts", []):
        if h.lower() in tl:
            return f"目标是受保护主机({h})——DC/网关/mgmt 不动"
    for a in policy.get("protected_accounts", []):
        al = a.lower()
        if tl == al or tl.startswith(al + "\\") or tl.endswith("\\" + al):
            return f"目标是受保护账号({a})——AD 关键账号不禁用"
    return None


def _escalate(orig, reason):
    return Disposition(action="escalate", target=orig.target, risk=orig.risk,
                       status="proposed", by="auto")


def apply_guardrail(dispositions, policy=None):
    """把一串提议处置整成安全的:NEVER-TOUCH 硬拒 + 目标类型解析 + gated/auto 分级。
    返回 (safe_dispositions, audit)。audit 每条 = {action,target,decision,reason?}。"""
    policy = policy or default_policy()
    safe, audit = [], []
    for d in dispositions or []:
        reason = _never_touch(d.action, d.target, policy)
        if reason:
            audit.append({"action": d.action, "target": d.target, "decision": "blocked", "reason": reason})
            safe.append(_escalate(d, reason))
            continue
        exp = _EXPECT.get(d.action)
        if exp and d.target and not _looks_like(d.target, exp):
            reason = f"目标 {d.target!r} 不像{exp}(action={d.action})"
            audit.append({"action": d.action, "target": d.target, "decision": "retargeted", "reason": reason})
            safe.append(_escalate(d, reason))
            continue
        decision = "gated" if d.action in GATED_ACTIONS else "auto"
        audit.append({"action": d.action, "target": d.target, "decision": decision})
        safe.append(d)                                 # 保留(status 保持 proposed:首期一律仅建议)
    return safe, audit
