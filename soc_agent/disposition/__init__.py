"""处置层 · 提议时护栏(不真做,只把提议整成安全的)。

三件事(全部按**处置接口文档**驱动,不再硬编码原语语义):
  ① NEVER-TOUCH 硬拒:传感器进程(security_agent)、受保护主机(DC/网关/CA)、受保护账号(krbtgt/DA 等)
     —— 命中 → 降级为 escalate(交人工),绝不自伤。
  ② 目标类型解析:原语期望的目标类型(interface.kind_of)与 target 明显不符 → 降级 escalate。
  ③ gating:变更类原语(interface.is_gated)→ gated(人审后才真做);只读/非执行动作 → auto。
护栏逐条独立处理(被拦的一步降级 escalate,其余步保留)→ 多步计划不会被单步毁掉。
真执行(真做/模拟/回退)是后续 range 处置面 + 执行器,另做。纯逻辑,可单测。
"""
import os
import re

from ..models import Disposition
from ..recipe_lib import security_agent
from ..response import default_interface
from ..response.interface import NON_EXECUTING

__all__ = ["apply_guardrail", "default_policy", "policy_from_graph"]

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
    if kind in ("host", "account", "domain"):
        return not is_path and not is_ip
    return True


def _host_matches(target, protected):
    """★修子串 bug:按主机名标签/精确 FQDN 比,不用子串(旧 `dc01 in adc01` 会误判)。
    protected 给 'dc01' 或 'dc01.corp.local' 都能保护 dc01,但不误伤 adc01。"""
    t = (target or "").lower().strip()
    p = (protected or "").lower().strip()
    if not t or not p:
        return False
    return t == p or t.split(".")[0] == p.split(".")[0]


def _never_touch(action, target, policy, iface):
    """命中 NEVER-TOUCH 返回原因串,否则 None。"""
    t = (target or "")
    tl = t.lower().strip()
    if iface.touches_endpoint(action):          # 端点面(隔离/杀进程/取证/隔离文件)→ 查传感器
        agent = security_agent(t)
        if agent:
            return f"目标是安全/监控代理({agent})——绝不 kill/隔离传感器"
    kind = iface.kind_of(action)
    if kind == "host":
        for h in policy.get("protected_hosts", []):
            if _host_matches(t, h):
                return f"目标是受保护主机({h})——DC/网关/mgmt 不动"
    if kind == "account":
        for a in policy.get("protected_accounts", []):
            al = a.lower()
            if tl == al or tl.startswith(al + "\\") or tl.endswith("\\" + al):
                return f"目标是受保护账号({a})——AD 关键账号不禁用"
    return None


def _escalate(orig, reason):
    return Disposition(action="escalate", target=orig.target, risk=orig.risk,
                       status="proposed", by="auto")


def apply_guardrail(dispositions, policy=None, iface=None):
    """把一串提议处置整成安全的:NEVER-TOUCH 硬拒 + 目标类型解析 + gating(接口文档驱动)。
    返回 (safe_dispositions, audit)。audit 每条 = {action,target,decision,reason?}。
    逐条独立:被拦的一步降级 escalate、其余保留 —— 多步计划不被单步毁掉。"""
    policy = policy or default_policy()
    iface = iface or default_interface()
    safe, audit = [], []
    for d in dispositions or []:
        # 非执行/agent 侧动作(escalate/monitor/none)直接放行为 auto
        if d.action in NON_EXECUTING:
            audit.append({"action": d.action, "target": d.target, "decision": "auto"})
            safe.append(d)
            continue
        reason = _never_touch(d.action, d.target, policy, iface)
        if reason:
            audit.append({"action": d.action, "target": d.target, "decision": "blocked", "reason": reason})
            safe.append(_escalate(d, reason))
            continue
        kind = iface.kind_of(d.action)
        if kind != "none" and d.target and not _looks_like(d.target, kind):
            reason = f"目标 {d.target!r} 不像{kind}(action={d.action})"
            audit.append({"action": d.action, "target": d.target, "decision": "retargeted", "reason": reason})
            safe.append(_escalate(d, reason))
            continue
        decision = "gated" if iface.is_gated(d.action) else "auto"
        audit.append({"action": d.action, "target": d.target, "decision": decision})
        safe.append(d)                                 # 保留(status 保持 proposed:首期一律仅建议)
    return safe, audit
