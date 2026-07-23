"""浅度研判硬底线:哪些告警**绝不许**浅层终局、必须升级到深度研判。

纯 Python、只读告警字段(technique_ids / rule_description / raw),不查图、不 seed。
两条触发(命中其一即强制升级):
  ① 高危技战术:凭据转储 / Kerberos 票据 / 备用凭据 / 流氓域控 / 域策略篡改(前缀匹配含子技术)。
  ② 告警文本涉及受保护主机(DC/CA,来自 disposition policy 的 protected_hosts)。

调研结论:升级判定不靠 LLM 自报置信(不可靠)—— 这条确定性底线在 Python 入口预算成
``force_deep``,分叉条件 OR 上它。见计划 humming-twirling-moore、[[soc-agent-p3-built]] 护栏。
"""
import re

__all__ = ["force_deep", "HIGH_STAKES_PREFIXES"]

# 高危技战术前缀(startswith,自动覆盖子技术):
#   T1003 凭据转储(LSASS/SAM/NTDS/DCSync) · T1558 Kerberos 票据(kerberoast/AS-REP/金银票)
#   T1550 备用认证材料(PtH/PtT) · T1207 流氓域控/DCShadow · T1484 域策略/GPO 篡改
HIGH_STAKES_PREFIXES = ("T1003", "T1558", "T1550", "T1207", "T1484")


def _hits_high_stakes(technique_ids) -> bool:
    for t in technique_ids or []:
        ts = str(t).upper().strip()
        if any(ts.startswith(p) for p in HIGH_STAKES_PREFIXES):
            return True
    return False


def _alert_text(alert) -> str:
    return " ".join([getattr(alert, "rule_description", "") or "",
                     getattr(alert, "raw", "") or ""])


def _mentions(text: str, name: str) -> bool:
    """name 作为**整段 token** 出现在 text 里(避免 dc01 命中 adc01 的子串误判)。
    name 给 FQDN(dc01.corp.local)也匹配其裸标签(dc01)。大小写不敏感。"""
    name = (name or "").strip()
    if not name:
        return False
    for tok in {name.lower(), name.split(".")[0].lower()}:
        if tok and re.search(r"(?<![A-Za-z0-9_])" + re.escape(tok) + r"(?![A-Za-z0-9_])",
                             text, re.IGNORECASE):
            return True
    return False


def _hits_protected_host(alert, policy) -> bool:
    hosts = (policy or {}).get("protected_hosts") or []
    if not hosts:
        return False
    text = _alert_text(alert)
    if not text.strip():
        return False
    return any(_mentions(text, h) for h in hosts)


def force_deep(alert, policy=None) -> bool:
    """浅层硬底线:命中高危技战术 或 告警文本涉及受保护主机 → True(强制升级深度研判)。"""
    if _hits_high_stakes(getattr(alert, "technique_ids", None)):
        return True
    if _hits_protected_host(alert, policy):
        return True
    return False
