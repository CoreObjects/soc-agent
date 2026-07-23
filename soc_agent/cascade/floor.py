"""浅度研判硬底线:哪些告警**绝不许**浅层终局、必须升级到深度研判。

纯 Python、只读 `alert.technique_ids`,不查图、不 seed。触发=**高危技战术前缀**
(凭据转储 / Kerberos 票据 / 备用凭据 / 流氓域控 / 域策略篡改,含子技术)。

★曾有第二条触发"告警文本涉及受保护主机(DC/CA)",但在全 AD 靶场(GOAD)里几乎每条告警的
原文都带 DC 主机名 → 对几乎所有告警强制升级,把浅层降噪能力整个盖死。已去掉:真正危险的
凭据/Kerberos 类攻击由高危技战术那条覆盖;其余(哪怕告警提到 DC)应让浅层能自主降噪。
升级判定不靠 LLM 自报置信(调研:自报不可靠)——这条确定性底线在 Python 入口预算成 force_deep。
"""

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


def force_deep(alert, policy=None) -> bool:
    """命中高危技战术前缀 → True(强制升级深度研判)。policy 暂不用(保签名兼容)。"""
    return _hits_high_stakes(getattr(alert, "technique_ids", None))
