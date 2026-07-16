"""Kerberoast skill 本地共享原语 —— recipe.py 与 signature.py 都 import 这里。

★同步收在原语层:enc 归一 / 域归一(NetBIOS)/ 机器账号判定 / 短窗常量都只有一份,
recipe(喂 LLM 的证据)和 signature(快通道特征)对这些低层判定永远一致、不漂。
但两者的【图查询】仍各自 self-anchor、互不吃对方输出(查询不在这里共享)。
"""

FANOUT_WINDOW = "PT10M"          # 短窗:近 10 分钟该请求者去重目标数(扫描式取票信号)


def netbios(domain):
    """域归一到 NetBIOS 首段大写:NORTH / north.sevenkingdoms.local → NORTH;空/占位→None。"""
    if not domain or domain == "-":
        return None
    return domain.split(".")[0].strip().upper() or None


def same_domain(req_domain, tgt_domain) -> bool:
    """请求者域与目标域是否同域 —— 按 NetBIOS 比(NORTH 与 north.sevenkingdoms.local 是同一个域)。"""
    a, b = netbios(req_domain), netbios(tgt_domain)
    return bool(a and b and a == b)


def is_machine(sam) -> bool:
    """机器账号 = sam 以 $ 结尾(DC$/WS$…)。"""
    return bool(sam and str(sam).strip().endswith("$"))


def norm_enc(enc_raw) -> str:
    """加密类型归一:RC4(0x17/23/rc4…)vs other。"""
    e = str(enc_raw or "").strip().lower()
    return "RC4" if e in ("0x17", "23", "rc4", "rc4-hmac") else "other"
