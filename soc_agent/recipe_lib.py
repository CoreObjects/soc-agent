"""recipe 共用纯函数:PowerShell EncodedCommand 解码 + 已知良性供给/自检噪声识别。

背景:多条 PowerShell 告警的决定性证据(编码命令、脚本块)如果不先解码/识别就交给 LLM,
模型要么幻觉、要么把 GOAD 自身的 Ansible 供给当攻击误判。这里用确定性代码先解出来、认出来。
纯逻辑、可单测、不碰图/LLM;多个 recipe 复用。
"""
import base64
import re

__all__ = ["decode_powershell_cmd", "decode_chain", "provisioning_noise", "security_agent"]

# PowerShell -EncodedCommand(可缩写 -enc / -e)后跟 base64。-e 需紧跟空格,避免误吃 -ExecutionPolicy。
_ENC = re.compile(r"(?:-enc(?:odedcommand)?|-e)\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_powershell_cmd(command_line):
    """抽命令行里的 -EncodedCommand base64,按 UTF-16LE 解码;无/失败 → None。"""
    if not command_line:
        return None
    m = _ENC.search(command_line)
    if not m:
        return None
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        text = raw.decode("utf-16-le", errors="replace").strip()
        return text or None
    except Exception:
        return None


def decode_chain(command_line, max_depth=4):
    """连锁解码:解出的内容若又套 EncodedCommand 就继续解(攻击者常多层套)。返回各层 [str]。"""
    out, cur = [], command_line
    for _ in range(max_depth):
        dec = decode_powershell_cmd(cur)
        if not dec:
            break
        out.append(dec)
        cur = dec
    return out


# 已知良性:GOAD 用 Ansible 供给部署 + PowerShell 执行策略自检(系统自动写)。命中即"非攻击"强证伪。
_NOISE = [
    ("ansible_exec_wrapper", "良性:Ansible 供给/运维(GOAD 用 Ansible 部署)",
     re.compile(r"ConvertFrom-AnsibleJson|Write-AnsibleLog|ANSIBLE_EXEC_DEBUG|exec_wrapper", re.I)),
    ("ps_execution_policy_probe", "良性:PowerShell 执行策略自检(系统自动写,非攻击)",
     re.compile(r"__PSScriptPolicyTest_", re.I)),
]


def provisioning_noise(text):
    """text(命令行/脚本块/解码后内容/文件路径)命中已知良性供给/自检 → 返回标签串,否则 None。"""
    if not text:
        return None
    hits = [f"{name}({desc})" for name, desc, rx in _NOISE if rx.search(text)]
    return "; ".join(hits) if hits else None


# 已知安全/监控代理:这类进程"访问 LSASS / 读进程 / 大量外连"多为自身遥测/完整性检查,是头号 FP。
# ★绝不能因它自身触发的告警去 kill/隔离该代理或其主机(=戳瞎监控)。
_SEC_AGENTS = [
    (re.compile(r"wazuh-agent|ossec-agent", re.I), "Wazuh/OSSEC HIDS 代理"),
    (re.compile(r"MsMpEng\.exe|NisSrv\.exe|MpDefenderCoreService", re.I), "Microsoft Defender"),
    (re.compile(r"Sysmon6?4?\.exe", re.I), "Sysmon 传感器"),
    (re.compile(r"winlogbeat|filebeat|elastic-agent", re.I), "Elastic/Beats 采集器"),
    (re.compile(r"MsSense\.exe|SenseIR\.exe", re.I), "Microsoft Defender for Endpoint"),
    (re.compile(r"CSFalcon", re.I), "CrowdStrike Falcon"),
    (re.compile(r"xagt\.exe", re.I), "Trellix/FireEye"),
    (re.compile(r"SentinelAgent|SentinelServiceHost", re.I), "SentinelOne"),
]


def security_agent(image):
    """image/路径命中已知安全/监控代理 → 返回产品名,否则 None。命中即"自身遥测"强证伪信号。"""
    if not image:
        return None
    for rx, name in _SEC_AGENTS:
        if rx.search(image):
            return name
    return None
