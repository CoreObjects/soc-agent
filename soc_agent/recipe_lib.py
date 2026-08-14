"""recipe 共用纯函数:PowerShell EncodedCommand 解码 + 已知良性供给/自检噪声识别。

背景:多条 PowerShell 告警的决定性证据(编码命令、脚本块)如果不先解码/识别就交给 LLM,
模型要么幻觉、要么把配管工具(Ansible 等)的正常供给活动当攻击误判。这里用确定性代码先解出来、认出来。
纯逻辑、可单测、不碰图/LLM;多个 recipe 复用。
(唯一的例外是 `security_agent` —— 它的名单 WP10 起是每租户声明式的,
 落在 `sec_agents.py` 里惰性读文件;本模块只做转发,自己仍不碰 I/O。)
"""
import base64
import re

from soc_agent import sec_agents
from soc_agent.forensics import Finding

__all__ = ["decode_powershell_cmd", "decode_chain", "provisioning_noise", "security_agent",
           "bucket", "is_machine", "coverage_absent", "probe", "plus_activity"]

# ---------------------------------------------------------------------------
# 覆盖度感知(WP7):recipe 拿不到它赖以判别的那类遥测时,**明说自己瞎了**。
#
# 为什么必须有:三个 network/application recipe 的锚点查询是**硬性** `-[:BY]->(:Process)`,
# 换成没有发起进程的源(Zeek/NetFlow/防火墙)→ `base==[]` → `findings==[]` → 不报错,
# 落深度 LLM,给出一个**自信的空结论**。空 findings 与"确实没发现异常"在下游无法区分,
# 这是本系统里最贵的一类静默失败:它不会红,只会让结论悄悄变差。
#
# ★`_` 前缀 = 元 finding(不是证据)。`distill` 把它排除在指纹之外 ——
#   否则"瞎了 → 判 FP"会被当成经验学下来,以后一瞎就自动放过。
# ---------------------------------------------------------------------------


def coverage_absent(skill, *, need, pivot=None, detail=None) -> Finding:
    """产出 `_coverage.absent`:这条 recipe 需要 `need` 这类遥测,当前数据里没有。

    need 用**通用遥测类别名**(process_telemetry / file_telemetry / dns_telemetry …),
    不写厂商名 —— 跟指纹守的是同一条可移植性红线。

    ★`scope="alert"`:这里说的是**这一条**告警缺主语/缺行(个例)。
      另有 `scope="deployment"`(WP9,`graph/coverage.py`)说的是**整类遥测这套部署压根没有**。
      两者要能分开:前者可能只是这条告警特殊,后者是能力边界、该写进能力承诺里。
    """
    attrs = {"skill": skill, "need": need, "scope": "alert",
             "pivot_kind": getattr(pivot, "kind", None)}
    if detail:
        attrs["detail"] = detail
    return Finding("_coverage.absent", attrs, polarity="neutral")


def probe(graph, query, *, skill, need, findings, pivot=None, **params):
    """跑一条"按契约本应有行"的查询;**零行 = 覆盖度缺口**,追加 `_coverage.absent` 再返回 []。

    这就是计划里 `run_cypher(..., expect=...)` 的落点。★没做进 `graph.client.run_cypher`:
    那是 LLM 工具共用的只读 API,让它反向依赖 `forensics.Finding` 会把两层黏死;
    而且"零行意味着什么"本来就是 recipe 的语义,不是图客户端的。
    """
    rows = graph.run_cypher(query, **params)
    if not rows:
        findings.append(coverage_absent(skill, need=need, pivot=pivot))
    return rows


def bucket(n) -> str:
    """计数分桶(single/low/high/massive)—— 指纹用桶而非裸值,换环境仍稳。跨 recipe 共用。"""
    n = n or 0
    if n <= 1:
        return "single"
    if n <= 4:
        return "low"
    if n <= 19:
        return "high"
    return "massive"


def is_machine(sam) -> bool:
    """账号是否机器账号(sam 以 $ 结尾)—— 结构判别,不硬编码名单。跨 recipe 共用。"""
    return bool(sam and str(sam).strip().endswith("$"))

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


# 已知良性:配管工具(Ansible)供给 + PowerShell 执行策略自检(系统自动写)。命中即"非攻击"强证伪。
# 通用模式:凡用 Ansible 配管、凡 Windows 跑 PS 都会产生,不绑定任何具体环境(本靶场 GOAD 用 Ansible,是其一例)。
_NOISE = [
    ("ansible_exec_wrapper", "良性:Ansible 配管供给/运维(凡用 Ansible 的环境皆有)",
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


def security_agent(image):
    """image/路径命中已知安全/监控代理 → 返回产品名,否则 None。命中即"自身遥测"强证伪信号。

    ★WP10:名单从这里的 8 条硬编码正则改成**每租户声明式**(见 `soc_agent/sec_agents.py`)。
      换个客户就换一批 EDR —— 客户自己的 agent 不在名单里,它的进程会全程出现在进程
      遥测里却拿不到白极性豁免,而且**处置层的 NEVER-TOUCH 硬拒也保护不到它**
      (系统可能提议 kill 掉客户的 EDR = 戳瞎监控)。
      内置默认仍是原来那 8 条(pattern / name / 顺序逐字不变),GOAD 行为按定义不变;
      任何加载失败一律回退到内置,**绝不回退成空**(空名单在处置侧是危险,不是保守)。
    """
    if not image:
        return None
    return sec_agents.effective().match(image)


def plus_activity(attrs: dict, src) -> dict:
    """给 `Finding.attrs` 补中立活动类 —— **值为空就不写这个键**(WP10)。

    ★为什么不能写 `activity: None`:指纹 canon 会把它固化下来,而
      `_attr_ok` 只校验**已存 canon 里的 key** —— 于是
      · 现在写 None → canon 里带 `activity: None`;
      · 将来那个 event_code 被补上映射 → 同一情形产出 `activity: 'x'` → **对不上、静默失配**。
      缺键则相反:老指纹没这个 key 就不校验它,新老都能匹配。
      这正是计划决策 #2 反复强调的那个坑(WP4 回填必须早于本步),
      而**未映射的那 118 条事件今天就是 activity=null** —— 不是假想。

    ★`event_code` 等原有 key **一字不动**:只加不改。
    """
    out = dict(attrs)
    act = (src or {}).get("activity") if hasattr(src, "get") else None
    if act:
        out["activity"] = act
    return out
