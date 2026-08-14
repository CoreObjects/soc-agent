"""每租户「安全/监控代理」声明 —— 原来 8 条硬编码 EDR 正则的可配置化(WP10)。

## 为什么这条不是普通配置:它有两个**方向相反**的失败面

· **研判侧**(`lsass_dump` / `webshell` / `c2_beacon` 三个 recipe):命中即产出
  **white 极性** finding —— "这是代理自身遥测/完整性检查",头号 FP 证伪信号。
  匹配过宽 → 真攻击被白掉(漏报);过窄 → 代理自己的行为被当攻击(FP 风暴)。
· **处置侧**(`disposition._never_touch`):命中即 **NEVER-TOUCH 硬拒**。
  过窄 → 系统可能提议 kill/隔离 EDR 自己 = **戳瞎监控**。

⇒ 所以本模块的失败方向是按**处置侧**定的:配置读不到、解析不了、某条正则写坏,
  一律**保留内置名单**并把问题大声报出来,**绝不回退成空**。
  空名单在处置侧是危险,不是"保守"。

## 两条硬约束(改这个文件前先读)

1. **name 进指纹 canon**。`Finding("lsass.source_is_security_agent", {"agent": <name>, …})`、
   `Finding("webshell.security_agent_writer", {"agent": <name>, …})` —— 而
   `experience` 的 canon 是**精确相等**。改一个字(哪怕只是"Microsoft Defender"→"Defender")
   就静默作废该指纹。所以 `BUILTIN` 的 name 与 pattern 都必须与硬编码版**逐字一致**,
   `tests/test_sec_agents.py` 拿一份冻结字面量 + 语料逐条比对钉死。
2. **顺序有语义**。原实现是"按序遍历、首个命中即返回",一个 image 可能同时命中两条。
   所以内置顺序不动;租户 `agents` 追加在**内置之后**;同名条目是**就地替换**
   (改 pattern 但保住 name ⇒ 指纹不失效),不是追加。

## 可移植性红线

内置名单是**厂商产品名**,看着像"硬编码厂商" —— 但它键的是 `image` 原始值这个
通用本体字段,而且这份名单本身就是本模块要交给租户去改的**数据**,不是代码里的定制。
红线守的是"别把某个客户的定制字段焊进 key",不是"不许有默认值"。
"""
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 默认配置路径(不存在就只用内置名单 —— 这是绝大多数部署的常态,不算问题)
DEFAULT_PATH = os.path.join(_ROOT, "config", "security_agents.yaml")
ENV_KEY = "SOC_SECURITY_AGENTS_FILE"

# ---------------------------------------------------------------------------
# 内置名单 —— ★与原 `recipe_lib._SEC_AGENTS` 逐字一致(pattern / name / 顺序)。
# 已知安全/监控代理:这类进程"访问 LSASS / 读进程 / 大量外连"多为自身遥测/完整性检查,
# 是头号 FP。★绝不能因它自身触发的告警去 kill/隔离该代理或其主机(=戳瞎监控)。
# ---------------------------------------------------------------------------
BUILTIN = (
    {"name": "Wazuh/OSSEC HIDS 代理", "match": ["wazuh-agent|ossec-agent"]},
    {"name": "Microsoft Defender", "match": [r"MsMpEng\.exe|NisSrv\.exe|MpDefenderCoreService"]},
    {"name": "Sysmon 传感器", "match": [r"Sysmon6?4?\.exe"]},
    {"name": "Elastic/Beats 采集器", "match": ["winlogbeat|filebeat|elastic-agent"]},
    {"name": "Microsoft Defender for Endpoint", "match": [r"MsSense\.exe|SenseIR\.exe"]},
    {"name": "CrowdStrike Falcon", "match": ["CSFalcon"]},
    {"name": "Trellix/FireEye", "match": [r"xagt\.exe"]},
    {"name": "SentinelOne", "match": ["SentinelAgent|SentinelServiceHost"]},
)

_TOP_KEYS = frozenset({"version", "agents", "disable_builtin"})
_ENTRY_KEYS = frozenset({"name", "match"})


class Registry:
    """一份编译好的代理名单。`match(image)` 语义与原硬编码实现完全一致。"""

    def __init__(self, entries, problems=(), source="内置"):
        self.entries = list(entries)                      # [(name, [compiled…])]
        self.problems = list(problems)
        self.source = source

    def match(self, image):
        """image/路径命中已知安全/监控代理 → 返回产品名,否则 None。首个命中即返回。"""
        if not image:
            return None
        for name, rxs in self.entries:
            for rx in rxs:
                if rx.search(image):
                    return name
        return None

    def names(self):
        return [n for n, _ in self.entries]

    def describe(self):
        head = f"安全/监控代理名单:{len(self.entries)} 条(来源:{self.source})"
        body = "\n".join(f"  · {n}" for n in self.names())
        tail = ("\n★问题(已按失败安全回退,内置名单仍在生效):\n"
                + "\n".join(f"  ! {p}" for p in self.problems)) if self.problems else ""
        return f"{head}\n{body}{tail}"


def _compile(patterns, name, problems):
    """编译一条的正则组;写坏的**单条跳过并报问题**,不连累整份名单。"""
    out = []
    for p in patterns:
        try:
            out.append(re.compile(str(p), re.I))
        except re.error as e:
            problems.append(f"{name}: 正则编译失败 {p!r} —— {e}(该模式已跳过)")
    return out


def _read(path, problems):
    """读配置文件。约定与 `response.interface.load_interface` 一致:
    `.json` 走 stdlib、`.yaml/.yml` 走 PyYAML;缺 PyYAML 不崩、报问题后按内置走。"""
    import json
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith(".json"):
        return json.loads(text)
    try:
        import yaml
    except ImportError:
        problems.append(f"读 {path} 需要 PyYAML,当前环境没装 —— 本次只用内置名单")
        return None
    return yaml.safe_load(text)


def build(doc, problems):
    """把声明文档合并进内置名单。★内置在前(顺序即优先级),租户新增在后,同名就地替换。"""
    merged = [dict(e) for e in BUILTIN]
    if not isinstance(doc, dict):
        problems.append("配置根节点不是映射(dict)—— 整份忽略,只用内置名单")
        doc = {}
    for k in doc:
        if k not in _TOP_KEYS:
            problems.append(f"未知顶层键 {k!r}(允许:{sorted(_TOP_KEYS)})—— 已忽略")

    disabled = doc.get("disable_builtin") or []
    if not isinstance(disabled, list):
        problems.append("disable_builtin 不是列表 —— 已忽略")
        disabled = []
    known = {e["name"] for e in BUILTIN}
    for d in disabled:
        if d not in known:
            problems.append(f"disable_builtin 里的 {d!r} 不是内置项 —— 拼错了?已忽略")
    # ★关掉内置是**削弱处置侧护栏**的动作,必须留痕,不能悄悄生效
    for d in disabled:
        if d in known:
            problems.append(f"⚠ 已按声明关闭内置项 {d!r} —— 该产品今后不再享 NEVER-TOUCH 硬拒")
    merged = [e for e in merged if e["name"] not in set(disabled)]

    agents = doc.get("agents") or []
    if not isinstance(agents, list):
        problems.append("agents 不是列表 —— 已忽略")
        agents = []
    by_name = {e["name"]: i for i, e in enumerate(merged)}
    for raw in agents:
        if not isinstance(raw, dict):
            problems.append(f"agents 里有非映射条目 {raw!r} —— 已跳过")
            continue
        for k in raw:
            if k not in _ENTRY_KEYS:
                problems.append(f"条目未知键 {k!r}(允许:{sorted(_ENTRY_KEYS)})—— 已忽略")
        name, pats = raw.get("name"), raw.get("match")
        if not name or not isinstance(pats, list) or not pats:
            problems.append(f"条目缺 name 或 match(非空列表):{raw!r} —— 已跳过")
            continue
        if name in by_name:                     # 同名 = 就地替换,保住 name ⇒ 指纹不失效
            merged[by_name[name]] = {"name": name, "match": list(pats)}
        else:
            by_name[name] = len(merged)
            merged.append({"name": name, "match": list(pats)})

    entries = []
    for e in merged:
        rxs = _compile(e["match"], e["name"], problems)
        if rxs:
            entries.append((e["name"], rxs))
        else:
            problems.append(f"{e['name']}: 没有一条可用模式 —— 该条目已失效")
    return entries


def load(path=None):
    """加载有效名单。★任何失败都回退到内置名单(**绝不回退成空**),问题随 Registry 返回。"""
    problems = []
    p = path or os.environ.get(ENV_KEY) or DEFAULT_PATH
    if not os.path.exists(p):
        # 文件不存在是**常态**,不是问题:绝大多数部署就用内置名单。
        return Registry(build({}, problems), problems, source="内置(未提供租户声明)")
    try:
        doc = _read(p, problems)
    except Exception as e:                                  # noqa: BLE001 —— 读配置不许把进程带走
        problems.append(f"读/解析 {p} 失败:{type(e).__name__}: {e} —— 本次只用内置名单")
        doc = None
    if doc is None:
        return Registry(build({}, problems), problems, source=f"内置(读 {p} 失败)")
    return Registry(build(doc, problems), problems, source=p)


_CACHE = None


def effective():
    """进程内单次加载的有效名单。

    ★做成**惰性加载**而不是"启动时显式 load()":调用点有 poller / CLI / run_pipeline /
      处置层等多处,显式初始化少接一处就会**静默**按内置名单跑 —— 租户声明的条目全不生效
      而没有任何症状。这个项目已经在同一类"漏接一处、不报错只变差"的失败上栽过太多次。
    """
    global _CACHE
    if _CACHE is None:
        _CACHE = load()
    return _CACHE


def reset(registry=None):
    """重置缓存(测试/诊断用;传入 registry 可直接注入)。"""
    global _CACHE
    _CACHE = registry
