"""每租户安全/监控代理名单(WP10)—— 等价 + 失败安全 + 指纹兼容。

这条改动的风险不在"能不能读配置",在于它同时喂两个方向相反的下游:
  · 研判侧产出 **white 极性** finding(能把结论翻成 FP);
  · 处置侧做 **NEVER-TOUCH 硬拒**(拦住"kill 掉 EDR 自己")。
所以本文件守三件事:**与硬编码版逐条等价**、**任何失败都不回退成空**、**name 不许漂**。
"""
import re

import pytest

from soc_agent import sec_agents
from soc_agent.recipe_lib import security_agent

# ★冻结字面量:改这个文件之前那 8 条硬编码正则的**原样副本**。
#   等价闸门比的是它,而不是比 BUILTIN 自己(拿被测对象当基准等于什么都没测)。
FROZEN = [
    (re.compile(r"wazuh-agent|ossec-agent", re.I), "Wazuh/OSSEC HIDS 代理"),
    (re.compile(r"MsMpEng\.exe|NisSrv\.exe|MpDefenderCoreService", re.I), "Microsoft Defender"),
    (re.compile(r"Sysmon6?4?\.exe", re.I), "Sysmon 传感器"),
    (re.compile(r"winlogbeat|filebeat|elastic-agent", re.I), "Elastic/Beats 采集器"),
    (re.compile(r"MsSense\.exe|SenseIR\.exe", re.I), "Microsoft Defender for Endpoint"),
    (re.compile(r"CSFalcon", re.I), "CrowdStrike Falcon"),
    (re.compile(r"xagt\.exe", re.I), "Trellix/FireEye"),
    (re.compile(r"SentinelAgent|SentinelServiceHost", re.I), "SentinelOne"),
]


def frozen_impl(image):
    """改动前的实现,原样保留 —— 等价比对的基准。"""
    if not image:
        return None
    for rx, name in FROZEN:
        if rx.search(image):
            return name
    return None


# 覆盖 8 条各自的每一个分支 + 大小写 + 带路径 + 不该命中的
CORPUS = [
    None, "", "explorer.exe", r"C:\Windows\System32\svchost.exe",
    "/var/ossec/bin/wazuh-agentd", "ossec-agent", "WAZUH-AGENT.EXE",
    r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18\MsMpEng.exe",
    "NisSrv.exe", "MpDefenderCoreService.exe", "msmpeng.EXE",
    r"C:\Windows\Sysmon64.exe", r"C:\Windows\Sysmon.exe", "Sysmon6.exe", "sysmon64.exe",
    "SysmonDrv.sys",                                   # ★不该命中(没有 .exe)
    "winlogbeat.exe", "/usr/bin/filebeat", "elastic-agent", "FILEBEAT",
    "MsSense.exe", "SenseIR.exe", "mssense.exe",
    r"C:\Program Files\CrowdStrike\CSFalconService.exe", "csfalcon",
    "xagt.exe", "/opt/fireeye/xagt.exe", "XAGT.EXE",
    "SentinelAgent.exe", "SentinelServiceHost.exe", "sentinelagent",
    # 一个都不该命中的近似串
    "sysmon.txt", "falcon.exe", "sentinel.exe", "beats.exe", "defender.exe",
    # ★路径里藏的伪装(现有语义就是全串搜索,等价闸门要把这个行为也钉住,
    #   免得改写时"顺手修好"却悄悄改了研判结论)
    r"C:\Users\Public\MsMpEng.exe",
]


@pytest.fixture(autouse=True)
def _clean_registry():
    """每条用例前后都清缓存 —— 惰性单例最容易在测试间互相污染。"""
    sec_agents.reset()
    yield
    sec_agents.reset()


def test_builtin_is_byte_equivalent_to_the_frozen_hardcoded_list():
    """★验收硬闸门:GOAD 租户上必须与原 8 条正则**逐条等价** —— 包括**返回的名字串**。

    只比"命中/不命中"是不够的:名字进 `Finding.attrs`、进指纹 canon(精确相等),
    "Microsoft Defender"→"Defender" 这种改名会**静默作废**已沉淀的指纹。
    """
    reg = sec_agents.load(path="/nonexistent-on-purpose")
    for s in CORPUS:
        assert reg.match(s) == frozen_impl(s), f"不等价:{s!r}"


def test_public_api_goes_through_the_registry_and_stays_equivalent():
    """对外的 `security_agent()` 也要等价 —— 三个 recipe 和处置层用的是它。"""
    for s in CORPUS:
        assert security_agent(s) == frozen_impl(s), f"不等价:{s!r}"


def test_builtin_order_is_preserved():
    """顺序即优先级(首个命中即返回)—— 内置顺序不许动。"""
    assert sec_agents.load(path="/nope").names() == [n for _rx, n in FROZEN]


# ---------------------------------------------------------------------------
# 失败安全:★所有异常路径都必须**保留内置**,绝不回退成空。
# 空名单在处置侧意味着 NEVER-TOUCH 全线失守 —— 那是危险,不是保守。
# ---------------------------------------------------------------------------

def _write(tmp_path, text, name="security_agents.yaml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_missing_file_is_not_an_error_just_builtins():
    reg = sec_agents.load(path="/definitely/not/here.yaml")
    assert reg.names() == [n for _rx, n in FROZEN]
    assert reg.problems == []                       # 文件不存在是常态,不该刷问题


def test_unparsable_file_keeps_builtins_and_shouts(tmp_path):
    reg = sec_agents.load(path=_write(tmp_path, "agents: [oops\n  - ]]]"))
    assert reg.names() == [n for _rx, n in FROZEN]  # ★仍然全在
    assert any("失败" in p for p in reg.problems)


def test_root_not_a_mapping_keeps_builtins(tmp_path):
    reg = sec_agents.load(path=_write(tmp_path, "- just\n- a\n- list\n"))
    assert reg.names() == [n for _rx, n in FROZEN]
    assert any("不是映射" in p for p in reg.problems)


def test_broken_regex_skips_only_that_pattern(tmp_path):
    """一条正则写坏,不许连累整份名单 —— 那会让护栏整体消失。"""
    reg = sec_agents.load(path=_write(
        tmp_path, 'agents:\n  - name: "Acme EDR"\n    match: ["AcmeSensor\\\\.exe", "(unclosed"]\n'))
    assert reg.match("AcmeSensor.exe") == "Acme EDR"          # 好的那条照常生效
    assert any("正则编译失败" in p for p in reg.problems)
    assert reg.names()[:8] == [n for _rx, n in FROZEN]        # 内置一条没少


def test_unknown_keys_are_rejected_loudly(tmp_path):
    """未知 key 大声拒绝 —— 拼错的键静默生效等于配置没生效而没人知道。"""
    reg = sec_agents.load(path=_write(tmp_path, "agentz:\n  - name: x\n    match: [y]\n"))
    assert any("未知顶层键" in p for p in reg.problems)


# ---------------------------------------------------------------------------
# 租户增补:这正是接 EDR 客户要用的能力
# ---------------------------------------------------------------------------

def test_tenant_can_add_its_own_edr(tmp_path):
    """客户的 EDR 型号未知、必然不在内置 8 条里 —— 声明一条就该同时拿到
    白极性证伪**和**处置层 NEVER-TOUCH 保护。"""
    reg = sec_agents.load(path=_write(
        tmp_path, 'agents:\n  - name: "Acme EDR"\n    match: ["AcmeSensor\\\\.exe", "acme-agentd"]\n'))
    assert reg.match(r"C:\Program Files\Acme\AcmeSensor.exe") == "Acme EDR"
    assert reg.match("/usr/sbin/acme-agentd") == "Acme EDR"
    for s in CORPUS:                                          # 内置行为一点没变
        assert reg.match(s) == frozen_impl(s)


def test_same_name_replaces_in_place_so_fingerprints_survive(tmp_path):
    """同名 = 就地替换:改 pattern 但**保住 name** ⇒ 已沉淀指纹里的 attrs.agent 仍对得上。"""
    reg = sec_agents.load(path=_write(
        tmp_path, 'agents:\n  - name: "CrowdStrike Falcon"\n    match: ["CsAgent\\\\.exe"]\n'))
    assert reg.names() == [n for _rx, n in FROZEN]             # 位置和名字都没动
    assert reg.match("CsAgent.exe") == "CrowdStrike Falcon"
    assert reg.match("CSFalconService.exe") is None            # 旧模式已被替换掉


def test_disabling_a_builtin_is_allowed_but_leaves_a_trace(tmp_path):
    """关掉内置是**削弱处置侧护栏**的动作(比如防攻击者把马命名成 CSFalcon 蹭白)。
    允许,但必须留痕 —— 悄悄生效的护栏削弱是这套系统里最贵的一类改动。"""
    reg = sec_agents.load(path=_write(
        tmp_path, 'disable_builtin: ["CrowdStrike Falcon"]\n'))
    assert reg.match("CSFalconService.exe") is None
    assert any("已按声明关闭内置项" in p and "NEVER-TOUCH" in p for p in reg.problems)
    assert len(reg.names()) == 7


def test_typo_in_disable_builtin_is_reported(tmp_path):
    reg = sec_agents.load(path=_write(tmp_path, 'disable_builtin: ["CrowdStrke Falcon"]\n'))
    assert len(reg.names()) == 8                               # 没误删
    assert any("不是内置项" in p for p in reg.problems)


def test_effective_is_lazy_and_cached():
    """惰性单例:调用点太多,显式初始化漏接一处就会**静默**按内置跑。"""
    sec_agents.reset()
    a = sec_agents.effective()
    assert sec_agents.effective() is a
    injected = sec_agents.Registry([("X", [re.compile("zzz")])], source="注入")
    sec_agents.reset(injected)
    assert security_agent("zzz.exe") == "X"


def test_describe_surfaces_problems():
    """诊断输出要能一眼看到"名单从哪来、有没有问题" —— 不然又是个静默态。"""
    reg = sec_agents.Registry([("X", [re.compile("x")])], problems=["坏了"], source="/tmp/x.yaml")
    txt = reg.describe()
    assert "/tmp/x.yaml" in txt and "坏了" in txt and "X" in txt
