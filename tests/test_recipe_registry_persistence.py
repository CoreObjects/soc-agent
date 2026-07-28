"""registry_persistence recipe 迁移(旧散装 dict → 结构化 Forensics)的 finding 抽取单测。

finding_id = 方法论(第一类,离线定);"哪些 finding→什么结论"的映射才是第二类(qwen 学)。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行,解耦调用顺序(子串须在各查询里唯一)。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _regpersist():
    return SkillRegistry(_SKILLS).by_name("registry_persistence").recipe


def test_registry_attack_powershell_temp_emits_red_findings_and_bindings():
    # 攻击态:powershell 写 Run 键、value_data 指向 %TEMP%/AppData 下的载荷 → 双红
    graph = FakeGraph([
        ("rv.hive AS hive", [{
            "hive": "HKLM",
            "key_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "Updater",
            "value_data": r"powershell -w hidden -File C:\Users\hacker\AppData\Local\Temp\evil.exe",
            "proc_guid": "g1",
            "writer_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "writer_cmdline": "powershell -enc ZQB2AGkAbAA=",
            "parent": "cmd.exe",
            "host": "WIN10",
        }]),
        ("acc.sam AS sam", [{"sam": "hacker", "domain": "NORTH", "privileged": False}]),
    ])
    a = Alert.from_node({"alert_uid": "rp1", "technique_ids": ["T1547.001"]})
    fo = _regpersist()(graph, a, {})
    assert isinstance(fo, Forensics)

    ids = fo.finding_ids()
    assert "regpersist.autostart_write" in ids             # 触发本身
    assert "regpersist.suspicious_writer" in ids            # powershell = LOLBin 写入(红)
    assert "regpersist.nonstandard_target" in ids           # value_data 指向 AppData\Temp(红)
    assert "regpersist.installer_writer" not in ids         # 非安装器
    assert "regpersist.privileged_account" not in ids       # 普通账号

    aw = next(f for f in fo.findings if f.finding_id == "regpersist.autostart_write")
    assert aw.polarity == "neutral"
    assert aw.attrs == {"hive": "HKLM", "key_type": "run"}  # 键类归类,非裸 key_path
    sw = next(f for f in fo.findings if f.finding_id == "regpersist.suspicious_writer")
    assert sw.polarity == "red"
    assert "powershell" in (sw.attrs.get("writer_image") or "")   # 原始进程名进 attrs(承重 key)
    nt = next(f for f in fo.findings if f.finding_id == "regpersist.nonstandard_target")
    assert nt.polarity == "red" and nt.attrs == {}          # presence-only,裸值留 ctx

    assert fo.bindings["process"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert fo.bindings["account"] == "hacker"
    assert fo.bindings["account_domain"] == "NORTH"
    assert fo.bindings["host"] == "WIN10"
    assert fo.context.get("键与写入值+写入进程")             # prose 仍在(喂 LLM)
    assert "AppData" in (fo.context.get("非标准落地路径(value_data)") or "")   # value_data 裸值进 ctx


def test_registry_benign_installer_signed_dir_white_no_red():
    # 良性态:msiexec 写 Run 键、value_data 指向签名安装目录(Program Files)→ installer_writer 白、无红
    graph = FakeGraph([
        ("rv.hive AS hive", [{
            "hive": "HKLM",
            "key_path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "OneDrive",
            "value_data": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background",
            "proc_guid": "g2",
            "writer_image": r"C:\Windows\System32\msiexec.exe",
            "writer_cmdline": "msiexec /i onedrive.msi /quiet",
            "parent": "services.exe",
            "host": "WKS01",
        }]),
        ("acc.sam AS sam", [{"sam": "SYSTEM", "domain": "NORTH", "privileged": True}]),
    ])
    a = Alert.from_node({"alert_uid": "rp2", "technique_ids": ["T1547.001"]})
    fo = _regpersist()(graph, a, {})
    assert isinstance(fo, Forensics)

    ids = fo.finding_ids()
    assert "regpersist.autostart_write" in ids
    assert "regpersist.installer_writer" in ids             # msiexec = 安装器(白)
    assert "regpersist.suspicious_writer" not in ids        # 非 LOLBin
    assert "regpersist.nonstandard_target" not in ids       # Program Files 签名目录,非临时路径
    assert "regpersist.privileged_account" in ids           # SYSTEM 特权(中性上下文,不 red)

    iw = next(f for f in fo.findings if f.finding_id == "regpersist.installer_writer")
    assert iw.polarity == "white"
    assert iw.attrs == {"writer_image": r"C:\Windows\System32\msiexec.exe"}   # 原值承重
    pa = next(f for f in fo.findings if f.finding_id == "regpersist.privileged_account")
    assert pa.polarity == "neutral"                         # 特权=中性,不单独定 red

    assert fo.bindings["process"] == r"C:\Windows\System32\msiexec.exe"
    assert fo.bindings["account"] == "SYSTEM"
    assert fo.bindings["host"] == "WKS01"
    assert "非标准落地路径(value_data)" not in fo.context     # 良性值不落 ctx 高危键


def test_registry_key_type_classification_runonce_winlogon_services():
    # 键类归类:RunOnce 不被 Run 抢、Winlogon、Services 各自命中
    def _run(key_path):
        graph = FakeGraph([
            ("rv.hive AS hive", [{"hive": "HKLM", "key_path": key_path, "value_name": "x",
                                  "value_data": r"C:\Program Files\App\app.exe", "proc_guid": None,
                                  "writer_image": r"C:\Windows\explorer.exe", "writer_cmdline": "x",
                                  "parent": None, "host": "H1"}]),
        ])
        a = Alert.from_node({"alert_uid": "rpk", "technique_ids": ["T1547.001"]})
        fo = _regpersist()(graph, a, {})
        aw = next(f for f in fo.findings if f.finding_id == "regpersist.autostart_write")
        return aw.attrs["key_type"]

    assert _run(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce") == "runonce"
    assert _run(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") == "run"
    assert _run(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell") == "winlogon"
    assert _run(r"HKLM\SYSTEM\CurrentControlSet\Services\evilsvc") == "services"
    # explorer.exe 既非安装器也非 LOLBin → 写入进程画像 finding 都不触发
    graph = FakeGraph([("rv.hive AS hive", [{"hive": "HKLM", "key_path": r"...\Run",
                        "value_data": r"C:\Program Files\App\app.exe", "proc_guid": None,
                        "writer_image": r"C:\Windows\explorer.exe"}])])
    fo = _regpersist()(graph, Alert.from_node({"alert_uid": "rpk2", "technique_ids": ["T1547.001"]}), {})
    ids = fo.finding_ids()
    assert "regpersist.installer_writer" not in ids and "regpersist.suspicious_writer" not in ids
