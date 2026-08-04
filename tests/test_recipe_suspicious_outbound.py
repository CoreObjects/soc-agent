"""suspicious_outbound recipe 迁移(旧 dict → 结构化 Forensics/Finding)的 finding 抽取测试。

覆盖:①可疑态(LOLBin + 非标端口 + 反复外连 → 出红 finding);②良性态(命中 provisioning_noise
供给噪声 → white,且 LOLBin 不触发)。断言 Forensics 类型 / finding_ids / bindings / context。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行(子串须在各查询里唯一),解耦调用顺序。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _suspicious_outbound():
    return SkillRegistry(_SKILLS).by_name("suspicious_outbound").recipe


def _finding(fo, fid):
    return next(f for f in fo.findings if f.finding_id == fid)


# ---------- ① 可疑态:LOLBin(rundll32)+ 非标端口(4444)+ 反复外连(30) → red ----------
def test_lolbin_nonstandard_repetitive_emits_red_findings_and_bindings():
    graph = FakeGraph([
        # base 查询(唯一子串 "e.dst_port AS dst_port")
        ("e.dst_port AS dst_port",
         [{"proc_guid": "pg-c2", "image": r"C:\Windows\System32\rundll32.exe",
           "command_line": r"rundll32.exe url.dll,OpenURL http://203.0.113.5:4444",
           "parent": "winword.exe", "account": "north\\jon.snow",
           "dst_ip": "203.0.113.5", "dst_port": 4444, "proto": "tcp", "host": "WKS01"}]),
        # 外连反复性聚合(唯一子串 "sum(coalesce(e.count,1)) AS count")
        ("sum(coalesce(e.count,1)) AS count",
         [{"count": 30, "first_seen": "2026-07-20T01:00:00", "last_seen": "2026-07-20T03:00:00"}]),
    ])
    a = Alert.from_node({"alert_uid": "so1", "technique_ids": ["T1571"]})
    fo = _suspicious_outbound()(graph, a, {})

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "outbound.connection" in ids
    assert "outbound.nonstandard_port" in ids               # 4444 非常用
    assert "outbound.lolbin" in ids                          # rundll32
    assert "outbound.repetitive" in ids                      # 30 次
    assert "outbound.provisioning_noise" not in ids          # 无良性供给噪声

    lolbin = _finding(fo, "outbound.lolbin")
    assert lolbin.polarity == "red"
    assert "rundll32.exe" in (lolbin.attrs.get("image") or "")   # image 原值承重(可移植指纹 key)

    rep = _finding(fo, "outbound.repetitive")
    assert rep.polarity == "red" and rep.attrs["count_bucket"] == "massive"   # 30 → massive,分桶入 attrs

    # 端口是易变字段 → 不进决定性 attrs;presence-only finding + 端口值落 ctx
    assert _finding(fo, "outbound.nonstandard_port").attrs == {}
    assert fo.context["非常用端口"]["dst_port"] == 4444

    assert fo.bindings["process"] == r"C:\Windows\System32\rundll32.exe"   # 进程 image 原值保留
    assert fo.bindings["ip"] == "203.0.113.5"
    assert fo.bindings["host"] == "WKS01"
    assert fo.context.get("进程与目标+父链")                 # prose 仍在(喂 LLM)
    assert fo.context.get("外连聚合(反复性)")

    # 至少一条红信号(可疑态)
    assert any(f.polarity == "red" for f in fo.findings)


# ---------- ② 良性态:命中 Ansible 供给噪声 → white,非 LOLBin,常见端口 ----------
def test_provisioning_noise_benign_emits_white_and_no_lolbin():
    graph = FakeGraph([
        ("e.dst_port AS dst_port",
         [{"proc_guid": "pg-ci", "image": r"C:\ProgramData\ansible\exec_wrapper.exe",
           "command_line": "exec_wrapper.exe; ConvertFrom-AnsibleJson $payload; Write-AnsibleLog ok",
           "parent": "services.exe", "account": "north\\svc_ci",
           "dst_ip": "10.0.0.10", "dst_port": 8080, "proto": "tcp", "host": "SRV05"}]),
        ("sum(coalesce(e.count,1)) AS count",
         [{"count": 2, "first_seen": "2026-07-20T01:00:00", "last_seen": "2026-07-20T01:05:00"}]),
    ])
    a = Alert.from_node({"alert_uid": "so2", "technique_ids": ["T1571"]})
    fo = _suspicious_outbound()(graph, a, {})

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "outbound.connection" in ids
    assert "outbound.provisioning_noise" in ids              # 命中 Ansible 供给噪声
    assert "outbound.lolbin" not in ids                      # 非 LOLBin(exec_wrapper.exe)
    assert "outbound.nonstandard_port" not in ids            # 8080 = 常见端口

    noise = _finding(fo, "outbound.provisioning_noise")
    assert noise.polarity == "white"
    assert "ansible_exec_wrapper" in (noise.attrs.get("label") or "")   # label 承重(通用良性模式)

    rep = _finding(fo, "outbound.repetitive")
    assert rep.polarity == "neutral" and rep.attrs["count_bucket"] == "low"   # 2 → low,不 red

    # 良性态:无任何红信号
    assert not any(f.polarity == "red" for f in fo.findings)

    assert fo.bindings["process"] == r"C:\ProgramData\ansible\exec_wrapper.exe"
    assert fo.bindings["ip"] == "10.0.0.10"
    assert fo.bindings["host"] == "SRV05"
    assert fo.context["供给/自检噪声"] != "未识别到已知良性噪声"
