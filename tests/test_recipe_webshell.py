"""webshell recipe 迁移(dict → 结构化 Forensics/Finding)的 finding 抽取测试。

finding 词典:webshell.file_drop(触发)/ web_process_writer(红)/ in_webroot(红)/
security_agent_writer(白)/ active_use(红)。★writer_image 原值 = 可移植承重 key(进 attrs)。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行(子串须在各查询里唯一)。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _webshell():
    return SkillRegistry(_SKILLS).by_name("webshell").recipe


def test_w3wp_writes_webroot_then_spawns_shell_is_active_webshell():
    # 确定态:w3wp 应用池身份在 wwwroot 写 .aspx + 随后派生 cmd → 活跃 webshell
    graph = FakeGraph([
        ("dropped_paths", [{"writer_guid": "w1",
                            "writer_image": r"C:\Windows\System32\inetsrv\w3wp.exe",
                            "writer_cmd": "",
                            "dropped_paths": [r"C:\inetpub\wwwroot\uploads\shell.aspx"],
                            "host": "castelblack", "host_role": "member_server",
                            "host_criticality": "medium"}]),
        ("spawned_images", [{"spawned_images": [r"C:\Windows\System32\cmd.exe"],
                             "spawned_cmds": ["cmd /c whoami"], "outbound": []}]),
    ])
    a = Alert.from_node({"alert_uid": "ws1", "technique_ids": ["T1505.003"]})
    fo = _webshell()(graph, a, {})

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "webshell.file_drop" in ids                     # 触发本身
    assert "webshell.web_process_writer" in ids            # w3wp 写脚本(红)
    assert "webshell.in_webroot" in ids                    # 落 wwwroot(红)
    assert "webshell.active_use" in ids                    # 随后派生 cmd(红)
    assert "webshell.security_agent_writer" not in ids     # 非安全代理

    # writer_image 原值进 attrs(可移植承重 key)
    wpw = next(f for f in fo.findings if f.finding_id == "webshell.web_process_writer")
    assert wpw.attrs["writer_image"] == r"C:\Windows\System32\inetsrv\w3wp.exe"
    assert wpw.polarity == "red"
    au = next(f for f in fo.findings if f.finding_id == "webshell.active_use")
    assert au.attrs["spawned_shell"] is True and au.attrs["outbound"] is False

    # bindings:process 保留原值、host
    assert fo.bindings["process"] == r"C:\Windows\System32\inetsrv\w3wp.exe"
    assert fo.bindings["host"] == "castelblack"
    assert fo.context.get("落盘事件(写入进程+文件)")        # prose 仍在(喂 LLM)


def test_security_agent_writer_is_benign_white():
    # 良性态:安全代理(ossec)写脚本到自己目录 → security_agent_writer(白),web_process_writer 不触发
    graph = FakeGraph([
        ("dropped_paths", [{"writer_guid": "w2",
                            "writer_image": r"C:\Program Files\ossec-agent\ossec-agent.exe",
                            "writer_cmd": "",
                            "dropped_paths": [r"C:\ProgramData\ossec\active-response\bin\note.aspx"],
                            "host": "srv02", "host_role": "member_server",
                            "host_criticality": "medium"}]),
        # 无 spawned_images 行 → 派生/外连查询返回 [] → active_use 不触发
    ])
    a = Alert.from_node({"alert_uid": "ws2", "technique_ids": ["T1505.003"]})
    fo = _webshell()(graph, a, {})

    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "webshell.file_drop" in ids                     # 触发本身仍在
    assert "webshell.security_agent_writer" in ids         # 安全代理写(白)
    assert "webshell.web_process_writer" not in ids        # 非 web 服务进程
    assert "webshell.in_webroot" not in ids                # 非 web 根
    assert "webshell.active_use" not in ids                # 无派生/外连

    sa = next(f for f in fo.findings if f.finding_id == "webshell.security_agent_writer")
    assert sa.polarity == "white"
    assert "ossec-agent.exe" in (sa.attrs.get("writer_image") or "")   # image 原值进 attrs
    assert sa.attrs.get("agent")                                       # 认出的代理名
    assert fo.bindings["process"] == r"C:\Program Files\ossec-agent\ossec-agent.exe"
    assert fo.bindings["host"] == "srv02"


def test_deploy_process_writes_webroot_is_ambiguous():
    # 中间态:部署进程(msdeploy)写 wwwroot → in_webroot(红) 但非 web 进程/非安全代理/无利用 → 交 LLM
    graph = FakeGraph([
        ("dropped_paths", [{"writer_guid": "w3",
                            "writer_image": r"C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy.exe",
                            "writer_cmd": "",
                            "dropped_paths": [r"C:\inetpub\wwwroot\app\default.aspx"],
                            "host": "castelblack", "host_role": "member_server",
                            "host_criticality": "medium"}]),
    ])
    a = Alert.from_node({"alert_uid": "ws3", "technique_ids": ["T1505.003"]})
    fo = _webshell()(graph, a, {})

    ids = fo.finding_ids()
    assert "webshell.file_drop" in ids
    assert "webshell.in_webroot" in ids                    # 落 wwwroot(红)
    assert "webshell.web_process_writer" not in ids        # msdeploy 非 web 服务进程
    assert "webshell.security_agent_writer" not in ids     # 非安全代理
    assert "webshell.active_use" not in ids                # 无派生/外连
    assert fo.bindings["process"] == r"C:\Program Files\IIS\Microsoft Web Deploy V3\msdeploy.exe"
