"""LSASS 凭据转储(T1003.001)确定性取证。

从触发事件(EID10 访问 lsass)取源进程/掩码/call_trace;沿 SPAWNED 回溯父链、RAN_AS 取身份、
看读后行为。★头号 FP:源进程本身是安全/监控代理(Wazuh/Defender/Sysmon)在做自身遥测 ——
recipe 直接判出来并给 call_trace 转储库指纹,避免 LLM 把"传感器自检"误当攻击、更避免建议杀传感器。
进程签名/哈希是图盲区。
"""
import re

from soc_agent.recipe_lib import security_agent

_DUMP_LIB = re.compile(r"dbghelp|dbgcore|comsvcs|UNKNOWN|unbacked", re.I)


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(src:Process) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(tgt:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN src.process_guid AS src_guid, src.image AS src_image, src.command_line AS src_cmdline, "
        "tgt.image AS target_image, e.granted_access AS granted_access, e.call_trace AS call_trace, "
        "h.hostname AS host",
        aid=aid)
    row = base[0] if base else {}
    ev["源进程与访问掩码"] = {k: v for k, v in row.items() if k != "call_trace"}
    src_guid = row.get("src_guid")

    # ★源进程是否已知安全/监控代理(命中=自身遥测强证伪;绝不 kill/隔离该代理)
    agent = security_agent(row.get("src_image"))
    ev["源进程是否已知安全代理"] = (f"是:{agent}(自身遥测/完整性检查,头号 FP;禁止 kill/隔离该代理或其主机)"
                            if agent else "否(非已知安全/监控代理)")

    # call_trace 转储库指纹:含 dbghelp/dbgcore/comsvcs/UNKNOWN = 转储工具强信号;纯系统+自身模块 = 偏良性
    ct = row.get("call_trace") or ""
    ev["call_trace 指纹"] = {
        "含转储库(dbghelp/dbgcore/comsvcs/UNKNOWN)": bool(_DUMP_LIB.search(ct)),
        "末端模块": ct.split("|")[-1][:120] if ct else None,
    }

    if src_guid:
        ev["父进程链"] = graph.run_cypher(
            "MATCH (p:Process)-[:SPAWNED]->(src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS grandparent, p.image AS parent, p.command_line AS parent_cmdline",
            g=src_guid)
        ev["运行账号"] = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=src_guid)
        ev["读后行为"] = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (src)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (src)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (src)-[:WROTE]->(f:File) "
            "RETURN collect(DISTINCT ip.ip) AS out_ips, collect(DISTINCT c.image) AS spawned, "
            "collect(DISTINCT f.path) AS wrote_files",
            g=src_guid)

    ev["_图盲区"] = ("源进程 EXE 签名/发布者/哈希(白名单只能按 image 路径)、"
                    "call_trace 是否已语义化、dump 文件哈希 —— 未建模")
    return ev
