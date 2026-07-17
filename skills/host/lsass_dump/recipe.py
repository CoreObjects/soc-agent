"""LSASS 凭据转储(T1003.001)确定性取证。

从触发事件(EID10 访问 lsass)取源进程/掩码/call_trace;沿 SPAWNED 回溯父链、RAN_AS 取身份、
看读后行为。抽出规范化 findings + 实体 bindings。★头号 FP:源进程本身是安全/监控代理在做自身遥测 ——
recipe 直接标出来(hint),真正的可移植承重 key 是 **src_image 原始值**(结论让第二类学),不是硬编码名单。

finding 词典(方法论):lsass_accessed / source_is_security_agent(白,hint)/ dump_lib_loaded(红)/
post_read_exfil(红)。进程签名/哈希是图盲区。
"""
import re

from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import security_agent

_DUMP_LIB = re.compile(r"dbghelp|dbgcore|comsvcs|UNKNOWN|unbacked", re.I)   # Windows 转储相关库/未回填内存


def has_dump_lib(call_trace) -> bool:
    return bool(_DUMP_LIB.search(call_trace or ""))


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(src:Process) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(tgt:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN src.process_guid AS src_guid, src.image AS src_image, src.command_line AS src_cmdline, "
        "tgt.image AS target_image, e.granted_access AS granted_access, e.call_trace AS call_trace, "
        "h.hostname AS host, h.role AS host_role, h.criticality AS host_criticality",
        aid=aid)
    row = base[0] if base else {}
    ctx["源进程与访问掩码"] = {k: v for k, v in row.items() if k != "call_trace"}
    src_guid, src_image, host = row.get("src_guid"), row.get("src_image"), row.get("host")

    if src_image:
        bindings["source_process"] = src_image
    if src_guid:
        bindings["source_process_guid"] = src_guid
    if host:
        bindings["victim_host"] = host

    # 访问了 lsass = 触发本身;src_image 原始值可作可移植指纹 key(结论学出来,非硬编码)
    if row:
        findings.append(Finding("lsass.lsass_accessed",
                                {"src_image": src_image, "granted_access": row.get("granted_access"),
                                 "target_image": row.get("target_image")}, evidence_ref=aid, polarity="neutral"))

    # ★源进程是否已知安全/监控代理(命中=自身遥测强证伪 hint;绝不 kill/隔离该代理)
    agent = security_agent(src_image)
    ctx["源进程是否已知安全代理"] = (f"是:{agent}(自身遥测/完整性检查,头号 FP;禁止 kill/隔离该代理或其主机)"
                            if agent else "否(非已知安全/监控代理)")
    if agent:
        findings.append(Finding("lsass.source_is_security_agent",
                                {"agent": agent, "src_image": src_image}, polarity="white"))

    # call_trace 转储库指纹:含 dbghelp/dbgcore/comsvcs/UNKNOWN = 转储工具强信号
    ct = row.get("call_trace") or ""
    dump = has_dump_lib(ct)
    end_module = ct.split("|")[-1][:120] if ct else None
    ctx["call_trace 指纹"] = {"含转储库(dbghelp/dbgcore/comsvcs/UNKNOWN)": dump, "末端模块": end_module}
    if dump:
        findings.append(Finding("lsass.dump_lib_loaded", {"end_module": end_module}, polarity="red"))

    if src_guid:
        ctx["父进程链"] = graph.run_cypher(
            "MATCH (p:Process)-[:SPAWNED]->(src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS grandparent, p.image AS parent, p.command_line AS parent_cmdline",
            g=src_guid)
        runas = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=src_guid)
        ctx["运行账号"] = runas
        ra = runas[0] if runas else {}
        if ra.get("sam"):
            bindings["run_as_account"] = ra.get("sam")
            if ra.get("domain"):
                bindings["run_as_account_domain"] = ra.get("domain")
        post = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (src)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (src)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (src)-[:WROTE]->(f:File) "
            "RETURN collect(DISTINCT ip.ip) AS out_ips, collect(DISTINCT c.image) AS spawned, "
            "collect(DISTINCT f.path) AS wrote_files",
            g=src_guid)
        ctx["读后行为"] = post
        pr = post[0] if post else {}
        out_ips, wrote = pr.get("out_ips") or [], pr.get("wrote_files") or []
        if out_ips or wrote:
            findings.append(Finding("lsass.post_read_exfil",
                                    {"out_ips": out_ips, "wrote_files": wrote, "spawned": pr.get("spawned") or []},
                                    polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="源进程 EXE 签名/发布者/哈希(白名单只能按 image 路径)、"
                                 "call_trace 是否已语义化、dump 文件哈希 —— 未建模")
