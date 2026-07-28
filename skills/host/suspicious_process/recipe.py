"""可疑进程/命令执行/LOLBin(T1059/T1055/T1218)确定性取证 —— 结构化 Finding 版(seed-dict 型)。

base 证据取自 seed.event / seed.subject / seed.related(**不走 cypher**);触发不一定是 EID1:
EID11(建文件)/EID4104(脚本块)没有子进程,决定性证据是 command_line / script_block_text ——
直接从 seed 取,别假设有父子链。仅当主语进程有 process_guid 才补查图(父链 + 子进程后续行为)。
★把 -EncodedCommand 连锁解码、把 Ansible 配管/执行策略自检等通用良性噪声认出来,再交 LLM
(否则模型看不懂编码命令就幻觉/误判)。

finding 词典(方法论,第一类):
  suspproc.process(触发)/ anomalous_parent(红,异常父进程派生 shell,parent_image 原值承重)/
  decoded_malicious(红,命令行含远程下载/隐藏执行)/ provisioning_noise(白,配管/执行策略自检噪声)/
  followup_exfil(红,子进程后续外连/读 LSASS)。
"哪些 finding → 什么结论"的映射是第二类(qwen 学)。进程 EXE 签名/是否 LOLBin 原版/完整性提权是图盲区。
"""
import re

from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import bucket, decode_chain, provisioning_noise

# 不该派生 shell 的父进程(webshell 载体 w3wp/httpd/tomcat;被利用服务 services/spoolsv/wmiprvse/sqlservr)。
# 原值作可移植承重 key,"是否恶意"的结论交第二类学(不硬编码良性/恶意名单)。
_ANOMALOUS_PARENT = re.compile(r"w3wp|httpd|tomcat|services|spoolsv|wmiprvse|sqlservr", re.I)
# shell / LOLBin 解释器(被上述父进程派生 = 强信号)
_SHELL = re.compile(r"cmd\.exe|powershell|pwsh|rundll32|mshta|regsvr32|cscript|wscript|/bin/(?:ba)?sh", re.I)
# 命令行(含解码后)恶意特征:远程下载执行 / 隐藏执行 / LOLBin 网络加载
_MALICIOUS_CMD = re.compile(
    r"DownloadString|DownloadFile|Net\.WebClient|Invoke-Expression|\bIEX\b|FromBase64String|"
    r"-nop\b|-noni\b|-w\s+hidden|-windowstyle\s+hidden|-enc\b|certutil\s+.*-(?:decode|urlcache)|"
    r"regsvr32\s+/s.*/i:http|mshta\s+http|bitsadmin|iwr\s+http|curl\s+http|wget\s+http", re.I)


def _is_anomalous_parent(image) -> bool:
    return bool(image and _ANOMALOUS_PARENT.search(image))


def _is_shell(image) -> bool:
    return bool(image and _SHELL.search(image))


def _looks_malicious(text) -> bool:
    return bool(text and _MALICIOUS_CMD.search(text))


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    seed = seed or {}
    event = seed.get("event") or {}
    subject = seed.get("subject") or {}
    related = seed.get("related") or []
    ctx, findings, bindings = {}, [], {}

    # 1. 触发事件本体:命令行 / 脚本块 / 完整性级别(哪种 EID 都先把决定性文本捞出来)
    ctx["触发事件"] = {k: event.get(k) for k in
                    ("event_code", "integrity_level", "command_line", "script_block_text",
                     "creation_time", "event_time") if event.get(k) is not None}

    # 2. 主语进程(4104 脚本块时可能为空)
    ctx["主语进程"] = {k: subject.get(k) for k in
                    ("image", "command_line", "pid", "process_guid", "hashes")
                    if subject.get(k) is not None}

    # 3. seed 里的关联:落地文件 / 子进程 / 主机
    files = sorted({r["node"].get("path") for r in related
                    if r.get("rel") == "WROTE" and r.get("node") and r["node"].get("path")})
    children = [r["node"] for r in related if r.get("rel") == "SPAWNED" and r.get("node")]
    host = next((r["node"].get("hostname") for r in related
                 if r.get("rel") == "ON_HOST" and r.get("node")), None)
    ctx["落地文件"] = files
    ctx["子进程(含命令行)"] = [{k: c.get(k) for k in ("image", "command_line", "process_guid")
                          if c.get(k) is not None} for c in children]
    ctx["主机"] = host

    # 实体登记:主语进程(image 保留,承重 key)+ 主机(bindings 抽象)
    image = subject.get("image")
    if image:
        bindings["process"] = image
    if host:
        bindings["host"] = host

    # 触发本身:一条可疑进程/命令执行事件(决定性标量进 attrs,供按事件种类泛化)
    if event or subject:
        findings.append(Finding(
            "suspproc.process",
            {"event_code": event.get("event_code"), "integrity_level": event.get("integrity_level")},
            evidence_ref=aid, polarity="neutral"))

    # 4. ★连锁解码 EncodedCommand(主语 + 各子进程),把编码命令的真身摊开
    decoded = {}
    for label, cl in ([("主语", subject.get("command_line"))]
                      + [(f"子进程{i}", c.get("command_line")) for i, c in enumerate(children)]):
        layers = decode_chain(cl)
        if layers:
            decoded[label] = layers
    if decoded:
        ctx["解码后命令(逐层)"] = decoded

    # 5. ★已知良性供给/自检噪声识别(命中即强证伪 white;label 承重,供白指纹区分是哪类噪声)
    blob = "\n".join(filter(None, (
        [event.get("script_block_text"), subject.get("command_line")]
        + [c.get("command_line") for c in children]
        + [layer for layers in decoded.values() for layer in layers]
        + files)))
    noise = provisioning_noise(blob)
    ctx["供给/自检噪声"] = noise or "未识别到已知良性噪声"
    if noise:
        findings.append(Finding("suspproc.provisioning_noise", {"label": noise}, polarity="white"))

    # 6. 命令行(含解码后)恶意特征 → decoded_malicious(红)
    if _looks_malicious(blob):
        findings.append(Finding(
            "suspproc.decoded_malicious",
            {"decoded_layers": bucket(sum(len(v) for v in decoded.values()))},
            evidence_ref=aid, polarity="red"))

    # 7. 有主语进程 GUID 才回溯父链 / 看子进程后续(EID11/4104 常无 → 跳过,不空查报警)
    guid = subject.get("process_guid")
    if guid:
        rows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS parent_image, p.image AS image", g=guid)
        parent = rows[0] if rows else {}
        ctx["父进程"] = parent
        parent_image = parent.get("parent_image")
        self_image = parent.get("image") or image
        # 异常父进程派生 shell/LOLBin:parent_image ∈ 高危载体 且派生了 shell(parent_image 原值承重)
        if _is_anomalous_parent(parent_image) and _is_shell(self_image):
            findings.append(Finding(
                "suspproc.anomalous_parent",
                {"parent_image": parent_image, "image": self_image},
                evidence_ref=aid, polarity="red"))

        follow = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:SPAWNED]->(d:Process) "
            "OPTIONAL MATCH (p)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (p)-[:ACCESSED]->(l:Process) "
            "RETURN collect(DISTINCT d.image)[0..10] AS descendants, "
            "collect(DISTINCT ip.ip)[0..10] AS out_ips, "
            "collect(DISTINCT l.image)[0..10] AS accessed_procs", g=guid)
        fr = follow[0] if follow else {}
        ctx["子进程后续行为"] = fr
        out_ips = fr.get("out_ips") or []
        accessed = fr.get("accessed_procs") or []
        descendants = fr.get("descendants") or []
        has_lsass = any("lsass" in (p or "").lower() for p in accessed)
        # 派生 → 外连 / 读 LSASS = 攻击链闭环(子进程后续行为)
        if out_ips or has_lsass:
            findings.append(Finding(
                "suspproc.followup_exfil",
                {"has_outbound": bool(out_ips), "has_lsass_access": has_lsass,
                 "spawn_count": bucket(len(descendants))},
                evidence_ref=aid, polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="进程 EXE 签名/是否 LOLBin 原版、完整性级别/Token 提权、"
                                 "注入子行为细节 —— 未建模;已解码命令与噪声标签见 context")
