"""Ingress Tool Transfer(T1105)确定性取证 —— 结构化 Forensics+Finding 版(seed-dict 型)。

要点(与 suspicious_process 同源):此类告警极吵、绝大多数是正常下载/系统自检。触发常是
EID11(掉文件),决定性证据是"谁写的、写了啥、命令行(解码后)是不是良性运维/策略探针"。
base 证据取自 seed(event/subject/related),仅在有 process_guid 时补查图(父进程/外连/落地即执行)。
不查图里没有的字段(ip.reputation / asn / file.sha256,全空 → 图盲区)。

finding 词典(方法论,第一类):ingress.download(触发)/ ingress.lolbin_download(红,image 原值承重)/
ingress.whitelisted_downloader(白)/ ingress.provisioning_noise(白)/ ingress.dropped_then_executed(红)。
★落地文件/外连 IP 是 list → 只进 context,不进指纹 attrs(交 DSL 存在性)。"哪些 finding→什么结论"交第二类(qwen 学)。
"""
import re

from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import decode_chain, provisioning_noise

# LOLBin 下载器:image 命中 certutil/bitsadmin/mshta,或 powershell 带下载动词(image 原值 = 可移植承重 key)
_LOLBIN_IMAGE = re.compile(r"certutil|bitsadmin|mshta", re.I)
_PS_IMAGE = re.compile(r"powershell|pwsh", re.I)
_PS_DOWNLOAD = re.compile(
    r"IWR|Invoke-WebRequest|DownloadString|DownloadFile|DownloadData|"
    r"Net\.WebClient|Start-BitsTransfer", re.I)

# 已知白名单下载器/更新器/浏览器(良性大宗;原值放 attrs,具体结论让第二类学,不硬编码判决)
_WHITELIST_DOWNLOADER = re.compile(
    r"msedge|chrome|firefox|svchost|TiWorker|TrustedInstaller|MsMpEng|"
    r"OneDrive|Teams|msiexec|wuauclt", re.I)


def _lolbin_method(image, command_line):
    """LOLBin 下载器判定 → 方法标签(certutil/bitsadmin/mshta/powershell_download)或 None。"""
    hay = " ".join(filter(None, (image, command_line)))
    m = _LOLBIN_IMAGE.search(hay)
    if m:
        return m.group(0).lower()
    if _PS_IMAGE.search(image or "") and _PS_DOWNLOAD.search(command_line or ""):
        return "powershell_download"
    return None


def _whitelisted(image):
    m = _WHITELIST_DOWNLOADER.search(image or "")
    return m.group(0) if m else None


def collect(graph, alert, seed=None) -> Forensics:
    seed = seed or {}
    event = seed.get("event") or {}
    subject = seed.get("subject") or {}
    related = seed.get("related") or []
    ctx, findings, bindings = {}, [], {}

    image = subject.get("image")
    command_line = subject.get("command_line")
    event_code = event.get("event_code")

    # 1. 触发/下载进程 + 命令行 + 事件类型(原始证据进 context)
    ctx["触发进程"] = {k: subject.get(k) for k in ("image", "command_line", "pid", "process_guid")
                    if subject.get(k) is not None}
    ctx["事件类型"] = event_code

    # 2. 落地文件 / 主机(来自 seed)—— list 只进 context,不进指纹 attrs
    files = sorted({r["node"].get("path") for r in related
                    if r.get("rel") == "WROTE" and r.get("node") and r["node"].get("path")})
    host = next((r["node"].get("hostname") for r in related
                 if r.get("rel") == "ON_HOST" and r.get("node")), None)
    ctx["落地文件"] = files
    ctx["主机"] = host

    # 实体登记:进程(image 保留原值),主机(身份角色 → 指纹占位符抽象)
    if image:
        bindings["process"] = image
    if host:
        bindings["host"] = host

    # 触发本身:一次下载/掉文件(event_code 决定性标量进 attrs,供按"事件类型"泛化)
    findings.append(Finding("ingress.download", {"event_code": event_code},
                            evidence_ref=alert.alert_uid, polarity="neutral"))

    # 3. ★解码命令行 + 认良性噪声(把"掉可执行文件"其实是策略探针/Ansible 供给的 FP 认出来)
    layers = decode_chain(command_line)
    if layers:
        ctx["解码后命令(逐层)"] = layers
    blob = "\n".join(filter(None, [command_line] + layers + files))
    noise = provisioning_noise(blob)
    ctx["供给/自检噪声"] = noise or "未识别到已知良性噪声"
    if noise:
        findings.append(Finding("ingress.provisioning_noise", {"label": noise}, polarity="white"))

    # 4. 下载进程画像:LOLBin(红,image 原值承重)vs 白名单更新器/浏览器(白,presence-only 倾向)
    lolbin = _lolbin_method(image, "\n".join(filter(None, [command_line] + layers)))
    wl = _whitelisted(image)
    if lolbin:
        findings.append(Finding("ingress.lolbin_download",
                                {"image": image, "method": lolbin}, evidence_ref=alert.alert_uid, polarity="red"))
    if wl:
        findings.append(Finding("ingress.whitelisted_downloader",
                                {"image": image, "downloader": wl}, polarity="white"))

    # 5. 下载语义:父进程 + 外连目的 + 落地即执行(有 process_guid 才查;reputation/asn 图无 → 不查)
    pg = subject.get("process_guid")
    spawned = []
    if pg:
        rows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS parent_image", g=pg)
        ctx["父进程"] = rows[0].get("parent_image") if rows else None
        ctx["外连目的(仅存在性,信誉是盲区)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (p)-[:QUERIED]->(d:Domain) "
            "RETURN collect(DISTINCT ip.ip)[0..20] AS ips, "
            "collect(DISTINCT d.fqdn)[0..20] AS domains", g=pg)
        srows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (p)-[:SPAWNED]->(c:Process) "
            "RETURN collect(DISTINCT c.image)[0..10] AS spawned", g=pg)
        spawned = (srows[0].get("spawned") if srows else None) or []
        ctx["落地即执行(SPAWNED 子进程)"] = spawned

    # 落地文件 + 随后被 SPAWNED 执行 = 高危闭环(list 交 context,finding 走 presence-only 红)
    if files and spawned:
        findings.append(Finding("ingress.dropped_then_executed", {}, evidence_ref=alert.alert_uid, polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="完整下载 URL/文件名、落地文件哈希、IP/域信誉(reputation/asn 未建模、全空)、"
                                 "下载进程 EXE 签名 —— 未建模;编码命令已解码见 context,据此与噪声标签判良性/恶意")
