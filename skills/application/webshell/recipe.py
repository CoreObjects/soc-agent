"""Webshell 落盘(T1505.003)确定性取证 —— host-side 主线,结构化 Finding 版。

触发 = Sysmon EID11 写 web 脚本(.aspx/.asp/.php/.jsp...)。核心判别:
★写入进程是不是 web 服务进程(w3wp/php-cgi/tomcat = webshell 强信号;部署/管理进程 = 偏良性;安全代理 = FP)
+ 落盘路径是否 web 根 + 编码写入命令连锁解码看真身 + 写入进程随后有没有派生 shell/回连(利用)。
(WAF 上传请求是可选佐证,需 WAF→后端同主机映射,当前盲。)

finding 词典(方法论):file_drop(触发)/ web_process_writer(红,web 进程写脚本;writer_image 原值承重)/
in_webroot(红,落 web 根)/ security_agent_writer(白,安全代理写=FP;image 原值承重)/
active_use(红,写后派生 shell 或外连)。红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。
★可移植承重 key = writer_image 原始值(照 lsass 把 src_image 原值进 attrs 的做法),结论让第二类学,非硬编码名单。
"""
import re

from soc_agent.forensics import Finding, Forensics
from soc_agent.graph.pivot import resolve_pivot
from soc_agent.recipe_lib import coverage_absent, decode_chain, provisioning_noise, security_agent

# 本 recipe 能在哪些主语上工作(WP7 pivot 多态):
#   process —— Sysmon EID11(GOAD 今天走这条,查询字面量原样保留);判别链条**完整**
#   host    —— 纯 FIM/文件审计源(没有写入进程归因):只拿得到"落了什么、落在哪",
#              ★核心判别①(写入进程是不是 web 服务进程)结构上不成立 → 显式 `_coverage.absent`
# ★这里不硬凑:webshell 的判别本质就是"谁写的",拿不到写入者就是拿不到;
#   把话说清楚,比编一个看起来合理的结论有价值得多。
SUPPORTED_PIVOTS = ("process", "host")

# ★process 分支:与迁移前**逐字相同**(Windows 侧零回归的依据就是它没被动过)
_BASE_PROCESS = (
    "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(w:Process) "
    "OPTIONAL MATCH (e)-[:WROTE]->(f:File) "
    "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
    "RETURN w.process_guid AS writer_guid, w.image AS writer_image, w.command_line AS writer_cmd, "
    "collect(DISTINCT f.path) AS dropped_paths, "
    "h.hostname AS host, h.role AS host_role, h.criticality AS host_criticality")

# host 分支:无写入进程归因,写入者三列恒 null;落盘文件与主机画像仍然拿得到
_BASE_HOST = (
    "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event) "
    "OPTIONAL MATCH (e)-[:WROTE]->(f:File) "
    "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
    "RETURN null AS writer_guid, null AS writer_image, null AS writer_cmd, "
    "collect(DISTINCT f.path) AS dropped_paths, "
    "h.hostname AS host, h.role AS host_role, h.criticality AS host_criticality")

_WEBROOT_HINT = ("inetpub", "wwwroot", "htdocs", "\\www\\", "webapps", "\\web\\")
_SHELL = re.compile(r"cmd\.exe|powershell|pwsh|/bin/(?:ba)?sh|\bbash\b|\bsh\b", re.I)


def _spawned_shell(images) -> bool:
    """随后派生的进程里有没有交互式 shell(cmd/powershell/pwsh/bash/sh)。"""
    return any(_SHELL.search(i or "") for i in (images or []))


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # ★先定主语:有写入进程(EID11 那类),还是只有一条文件变更记录(纯 FIM)?
    pivot = resolve_pivot(graph, aid)
    if pivot is None or pivot.kind not in SUPPORTED_PIVOTS:
        return Forensics(
            findings=[coverage_absent("webshell", need="file_write_telemetry", pivot=pivot,
                                      detail="主语既不是写入进程也不是主机,取不到「谁往哪儿写了什么」")],
            # ★与正常路径同一个键:否则报表里"没有主语"和"主语不被本 recipe 支持"
            #   会混成一格 —— 而这正是接新源时最需要分清的一件事(缺阶梯 vs 缺支持)。
            context={"主语(pivot)": {"kind": getattr(pivot, "kind", None),
                                  "label": getattr(pivot, "label", None),
                                  "supported": False,
                                  "supported_pivots": list(SUPPORTED_PIVOTS)}},
            blind_spots="这条告警的触发事件没有可用主语(写入进程/主机),落盘判别整条不成立")
    ctx["主语(pivot)"] = {"kind": pivot.kind, "label": pivot.label, "supported": True,
                       "key": pivot.key_prop, "value": pivot.key_value}

    base = graph.run_cypher(_BASE_PROCESS if pivot.kind == "process" else _BASE_HOST, aid=aid)
    b = base[0] if base else {}
    wg, wimg = b.get("writer_guid"), (b.get("writer_image") or "")
    # 反斜杠归一 + 去重(同一文件因 alert 双转义/winlogbeat 单转义建了两个 File 节点)
    paths = sorted({(p or "").replace("\\\\", "\\") for p in (b.get("dropped_paths") or []) if p})

    il = wimg.lower()
    # ★核心判别①:写入进程是不是 web 服务进程(是→webshell 强信号;否→部署/管理写脚本,偏良性)
    writer_is_webproc = any(k in il for k in ("w3wp", "php-cgi", "httpd", "tomcat", "\\java"))
    agent = security_agent(wimg)                                          # 安全代理写脚本=FP
    # ★核心判别②:落盘路径是否 web 根
    in_webroot = any(any(hint in p.lower() for hint in _WEBROOT_HINT) for p in paths)

    # 人读证据:原始行 + 归一路径 + 判别布尔(dropped_paths 是 list → 只进 ctx/交 DSL,不入指纹 attrs)
    evrow = dict(b)
    evrow["dropped_paths"] = paths
    evrow["writer_is_webproc"] = writer_is_webproc
    evrow["writer_is_security_agent"] = agent
    evrow["in_webroot"] = in_webroot
    ctx["落盘事件(写入进程+文件)"] = evrow

    host = b.get("host")
    if wimg:
        bindings["process"] = wimg          # 进程镜像原值 = 可移植承重 key(fingerprint 保留不抽象)
    if host:
        bindings["host"] = host

    # ★没有写入进程归因 = 本 skill 的核心判别①整条失效。必须明说:
    #   否则 writer_is_webproc/agent 双双 False,读起来像"查过了,写入者不是 web 进程也不是安全代理",
    #   而事实是"根本不知道谁写的" —— 这两件事对结论的意义完全相反。
    if not wimg:
        findings.append(coverage_absent(
            "webshell", need="process_telemetry", pivot=pivot,
            detail="无写入进程归因:核心判别①(写入者是否 web 服务进程)、安全代理证伪、"
                   "写入命令解码、写后派生/外连 全部不可用,只剩落盘路径一条判据"))

    # 触发本身:一次脚本落盘(writer_image 原值进 attrs 作承重 key;host_role/criticality 标量随行)
    if base:
        findings.append(Finding(
            "webshell.file_drop",
            {"writer_image": wimg or None,
             "host_role": b.get("host_role"), "host_criticality": b.get("host_criticality")},
            evidence_ref=aid, polarity="neutral"))

    # ★核心判别①:web 服务进程写脚本 = webshell 强信号(writer_image 原值承重,结论让第二类学)
    if writer_is_webproc:
        findings.append(Finding("webshell.web_process_writer", {"writer_image": wimg}, polarity="red"))

    # ★核心判别②:落 web 根(存在即信号,presence-only)
    if in_webroot:
        findings.append(Finding("webshell.in_webroot", {}, polarity="red"))

    # 安全代理写脚本 = 自身行为强证伪(良性;image 原值进 attrs 作可移植 FP 承重 key)
    if agent:
        findings.append(Finding("webshell.security_agent_writer",
                                {"agent": agent, "writer_image": wimg}, polarity="white"))

    # 解码写入命令(EncodedCommand 连锁)+ 已知良性供给证伪 —— 看写进去的到底是什么(证据入 ctx)
    layers = decode_chain(b.get("writer_cmd") or "")
    if layers:
        ctx["写入命令解码(逐层)"] = layers
    ctx["供给/自检噪声"] = provisioning_noise(
        "\n".join([b.get("writer_cmd") or ""] + layers)) or "未识别到已知良性噪声"

    # ★利用:写入进程随后派生 shell / 外连(把"落盘"升"活跃 webshell")
    if wg:
        post = graph.run_cypher(
            "MATCH (w:Process {process_guid:$g}) "
            "OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (w)-[:CONNECTED_TO]->(dst:IPAddress) "
            "RETURN collect(DISTINCT c.image) AS spawned_images, collect(DISTINCT c.command_line) AS spawned_cmds, "
            "collect(DISTINCT dst.ip) AS outbound", g=wg)
        pr = post[0] if post else {}
        ctx["写入进程-派生与外连"] = pr
        spawned_images = pr.get("spawned_images") or []
        outbound = pr.get("outbound") or []
        spawned_shell = _spawned_shell(spawned_images)
        # 决定性字段用标量布尔(spawned_images/outbound 是 list → 只进 ctx/交 DSL)
        if spawned_shell or outbound:
            findings.append(Finding("webshell.active_use",
                                    {"spawned_shell": spawned_shell, "outbound": bool(outbound)},
                                    polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="落盘文件哈希/内容、WAF 上传请求关联(需 WAF→后端同主机映射)、"
                                 "站点物理路径→URL 可达性、落盘脚本后续被 w3wp 读取执行 —— 待补。"
                                 "写入进程/路径/解码写入内容/随后派生外连 已入图可用")
