"""可疑外连 / 罕见进程 C2 通道(T1571/T1090)确定性取证 —— 结构化 finding 版。

从触发事件取发起进程 + 外连目标(IP/端口/proto)+ 父链/账号;解码发起命令(LOLBin 常
-EncodedCommand,不解码=判不透意图)+ 已知良性供给证伪;外连反复性数连接事件(粗周期信号)。
抽出规范化 findings + 实体 bindings,再交 LLM 定性 / 第二类经验匹配。★cypher 保持不动。

finding 词典(方法论):
  outbound.connection        触发本身(neutral;proto 承 attrs,端口是易变字段只进 ctx)
  outbound.nonstandard_port  非常用端口(presence-only,端口值进 ctx)
  outbound.repetitive        反复外连(count 分桶,反复=通道而非误触)
  outbound.lolbin            LOLBin 发起外连(红;image 原值承重,可移植指纹 key)
  outbound.provisioning_noise  命中已知良性供给/自检(白,label 承重)
红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。

代理后落点、协议真伪、IP/域 reputation 需探针,是图盲区。
"""
from soc_agent.forensics import Finding, Forensics
from soc_agent.graph.pivot import resolve_pivot
from soc_agent.recipe_lib import bucket, coverage_absent, decode_chain, provisioning_noise

# 本 recipe 能在哪些主语上工作(WP7 pivot 多态):
#   process  —— Sysmon EID3 那类"进程发起外连"(GOAD 今天走这条,查询字面量原样保留)
#   endpoint —— Zeek/NetFlow/防火墙那类**没有发起进程**的流记录,主语是源 IP
# host/principal 拿不到"谁连了哪儿",不在此列 → 产出 `_coverage.absent`,绝不静默返回空。
SUPPORTED_PIVOTS = ("process", "endpoint")

# ★process 分支:与迁移前**逐字相同**(Windows 侧零回归的依据就是它没被动过)
_BASE_PROCESS = (
    "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
    "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
    "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
    "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
    "OPTIONAL MATCH (p)-[:RAN_AS]->(acc:Account) "
    "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
    "parent.image AS parent, acc.sam AS account, "
    "ip.ip AS dst_ip, e.dst_port AS dst_port, e.proto AS proto, h.hostname AS host")

# endpoint 分支:同一行形状,进程侧三列恒 null —— 下游逻辑一行不用改;
# 而"进程侧为空"会被显式记成 `_coverage.absent`,不会被当成"查过了、没异常"。
_BASE_ENDPOINT = (
    "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(src:IPAddress) "
    "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
    "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
    "RETURN null AS proc_guid, null AS image, null AS command_line, "
    "null AS parent, null AS account, src.ip AS src_ip, "
    "ip.ip AS dst_ip, e.dst_port AS dst_port, e.proto AS proto, h.hostname AS host")

# 常见/正当业务端口(Web/代理/DB/邮件/目录服务等);不在此集合的 → 提示"非常用"(端口值只进 ctx)
_COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995,
                 1433, 3306, 3128, 5432, 5672, 8080, 8443}

# LOLBin:本不该联网、常被滥用直连外部的系统二进制。结构判别(按进程名),不硬编码厂商/路径。
_LOLBINS = {"rundll32", "regsvr32", "mshta", "powershell", "pwsh", "cscript", "wscript",
            "certutil", "bitsadmin", "wmic", "msbuild", "installutil", "regasm", "regsvcs"}


def _port_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def is_nonstandard_port(dst_port) -> bool:
    """端口不在常见业务/代理端口集合内 = 非常用(粗信号,单条件不足以定性)。"""
    p = _port_int(dst_port)
    return p is not None and p not in _COMMON_PORTS


def is_lolbin(image) -> bool:
    """image 的进程名(去路径/去 .exe)命中 LOLBin 集合。"""
    if not image:
        return False
    base = str(image).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base in _LOLBINS


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 0. ★先定主语:是进程发起的外连,还是一条只有源 IP 的流记录?
    pivot = resolve_pivot(graph, aid)
    if pivot is None or pivot.kind not in SUPPORTED_PIVOTS:
        return Forensics(
            findings=[coverage_absent("suspicious_outbound", need="network_flow_telemetry",
                                      pivot=pivot, detail="主语既不是进程也不是端点,取不到「谁连了哪儿」")],
            # ★与正常路径同一个键:否则报表里"没有主语"和"主语不被本 recipe 支持"
            #   会混成一格 —— 而这正是接新源时最需要分清的一件事(缺阶梯 vs 缺支持)。
            context={"主语(pivot)": {"kind": getattr(pivot, "kind", None),
                                  "label": getattr(pivot, "label", None),
                                  "supported": False,
                                  "supported_pivots": list(SUPPORTED_PIVOTS)}},
            blind_spots="这条告警的触发事件没有可用主语(进程/源端点),本 recipe 的判别链条整条不成立")
    ctx["主语(pivot)"] = {"kind": pivot.kind, "label": pivot.label, "supported": True,
                       "key": pivot.key_prop, "value": pivot.key_value}

    # 1. 发起主语 + 外连目标(IP/端口/proto)+ 父链 + 账号
    base = graph.run_cypher(_BASE_PROCESS if pivot.kind == "process" else _BASE_ENDPOINT, aid=aid)
    b = base[0] if base else {}
    ctx["进程与目标+父链"] = b
    image, dst_ip = b.get("image"), b.get("dst_ip")
    dst_port, proto, host = b.get("dst_port"), b.get("proto"), b.get("host")

    # 实例登记:process 保留 image 原值(承重 key,不抽象);ip/host = 身份角色 → 抽象为占位符
    if image:
        bindings["process"] = image
    if dst_ip:
        bindings["ip"] = dst_ip
    if host:
        bindings["host"] = host
    if b.get("src_ip"):
        bindings["src_ip"] = b["src_ip"]

    # ★没有进程遥测 = LOLBin / 命令行解码 / 供给噪声证伪三条判据整条失效 —— 明说,别装作查过了。
    if not image:
        findings.append(coverage_absent("suspicious_outbound", need="process_telemetry", pivot=pivot,
                                        detail="无发起进程 image/command_line:"
                                               "LOLBin 判别、编码命令解码、良性供给证伪 均不可用"))

    # 触发本身:一次外连(proto 承 attrs 供指纹按"协议种类"泛化;端口易变,只进 ctx 不入 attrs)
    if b:
        findings.append(Finding("outbound.connection", {"proto": proto},
                                evidence_ref=aid, polarity="neutral"))

    # 2. 非常用端口(presence-only;端口值随 base 行留在 ctx,不入 attrs 免污染指纹)
    if is_nonstandard_port(dst_port):
        ctx["非常用端口"] = {"dst_port": _port_int(dst_port), "note": "不在常见业务/代理端口集合内"}
        findings.append(Finding("outbound.nonstandard_port", {}, polarity="neutral"))

    # 3. ★解码发起命令行(EncodedCommand 连锁解开)+ 已知良性供给/自检证伪 —— 编码外连的真身摊开
    layers = decode_chain(b.get("command_line") or "")
    if layers:
        ctx["发起命令解码(逐层)"] = layers
    noise = provisioning_noise("\n".join([b.get("command_line") or ""] + layers))
    ctx["供给/自检噪声"] = noise or "未识别到已知良性噪声"
    if noise:
        # label = 命中的通用良性模式(可移植白指纹承重 key;凡该类供给/自检环境皆有)
        findings.append(Finding("outbound.provisioning_noise", {"label": noise}, polarity="white"))

    # 4. LOLBin 发起外连(image 原值承重;内/外由 ip.type 定但未建模=盲区,有外连目标即取证)
    if dst_ip and is_lolbin(image):
        findings.append(Finding("outbound.lolbin", {"image": image}, evidence_ref=aid, polarity="red"))

    # 5. 外连反复性:数连接事件 —— 反复=通道而非误触。
    #    ★count-aware:折叠后代表事件带 e.count(=次数),未折叠事件视为 1;折叠前恒等于 count(e)。
    if pivot.key_value is not None and dst_ip:
        rows = graph.run_cypher(
            "MATCH " + pivot.match() + " "
            "MATCH (e)-[:CONNECTED_TO]->(:IPAddress {ip:$ip}) "
            "RETURN sum(coalesce(e.count,1)) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            pk=pivot.key_value, ip=dst_ip)
        agg = rows[0] if rows else {}
        ctx["外连聚合(反复性)"] = agg
        cnt = agg.get("count")
        if cnt is not None:
            findings.append(Finding("outbound.repetitive", {"count_bucket": bucket(cnt)},
                                    polarity="red" if (cnt or 0) >= 5 else "neutral"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="目标 IP/域 reputation(无情报源)、代理之后的真实外部目标(T1090)、"
                                 "协议 vs 端口错配(无 DPI)、字节量/时长 —— 需 NDR/情报探针")
