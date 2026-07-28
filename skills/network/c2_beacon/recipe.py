"""C2 信标 / DNS beacon(T1071/T1568)确定性取证 —— 结构化 finding 版。

从触发事件取发起进程 + 目标(IP/域);解码发起命令(EncodedCommand)+ 良性供给证伪;
外连/DNS 反复性数事件(周期性粗信号);目标域新鲜度;发起进程父链/账号。
精确节律/jitter、DNS 深度特征、reputation/解析扇出需探针,是图盲区。

★核心方法论:**周期性单独绝不 TP**。三信号(① 周期性 ② 目标可疑 ③ 进程异常)各自独立成 finding,
recipe 只观察、不下结论;"周期 ∧ 新域 ∧ 可疑进程 才 TP" 的组合交第二类经验/DSL(qwen 学)。

finding 词典(方法论):periodic_beacon(N/R,外连聚合 count 分桶,高=可疑但不单独定性)/
new_domain(R,目标域近期首见)/ suspicious_process(R,非浏览器/可疑父链,image 原值承重)/
known_updater(W,image 命中已知更新器/agent)/ provisioning_noise(W,Ansible 供给等已知良性)。
红=攻击迹象,白=良性豁免。
"""
import re
from datetime import datetime

from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import bucket, decode_chain, provisioning_noise, security_agent

# 浏览器 = 周期性 HTTP/DNS 外连的正常发起者(通用允许集,非厂商黑名单);非浏览器发起信标 = 可疑
_BROWSER = re.compile(r"chrome\.exe|msedge\.exe|firefox\.exe|iexplore\.exe|opera\.exe|brave\.exe|safari", re.I)
# 已知系统/浏览器更新器:凡有自动更新的环境皆有(与 recipe_lib.security_agent 互补 —— 后者认监控/EDR agent)。
# 通用更新器名,不绑定具体环境;具体 image 良恶结论仍由 qwen 慢通道学(image 原值进 attrs 承重)。
_UPDATER = re.compile(
    r"GoogleUpdate|(?:Microsoft)?EdgeUpdate|MsEdgeUpdate|wuauclt|UsoClient|MoUsoCoreWorker|"
    r"winget|OneDrive.*Updater|jusched|AdobeARM",
    re.I)
# 可疑父链:Office/脚本宿主/shell 派生的外连进程(Office→powershell→外连 = 典型攻击链)
_SUSPICIOUS_PARENT = re.compile(r"winword|excel|powerpnt|outlook|mshta|wscript|cscript|powershell|cmd\.exe", re.I)

_NEW_DOMAIN_MAX_AGE_DAYS = 30    # 目标域首见距参考时刻 ≤ 此天数 = "新域"(reputation/DGA 情报是图盲区,此为粗判)


def _parse_ts(s):
    """容错解析 ISO 时间戳(date 或 datetime,'Z' 归一);解析失败 → None。剥 tzinfo 免 aware/naive 混算。"""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).strip().replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def _age_days(first_seen, ref):
    """域首见相对参考时刻的天数;任一无法解析 → None(降级,不臆断新旧)。"""
    a, b = _parse_ts(first_seen), _parse_ts(ref)
    if a is None or b is None:
        return None
    return (b - a).days


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
        "OPTIONAL MATCH (e)-[:QUERIED]->(d:Domain) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
        "e.dst_port AS dst_port, ip.ip AS dst_ip, d.fqdn AS dst_domain, h.hostname AS host",
        aid=aid)
    b = base[0] if base else {}
    ctx["进程与目标"] = b
    pg, image = b.get("proc_guid"), b.get("image")
    dst_ip, dst_domain, host = b.get("dst_ip"), b.get("dst_domain"), b.get("host")

    # 实体登记:进程 image 保留原值(语义承重 key),身份角色(ip/域/主机)供指纹抽象为占位符
    if image:
        bindings["process"] = image
    if dst_ip:
        bindings["ip"] = dst_ip
    if dst_domain:
        bindings["domain"] = dst_domain
    if host:
        bindings["host"] = host

    # ★解码发起命令行 + 良性供给/自检证伪 —— 编码信标的真身摊开
    layers = decode_chain(b.get("command_line") or "")
    if layers:
        ctx["发起命令解码(逐层)"] = layers
    noise = provisioning_noise("\n".join([b.get("command_line") or ""] + layers))
    ctx["供给/自检噪声"] = noise or "未识别到已知良性噪声"
    if noise:
        findings.append(Finding("c2.provisioning_noise", {"label": noise}, evidence_ref=aid, polarity="white"))

    # 外连/DNS 反复性 —— 周期性粗信号(count 分桶;高=可疑但单独绝不定性)
    ref_time = alert.time                 # 域新鲜度参考时刻:优先告警时间,缺则退聚合末次时间
    if pg and dst_ip:                     # HTTP beacon:数连接事件(聚合边不存 count,现算)
        http = graph.run_cypher(
            "MATCH (e:Event)-[:BY]->(:Process {process_guid:$g}) "
            "MATCH (e)-[:CONNECTED_TO]->(:IPAddress {ip:$ip}) "
            "RETURN count(e) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            g=pg, ip=dst_ip)
        ctx["外连聚合(周期性)"] = http
        _emit_periodic(findings, http, "http", aid)
        ref_time = ref_time or (http[0].get("last_seen") if http else None)
    if pg and dst_domain:                 # DNS beacon:数查询事件
        dns = graph.run_cypher(
            "MATCH (e:Event)-[:BY]->(:Process {process_guid:$g}) "
            "MATCH (e)-[:QUERIED]->(:Domain {fqdn:$f}) "
            "RETURN count(e) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            g=pg, f=dst_domain)
        ctx["DNS查询聚合(周期性)"] = dns
        _emit_periodic(findings, dns, "dns", aid)
        ref_time = ref_time or (dns[0].get("last_seen") if dns else None)

    if dst_domain:                        # 目标域新鲜度(reputation/解析扇出未建模=盲区)
        fresh = graph.run_cypher(
            "MATCH (d:Domain {fqdn:$f}) RETURN d.first_seen AS domain_first_seen", f=dst_domain)
        first_seen = fresh[0].get("domain_first_seen") if fresh else None
        age = _age_days(first_seen, ref_time)
        ctx["目标域新鲜度"] = {"domain_first_seen": first_seen, "参考时刻": ref_time, "距今天数": age}
        # 新域 = 首见于近期(时间戳本身禁入 attrs;域身份走 bindings,finding 存在即"新"信号)
        if age is not None and age <= _NEW_DOMAIN_MAX_AGE_DAYS:
            findings.append(Finding("c2.new_domain", {}, evidence_ref=aid, polarity="red"))

    parent = None
    if pg:                                # 发起进程正常吗
        proc = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
            "OPTIONAL MATCH (p)-[:RAN_AS]->(acc:Account) "
            "RETURN parent.image AS parent, acc.sam AS account", g=pg)
        ctx["发起进程"] = proc
        parent = proc[0].get("parent") if proc else None

    # 发起进程画像:浏览器=正常发起者(不成信号);已知更新器/agent=良性(白);其余非浏览器=可疑(红)
    if image:
        agent = security_agent(image)
        if _BROWSER.search(image):
            ctx["发起进程画像"] = {"image": image, "判定": "已知浏览器(周期外连的正常发起者)"}
        elif agent or _UPDATER.search(image):
            label = agent or "已知更新器"
            ctx["发起进程画像"] = {"image": image, "判定": f"良性:{label}(image 原值承重,结论交经验层)"}
            findings.append(Finding("c2.known_updater", {"image": image}, evidence_ref=aid, polarity="white"))
        else:
            susp_parent = bool(parent and _SUSPICIOUS_PARENT.search(parent))
            ctx["发起进程画像"] = {"image": image, "父进程": parent, "可疑父链": susp_parent,
                              "判定": "非浏览器/非已知更新器 —— 可疑发起者(image 原值承重)"}
            findings.append(Finding("c2.suspicious_process",
                                    {"image": image, "parent": parent, "suspicious_parent": susp_parent},
                                    evidence_ref=aid, polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="精确信标周期/jitter 显著性、字节量/时长、DNS 深度特征(记录类型/子域熵/NXDOMAIN)、"
                                 "TLS/JA3、目标 reputation/解析扇出(RESOLVES_TO 未建模,需 DNS 应答映射)—— "
                                 "host-only 天花板,需 NDR/Zeek 探针")


def _emit_periodic(findings, rows, channel, aid):
    """外连/DNS 聚合 → periodic_beacon(count 分桶承重;高/巨量=红嫌疑,单独不定性)。"""
    r = rows[0] if rows else {}
    cnt = r.get("count")
    if cnt is None:
        return
    bkt = bucket(cnt)
    findings.append(Finding("c2.periodic_beacon",
                            {"channel": channel, "count_bucket": bkt},
                            evidence_ref=aid,
                            polarity="red" if bkt in ("high", "massive") else "neutral"))
