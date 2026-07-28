"""ADCS 证书滥用(T1649)确定性取证 —— 结构化 finding 版。

取图里真有的字段:4886 携 attributes(含请求机器 cdc/rmd)+ request_id + 请求者;4887(签发)
携 subject_dn(证书签给谁)。CA 为 Service(service_id/kind)。★模板名/EKU/SAN 仍是图盲区。
★subject_dn 与请求者比对是 ESC1 核心信号:subject≠请求者 = 冒充(倾向恶意);subject==请求者
= 正常自签(倾向良性);subject_dn 缺失(4886 阶段)= 仍盲区,两个 finding 都不发。

finding 词典(方法论):cert_request(触发,N;event_code 4886=请求 / 4887=签发)/
subject_mismatch(R,主体≠请求者=冒充,presence 即信号)/ subject_self_enroll(W,主体==请求者=自签,良性)/
requester_privileged(N,请求者本身特权=已有权限、非升权信号,仅作上下文)。
红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。
"""
import re

from soc_agent.forensics import Finding, Forensics


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 1. 请求者 + CA + 事件(4886 请求 / 4887 签发)+ subject_dn
    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(req:Account) "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(ca:Service) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN e.event_code AS event_code, e.attributes AS attributes, e.request_id AS request_id, "
        "e.subject_dn AS subject_dn, "
        "req.sam AS req_sam, req.domain AS req_domain, req.upn AS req_upn, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "ca.service_id AS ca, ca.kind AS ca_kind, h.hostname AS ca_host",
        aid=aid)
    b = base[0] if base else {}
    ctx["请求者与CA"] = b
    req_sam, req_domain = b.get("req_sam"), b.get("req_domain")
    ca = b.get("ca")

    if req_sam:
        bindings["account"] = req_sam
        if req_domain:
            bindings["account_domain"] = req_domain
    if ca:
        bindings["ca"] = ca                     # CA(Service)非身份角色,保留原值

    # 触发本身:一次证书请求/签发(event_code 标量进 attrs,供指纹按 4886/4887 泛化;实例账号/CA 走 bindings 抽象)
    if b:
        findings.append(Finding("adcs.cert_request", {"event_code": b.get("event_code")},
                                evidence_ref=aid, polarity="neutral"))

    # 2. 请求者估值(privileged / 属组)—— 请求者本身特权只作上下文(N),非升权信号
    req_privileged = bool(b.get("req_privileged"))
    if req_sam:
        rows = graph.run_cypher(
            "MATCH (req:Account {sam:$s}) OPTIONAL MATCH (req)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(req.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=req_sam)
        rv = rows[0] if rows else {}
        ctx["请求者估值"] = rv
        if rv.get("privileged"):
            req_privileged = True
    if req_privileged:
        # presence-only:请求者已有权限属上下文,极性 neutral(升权风险来自"低权请求者"=本 finding 缺席)
        findings.append(Finding("adcs.requester_privileged", {}, polarity="neutral"))

    # 3. ★主体(证书签给谁)与请求者比对 —— ESC1 核心:subject/SAN ≠ 请求者 = 冒充
    subject_dn = b.get("subject_dn")
    m = re.search(r"CN=([^,]+)", subject_dn or "", re.I)
    subject_cn = m.group(1).strip() if m else None
    matches = None
    if subject_cn and req_sam:
        matches = (subject_cn.strip().lower() == req_sam.strip().lower())
    ctx["主体与请求者比对"] = {
        "subject_dn": subject_dn, "subject_cn": subject_cn, "req_sam": req_sam,
        "subject_matches_requester": matches,
        "_note": ("subject==请求者 → 无冒充,大概率正常自签(suspicious/lean_benign;SAN 仍是盲区);"
                  "subject≠请求者 → 疑似 ESC1 冒充(lean_malicious,甚至 TP);"
                  "subject_dn 缺失(多为 4886 请求阶段)→ 仍盲区,suspicious/lean_unknown。"),
    }
    if subject_cn:
        # 证书签给的主体,用带 user 的角色名以便指纹抽象;presence-only,不进 attrs
        bindings["subject_user"] = subject_cn

    # 三态:True=自签(白)/ False=冒充(红)/ None(subject_dn 缺,多为 4886)两个都不发
    if matches is True:
        findings.append(Finding("adcs.subject_self_enroll", {}, polarity="white"))
    elif matches is False:
        findings.append(Finding("adcs.subject_mismatch", {}, polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="模板名/EKU/ENROLLEE_SUPPLIES_SUBJECT、证书 SAN(subjectAltName,ESC1 真正的冒充载体,"
                                 "与 subject_dn 不同、仍未建模)、ESC8 中继/强制认证链、CA 审计是否开启 —— 未建模。"
                                 "subject_dn 已取(见「主体与请求者比对」),SAN 仍盲")
