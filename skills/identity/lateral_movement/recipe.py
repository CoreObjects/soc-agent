"""横向移动/PtH/PtT(T1550/T1021)确定性取证 —— 结构化 finding 版。

图内数据较好:登录事件(logon_type/结果/账号/目标主机/源IP)、账号权限、账号↔主机基线
(AUTHENTICATED_TO 聚合边 count/first_seen)、账号扇出。认证包/票据生命周期是图盲区。

finding 词典(方法论):network_logon(触发)/ host_baseline_present(白,有史=良性)/ no_host_baseline(红,首见)/
privileged_account(红)/ high_value_target(红,登 DC/CA)/ fanout(扇出,红 if 高)。
红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。
"""
from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import bucket

_HIGH_VALUE_ROLES = {"domain_controller", "certificate_authority"}
_HIGH_CRIT = {"critical", "high"}


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 1. 登录事件:谁、什么类型、登到哪、从哪来
    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(acc:Account) "
        "OPTIONAL MATCH (e)-[:AUTHENTICATED_TO]->(h:Host) "
        "OPTIONAL MATCH (e)-[:FROM]->(ip:IPAddress) "
        "RETURN e.event_code AS event_code, e.logon_type AS logon_type, e.outcome AS result, "
        "acc.sam AS acc_sam, acc.domain AS acc_domain, coalesce(acc.privileged,false) AS acc_privileged, "
        "h.hostname AS target_host, h.role AS target_role, h.criticality AS target_criticality, "
        "ip.ip AS src_ip",
        aid=aid)
    b = base[0] if base else {}
    ctx["登录事件"] = b
    acc_sam, acc_domain = b.get("acc_sam"), b.get("acc_domain")
    target, src_ip = b.get("target_host"), b.get("src_ip")
    target_role, target_crit = b.get("target_role"), b.get("target_criticality")

    if acc_sam:
        bindings["account"] = acc_sam
        if acc_domain:
            bindings["account_domain"] = acc_domain
    if target:
        bindings["target_host"] = target
    if src_ip:
        bindings["src_ip"] = src_ip

    # 触发本身:一条网络登录(决定性标量进 attrs,供指纹按"登录种类"泛化;实例账号/主机走 bindings 抽象)
    if b:
        findings.append(Finding(
            "lateral.network_logon",
            {"logon_type": b.get("logon_type"), "event_code": b.get("event_code"), "result": b.get("result"),
             "acc_privileged": bool(b.get("acc_privileged")),
             "target_role": target_role, "target_criticality": target_crit},
            evidence_ref=aid, polarity="neutral"))

    if b.get("acc_privileged"):
        findings.append(Finding("lateral.privileged_account", {"sam": acc_sam}, polarity="red"))

    if (target_role in _HIGH_VALUE_ROLES) or (str(target_crit or "").lower() in _HIGH_CRIT):
        findings.append(Finding("lateral.high_value_target",
                                {"target_role": target_role, "target_criticality": target_crit}, polarity="red"))

    # 2. 账号↔该主机基线:有史=良性信号(white),无史=首见(red 强信号)。
    #    ★存在性 = AUTHENTICATED_TO 聚合边是否存在(first_seen/last_seen 从入图起就有);★次数从【事件】数
    #    (sum(coalesce(e.count,1)),折叠后代表带 e.count)—— 绝不读边上的 r.count(聚合边不落 count、恒 null,
    #    旧码读它→host_baseline_present 永不触发→每次登录误判成 no_host_baseline 红)。
    if acc_sam and target:
        rows = graph.run_cypher(
            "MATCH (acc:Account {sam:$s})-[r:AUTHENTICATED_TO]->(h:Host {hostname:$h}) "
            "RETURN r.first_seen AS first_seen, r.last_seen AS last_seen", s=acc_sam, h=target)
        has_baseline = bool(rows)
        cnt = graph.run_cypher(
            # ★WP10 放宽:`event_code='4624'` 是 Windows 专有码,换个源(Samba AD / sshd /
            #   第三方采集器)就再也命不中 —— 数据入了图,这里却查出零行、不报错。
            #   中立写法用 `activity`,**但不能一刀切**:
            #   ★`auth.logon` 比 4624 **粗** —— 4624(成功)/4625(失败)/4776(NTLM 校验)
            #     都归到它。这里数的是"登录次数",把失败登录算进来就是错的。
            #     (PROFILE 探针显示两边结果一致,是因为这条查询还要求 `-[:AUTHENTICATED_TO]->`,
            #      失败登录没有这条边、被顺带滤掉了 —— 那是**靠边的形状兜住**,不是谓词精确。
            #      换个把失败登录也建了这条边的源就会破。所以用 `outcome` 显式约束。)
            #   **只加不改**:存量 4624 走 OR 前半段照常命中,行集不变。
            "MATCH (e:Event)-[:BY]->(:Account {sam:$s}) "
            "WHERE e.event_code='4624' OR (e.activity='auth.logon' AND e.outcome='success') "
            "MATCH (e)-[:AUTHENTICATED_TO]->(:Host {hostname:$h}) "
            "RETURN sum(coalesce(e.count,1)) AS logins", s=acc_sam, h=target)
        logins = (cnt[0].get("logins") if cnt else None) or 0
        bl = rows[0] if rows else {}
        ctx["该账号↔该主机基线"] = {**bl, "登录次数": logins} if has_baseline else {"note": "无历史,疑似首次登该主机"}
        # 存在性即良性信号(有史);具体次数留 ctx 给 LLM,不进 attrs —— 免得 count 变了指纹就不认
        findings.append(Finding("lateral.host_baseline_present", {}, polarity="white") if has_baseline
                        else Finding("lateral.no_host_baseline", {}, polarity="red"))

    # 3. 扇出:登过几台主机(短时多台 = 横向扩散)
    if acc_sam:
        rows = graph.run_cypher(
            "MATCH (acc:Account {sam:$s})-[:AUTHENTICATED_TO]->(h:Host) "
            "RETURN count(DISTINCT h) AS distinct_hosts", s=acc_sam)
        sf = rows[0] if rows else {}
        ctx["账号扇出(共登过几台主机)"] = sf
        dh = sf.get("distinct_hosts")
        if dh is not None:
            findings.append(Finding("lateral.fanout",
                                    {"distinct_hosts": dh, "bucket": bucket(dh)},
                                    polarity="red" if (dh or 0) >= 5 else "neutral"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="认证包(NTLM/Kerberos)+KeyLength+冒充级别(PtH 首要签名)、"
                                 "票据生命周期(金票)、成员机票据↔DC 硬关联(银票)、来源工作站名 —— 未建模")
