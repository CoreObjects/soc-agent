"""DCSync(T1003.006)确定性取证 —— 结构化 finding 版。

核心判据 = 发起者是不是本域 DC 机器账号(是→DC 正常复制 benign;否→成立)。
图内可取:发起者账号(sam/domain/upn)+ 是否机器账号(sam 结尾 $,结构判别不硬编码实例)、
被访问对象 guid、properties(复制 GUID)、access_mask、本域 Domain 的 dc 主机名(Domain.dc)、
事件落地主机是否 DC。认证/票据用途、复制范围(拉了哪些账号)是图盲区。

finding 词典(方法论):replication_request(触发)/ actor_is_dc(白,DC-to-DC 正常复制,★头号良性)/
actor_is_machine(白)/ actor_non_dc_user(红,非机器非DC账号发起复制)/ get_changes_all(红,拉全量口令哈希权限)。
红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。
"""
from soc_agent.forensics import Finding, Forensics
from soc_agent.recipe_lib import is_machine

_GET_CHANGES_ALL = "1131f6ad"   # DS-Replication-Get-Changes-All(拉全量口令哈希,含 krbtgt→金票)
_GET_CHANGES = "1131f6aa"       # DS-Replication-Get-Changes


def _props_label(properties) -> str:
    """从 properties(复制 GUID)判权限档:全量拉哈希 > 普通复制 > 其它。指纹用标签而非裸 GUID 串。"""
    p = str(properties or "").lower()
    if _GET_CHANGES_ALL in p:
        return "get_changes_all"
    if _GET_CHANGES in p:
        return "get_changes"
    return "other"


def _short(name):
    """账号/主机短名归一(去 $、去域后缀、大写)—— 结构判别,不硬编码实例。"""
    if not name:
        return None
    s = str(name).strip().rstrip("$").split(".")[0].strip()
    return s.upper() or None


def _actor_is_dc(actor_sam, dc_host) -> bool:
    """actor 短名 == 本域 DC 短名(dc_host 可能是标量或多 DC 列表)→ DC 之间正常复制。"""
    a = _short(actor_sam)
    if not a:
        return False
    hosts = dc_host if isinstance(dc_host, (list, tuple, set)) else [dc_host]
    return any(_short(h) == a for h in hosts if h)


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 1. 发起者 + 被访问对象 + 落地主机(★保留原始 cypher 与证据不动)
    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4662'})-[:BY]->(actor:Account) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(obj:DirectoryObject) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(eh:Host) "
        "RETURN actor.sam AS actor_sam, actor.domain AS actor_domain, actor.upn AS actor_upn, "
        "coalesce(actor.privileged,false) AS actor_privileged, "
        "e.properties AS properties, e.access_mask AS access_mask, "
        "obj.guid AS obj_guid, eh.hostname AS event_host, coalesce(eh.is_dc,false) AS event_host_is_dc",
        aid=aid)
    b = base[0] if base else {}
    actor_sam, actor_domain = b.get("actor_sam"), b.get("actor_domain")
    event_host = b.get("event_host")
    properties, access_mask = b.get("properties"), b.get("access_mask")

    # ★核心判据(结构判别,不硬编码实例):发起者是不是机器账号(sam 结尾 $)
    actor_machine = is_machine(actor_sam)
    b["actor_is_machine"] = actor_machine        # 派生结论回填 prose(喂 LLM)
    ctx["发起者与对象"] = b

    if actor_sam:
        bindings["account"] = actor_sam
        if actor_domain:
            bindings["account_domain"] = actor_domain
    if event_host:
        bindings["host"] = event_host

    props_bucket = _props_label(properties)

    # 触发本身:一次目录复制请求(决定性标量进 attrs,供指纹按"复制权限档"泛化)
    if b:
        findings.append(Finding(
            "dcsync.replication_request",
            {"access_mask": access_mask, "props_bucket": props_bucket},
            evidence_ref=aid, polarity="neutral"))

    # 2. 发起者估值(privileged/组)—— context,供 LLM 看
    if actor_sam:
        rows = graph.run_cypher(
            "MATCH (actor:Account {sam:$s}) OPTIONAL MATCH (actor)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(actor.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=actor_sam)
        ctx["发起者估值"] = rows[0] if rows else {}

    # 3. 本域 DC 主机名(判"发起者是不是本域 DC")
    dc_host = None
    if actor_domain:
        rows = graph.run_cypher(
            "MATCH (d:Domain {netbios:$nb}) RETURN d.fqdn AS domain_fqdn, d.dc AS dc_host", nb=actor_domain)
        dinfo = rows[0] if rows else {}
        ctx["域DC"] = dinfo
        dc_host = dinfo.get("dc_host")
        if dinfo.get("domain_fqdn"):
            bindings["domain"] = dinfo.get("domain_fqdn")

    # ★头号良性:actor 就是本域 DC 机器账号 → DC-to-DC 正常复制(presence-only,让良性指纹泛化)
    actor_dc = actor_machine and _actor_is_dc(actor_sam, dc_host)
    if actor_dc:
        findings.append(Finding("dcsync.actor_is_dc", {}, polarity="white"))
    if actor_machine:
        findings.append(Finding("dcsync.actor_is_machine", {}, polarity="white"))

    # 非机器、非 DC 账号(尤其普通用户)发起复制 = 攻击强信号
    if actor_sam and not actor_machine and not actor_dc:
        findings.append(Finding("dcsync.actor_non_dc_user",
                                {"actor_privileged": bool(b.get("actor_privileged"))}, polarity="red"))

    # Get-Changes-All:拉全量口令哈希权限(含 krbtgt)= 显著提权强信号
    if props_bucket == "get_changes_all":
        findings.append(Finding("dcsync.get_changes_all", {}, polarity="red"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="复制范围(是否含 krbtgt/全域,4662 不给被同步目标账号)、"
                                 "授予复制权的前置 ACL 修改(5136 未接)、DC/授权同步账号权威白名单 —— 图未建模")
