"""Webshell 上传与落地(T1505.003)确定性取证。

WAF 侧:上传类请求命中(payload 含脚本扩展 / 上传规则)+ 打的端点 + ★被拦否(http_status/outcome)。
★核心在主机侧:被打后端 Web 进程(w3wp/php-cgi)是否写出脚本到 web 目录(落盘)+ 随后派生 shell/外连(利用)。
后端为被监控主机时才有跨层三件套;容器化后端(如本靶场 DVWA)= 盲区。
"""

_WEBPROC = "toLower(w.image) CONTAINS 'w3wp' OR toLower(w.image) CONTAINS 'php-cgi'"
_SCRIPT = ("toLower(f.path) CONTAINS '.aspx' OR toLower(f.path) CONTAINS '.ashx' OR "
           "toLower(f.path) CONTAINS '.asmx' OR toLower(f.path) CONTAINS '.php' OR "
           "toLower(f.path) CONTAINS '.jsp'")
_WEBROOT = "toLower(f.path) CONTAINS 'wwwroot' OR toLower(f.path) CONTAINS 'inetpub' OR toLower(f.path) CONTAINS 'htdocs'"


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event) "
        "OPTIONAL MATCH (e)-[:FROM]->(ip:IPAddress) "
        "OPTIONAL MATCH (e)-[:TARGET]->(u:Uri) "
        "OPTIONAL MATCH (e)-[:TARGET]->(s:Service) "
        "RETURN a.rule_id AS crs_rule, a.rule_description AS rule_desc, "
        "e.rule_ids AS all_crs_rules, e.payload AS payload, e.http_method AS http_method, "
        "e.http_status AS http_status, e.outcome AS outcome, "
        "ip.ip AS src_ip, u.uri AS target_uri, s.service_id AS target_service, e.event_time AS event_time",
        aid=aid)
    ev["告警(WAF上传请求)"] = base[0] if base else {}
    target_service = ev["告警(WAF上传请求)"].get("target_service")

    # ★跨层:后端 Web 进程落盘脚本 + 随后派生/外连(利用)—— 判是否得手;容器化后端无 Host = 盲区
    ev["跨层-后端落地(落盘+利用)"] = _backend_dropzone(graph, target_service)

    ev["_图盲区"] = ("后端 Web 主机主机侧遥测(容器化=无 WROTE/SPAWNED→跨层空)、上传请求↔落盘因果强键、"
                    "落盘文件哈希、站点物理路径映射 —— 待补。http_status/outcome/payload/命中 CRS 规则/端点 已入图可用")
    return ev


def _backend_dropzone(graph, target_service):
    """被打 Service 若映射到被监控 Host → 查该主机 Web 进程落盘脚本 + 派生/外连。容器化后端无 Host = 盲区。"""
    if not target_service:
        return "无 target Service → 无法定位后端主机"
    host_hint = str(target_service).split("@", 1)[-1]
    rows = graph.run_cypher(
        "MATCH (h:Host) WHERE toLower(h.hostname) STARTS WITH toLower($hint) "
        "OPTIONAL MATCH (h)<-[:ON_HOST]-(:Event)-[:BY]->(w:Process) WHERE (" + _WEBPROC + ") "
        "OPTIONAL MATCH (w)-[:WROTE]->(f:File) WHERE (" + _SCRIPT + ") AND (" + _WEBROOT + ") "
        "OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process) "
        "OPTIONAL MATCH (w)-[:CONNECTED_TO]->(dst:IPAddress) "
        "RETURN h.hostname AS backend_host, collect(DISTINCT f.path) AS dropped_scripts, "
        "collect(DISTINCT c.command_line) AS spawned_cmds, collect(DISTINCT dst.ip) AS outbound",
        hint=host_hint)
    return rows[0] if (rows and rows[0].get("backend_host")) else "后端 Web 主机不在图中(容器/无主机侧遥测)= 跨层盲区"
