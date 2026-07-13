"""Webshell 上传与落地(T1505.003)确定性取证。

核心在主机侧:Web 进程(w3wp/php-cgi)是否写出脚本文件到 web 目录(落盘)+ 随后派生 shell/外连(利用)。
从 WAF 告警取被打 Web 主机 → pivot 到该主机的 WROTE/SPAWNED/CONNECTED_TO(跨层三件套)。
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
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN ip.ip AS src_ip, h.hostname AS web_host, e.event_time AS event_time",
        aid=aid)
    ev["告警(源IP+Web主机)"] = base[0] if base else {}
    web_host = ev["告警(源IP+Web主机)"].get("web_host")

    if web_host:
        # 落盘:Web 进程写脚本到 web 目录
        ev["主机侧-落盘脚本"] = graph.run_cypher(
            "MATCH (h:Host {hostname:$h})<-[:ON_HOST]-(:Event)-[:BY]->(w:Process) "
            "WHERE (" + _WEBPROC + ") "
            "MATCH (w)-[:WROTE]->(f:File) WHERE (" + _SCRIPT + ") AND (" + _WEBROOT + ") "
            "RETURN collect(DISTINCT f.path) AS dropped_scripts", h=web_host)
        # 执行/回连:Web 进程派生 shell / 外连
        ev["主机侧-执行与回连"] = graph.run_cypher(
            "MATCH (h:Host {hostname:$h})<-[:ON_HOST]-(:Event)-[:BY]->(w:Process) "
            "WHERE (" + _WEBPROC + ") "
            "OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (w)-[:CONNECTED_TO]->(dst:IPAddress) "
            "RETURN collect(DISTINCT c.command_line) AS spawned_cmds, "
            "collect(DISTINCT dst.ip) AS outbound", h=web_host)

    ev["_图盲区"] = ("上传请求文件名/落盘路径(WAF 给不出)、请求↔落盘因果强键(现靠同 Host+时间窗)、"
                    "HTTP 响应码、落盘文件哈希、站点物理路径映射 —— 未建模")
    return ev
