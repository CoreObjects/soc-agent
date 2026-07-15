"""Webshell 落盘(T1505.003)确定性取证 —— host-side 主线。

触发 = Sysmon EID11 写 web 脚本(.aspx/.asp/.php/.jsp...)。核心判别:
★写入进程是不是 web 服务进程(w3wp/php-cgi/tomcat = webshell 强信号;部署/管理进程 = 良性)
+ 落盘路径是否 web 根 + 编码写入命令连锁解码看真身 + 写入进程随后有没有派生 shell/回连(利用)。
(WAF 上传请求是可选佐证,需 WAF→后端同主机映射,当前盲。)
"""

from soc_agent.recipe_lib import decode_chain, provisioning_noise, security_agent

_WEBROOT_HINT = ("inetpub", "wwwroot", "htdocs", "\\www\\", "webapps", "\\web\\")


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(w:Process) "
        "OPTIONAL MATCH (e)-[:WROTE]->(f:File) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN w.process_guid AS writer_guid, w.image AS writer_image, w.command_line AS writer_cmd, "
        "collect(DISTINCT f.path) AS dropped_paths, "
        "h.hostname AS host, h.role AS host_role, h.criticality AS host_criticality",
        aid=aid)
    ev["落盘事件(写入进程+文件)"] = base[0] if base else {}
    b = ev["落盘事件(写入进程+文件)"]
    wg, wimg = b.get("writer_guid"), (b.get("writer_image") or "")
    # 反斜杠归一 + 去重(同一文件因 alert 双转义/winlogbeat 单转义建了两个 File 节点)
    paths = sorted({(p or "").replace("\\\\", "\\") for p in (b.get("dropped_paths") or []) if p})
    b["dropped_paths"] = paths

    il = wimg.lower()
    # ★核心判别①:写入进程是不是 web 服务进程(是→webshell 强信号;否→部署/管理写脚本,偏良性)
    b["writer_is_webproc"] = any(k in il for k in ("w3wp", "php-cgi", "httpd", "tomcat", "\\java"))
    b["writer_is_security_agent"] = security_agent(wimg)                 # 安全代理写脚本=FP
    # ★核心判别②:落盘路径是否 web 根
    b["in_webroot"] = any(any(h in p.lower() for h in _WEBROOT_HINT) for p in paths)

    # 解码写入命令(EncodedCommand 连锁)+ 已知良性供给证伪 —— 看写进去的到底是什么
    layers = decode_chain(b.get("writer_cmd") or "")
    if layers:
        ev["写入命令解码(逐层)"] = layers
    ev["供给/自检噪声"] = provisioning_noise(
        "\n".join([b.get("writer_cmd") or ""] + layers)) or "未识别到已知良性噪声"

    # ★利用:写入进程随后派生 shell / 外连(把"落盘"升"活跃 webshell")
    if wg:
        ev["写入进程-派生与外连"] = graph.run_cypher(
            "MATCH (w:Process {process_guid:$g}) "
            "OPTIONAL MATCH (w)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (w)-[:CONNECTED_TO]->(dst:IPAddress) "
            "RETURN collect(DISTINCT c.image) AS spawned_images, collect(DISTINCT c.command_line) AS spawned_cmds, "
            "collect(DISTINCT dst.ip) AS outbound", g=wg)

    ev["_图盲区"] = ("落盘文件哈希/内容、WAF 上传请求关联(需 WAF→后端同主机映射)、站点物理路径→URL 可达性、"
                    "落盘脚本后续被 w3wp 读取执行 —— 待补。写入进程/路径/解码写入内容/随后派生外连 已入图可用")
    return ev
