"""可疑进程/命令执行/LOLBin(T1059/T1055/T1218)确定性取证 —— 从 seed 起,适配多种事件类型。

要点(上一轮翻车教训):
- 触发事件不一定是 EID1(SPAWNED)。EID11(建文件)、EID4104(脚本块)没有子进程,
  决定性证据是 command_line / script_block_text —— 直接从 seed 取,别假设有父子链。
- ★把 -EncodedCommand 连锁解码、把 Ansible/执行策略自检等 GOAD 良性噪声认出来,
  再交 LLM(否则模型看不懂编码命令就幻觉/误判)。
- 不查图里不存在的字段(criticality 等,待补图第二弹)。
"""
from soc_agent.recipe_lib import decode_chain, provisioning_noise


def collect(graph, alert, seed=None):
    seed = seed or {}
    event = seed.get("event") or {}
    subject = seed.get("subject") or {}
    related = seed.get("related") or []
    ev = {}

    # 1. 触发事件本体:命令行 / 脚本块 / 完整性级别(哪种 EID 都先把决定性文本捞出来)
    ev["触发事件"] = {k: event.get(k) for k in
                    ("event_code", "integrity_level", "command_line", "script_block_text",
                     "creation_time", "event_time") if event.get(k) is not None}

    # 2. 主语进程(4104 脚本块时可能为空)
    ev["主语进程"] = {k: subject.get(k) for k in
                    ("image", "command_line", "pid", "process_guid", "hashes")
                    if subject.get(k) is not None}

    # 3. seed 里的关联:落地文件 / 子进程 / 主机
    files = sorted({r["node"].get("path") for r in related
                    if r.get("rel") == "WROTE" and r.get("node") and r["node"].get("path")})
    children = [r["node"] for r in related if r.get("rel") == "SPAWNED" and r.get("node")]
    host = next((r["node"].get("hostname") for r in related
                 if r.get("rel") == "ON_HOST" and r.get("node")), None)
    ev["落地文件"] = files
    ev["子进程(含命令行)"] = [{k: c.get(k) for k in ("image", "command_line", "process_guid")
                          if c.get(k) is not None} for c in children]
    ev["主机"] = host

    # 4. ★连锁解码 EncodedCommand(主语 + 各子进程),把编码命令的真身摊开
    decoded = {}
    for label, cl in ([("主语", subject.get("command_line"))]
                      + [(f"子进程{i}", c.get("command_line")) for i, c in enumerate(children)]):
        layers = decode_chain(cl)
        if layers:
            decoded[label] = layers
    if decoded:
        ev["解码后命令(逐层)"] = decoded

    # 5. ★已知良性供给/自检噪声识别(命中即强证伪:Ansible 供给 / 执行策略探针)
    blob = "\n".join(filter(None, (
        [event.get("script_block_text"), subject.get("command_line")]
        + [c.get("command_line") for c in children]
        + [layer for layers in decoded.values() for layer in layers]
        + files)))
    ev["供给/自检噪声"] = provisioning_noise(blob) or "未识别到已知良性噪声"

    # 6. 有主语进程 GUID 才回溯父链 / 看子进程后续(EID11/4104 常无 → 跳过,不空查报警)
    guid = subject.get("process_guid")
    if guid:
        rows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS parent_image, p.image AS image", g=guid)
        ev["父进程"] = rows[0] if rows else {}
        ev["子进程后续行为"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:SPAWNED]->(d:Process) "
            "OPTIONAL MATCH (p)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (p)-[:ACCESSED]->(l:Process) "
            "RETURN collect(DISTINCT d.image)[0..10] AS descendants, "
            "collect(DISTINCT ip.ip)[0..10] AS out_ips, "
            "collect(DISTINCT l.image)[0..10] AS accessed_procs", g=guid)

    ev["_图盲区"] = ("进程 EXE 签名/是否 LOLBin 原版、完整性级别提权、外连内容 —— 未建模;"
                    "已解码命令与噪声标签见上,据此判良性/恶意")
    return ev
