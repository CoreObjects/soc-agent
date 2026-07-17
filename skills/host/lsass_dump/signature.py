"""LSASS 凭据转储(T1003.001)快通道签名 —— 与 skill co-located,中央引擎自动发现。

★红线:键只在【通用本体字段】上,不碰任何厂商/产品名单(security_agent 名单绝不做 key)。
- **先证伪层**(总出):`{源进程image(原始), 有无转储库, 访问类别}` —— "哪个进程读 lsass 是良性"
  由慢通道**学**成规则(wazuh→FP / CSFalcon→FP / 某自研 EDR→FP 都是学出来的),不写死名单。
- **坐实层**(仅当 call_trace 含转储库时出):`{有转储库, 访问类别}` —— 转储库+读内存是【通用】强攻击信号,
  ★**不键进程名**:改名成 svchost.exe 也躲不过转储库信号;而真·良性(学过的)靠全局先证伪先命中、不会被误坐实。

自锚定「进程 BY 源 ACCESSED lsass」的进程访问事件;锚不到源进程 → None(伪签名)。
低层判定(转储库/掩码/进程名归一)走 ._lib,与 recipe 共享同一份、不漂。
"""
from ._lib import access_class, has_dump_lib, src_key


def signature(graph, alert, seed=None):
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(src:Process) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(tgt:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN src.process_guid AS src_guid, src.image AS src_image, tgt.image AS target_image, "
        "e.granted_access AS granted, e.call_trace AS call_trace, h.hostname AS host",
        aid=alert.alert_uid)
    b = rows[0] if rows else None
    if not b or not (b.get("src_image") or "").strip():
        return None                                  # 锚不到进程访问事件的源进程 → 伪签名

    src = src_key(b.get("src_image"))                # 原始进程标识(通用特征;值=环境数据,结论慢通道学)
    dumplib = has_dump_lib(b.get("call_trace"))      # 通用:call_trace 含 Windows 转储库
    acc = access_class(b.get("granted"))             # 通用:访问掩码类别(读内存/仅查询)

    layers = [
        {"layer": "exculpatory",
         "features": {"src_image": src, "has_dump_lib": dumplib, "access_class": acc}},
    ]
    if dumplib:                                       # 转储库+读内存 = 通用坐实信号(不键进程名,防伪装)
        layers.append({"layer": "incriminating",
                       "features": {"has_dump_lib": True, "access_class": acc}})

    return {
        "layers": layers,
        "bindings": {"src_process": src, "src_guid": b.get("src_guid"),
                     "host": b.get("host"), "granted_access": b.get("granted"),
                     "target": b.get("target_image")},
    }
