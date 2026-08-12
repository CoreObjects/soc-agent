"""★读侧 Pivot 契约 —— 让 recipe 不再写死"主语一定是 Process"。

为什么需要(WP1 真机证伪出来的,这是整个接入层产品化里**最容易被漏掉**的一半):
  `c2_beacon` / `suspicious_outbound` / `webshell` 三个 recipe 都以**硬性(非 OPTIONAL)**
      MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process)
  开头,并 pivot 在 `p.process_guid` 上;而且它们**一个 event_code 谓词都没有**。
  于是换成没有"发起进程"的源(Zeek/NetFlow/防火墙):
      base=[] → findings=[] → **不报错**,落深度 LLM,给出一个自信的空结论。
  真机实测(影子图):同一条 c2_beacon 锚点查询,Windows 告警 1 行 / Zeek 告警 **0 行且无异常**;
  pivot 化之后同样的数据取到 25 行。

  ⇒ **接一种新源的剩余成本不在 map() 里,在 recipe 的 pivot 里。**
     客户买的是"结论",不是"被填满的图"。

设计:
  · pivot 种类是**闭集**(process | host | endpoint | principal),4 种;
    ⇒ 成本 = 源类型数 + pivot 种类数,两者都有限,而不是随客户数增长。
  · 每个 skill 在 SKILL.md 里声明 `supported_pivots`;拿到不支持的 pivot →
    产出 `_coverage.absent` finding(**明说自己瞎了**),而不是静默返回空 findings。
"""
from dataclasses import dataclass

# BY 端(主语)的实体标签 → (pivot 种类, 强键属性)。闭集;新源带来新主语类型才在此加一行。
_SUBJECT_TO_PIVOT = {
    "Process": ("process", "process_guid"),
    "IPAddress": ("endpoint", "ip"),
    "Account": ("principal", "sam"),
    "Host": ("host", "hostname"),
}


@dataclass(frozen=True)
class Pivot:
    kind: str            # process | host | endpoint | principal
    label: str           # 图标签
    key_prop: str        # 强键属性名
    key_value: object
    via: str = "BY"      # 事件挂到该实体用的谓语边:BY(主语) | FROM(外部来源) | ON_HOST(落地主机)

    def match(self, evar: str = "e", xvar: str = "x", param: str = "pk") -> str:
        """渲染"事件 → pivot 实体"的 MATCH 片段。
        ★label/边/属性名全部来自上面的**闭集**,不是用户输入 → 插值安全(与图守卫的白名单同理)。
        ★`via` 必须随 pivot 一起记住:WAF 那类事件的主体挂在 `FROM` 上,
          若一律渲染成 `BY`,查询语法合法、恒返回零行 —— 又是一次静默空。"""
        return f"({evar}:Event)-[:{self.via}]->({xvar}:{self.label} {{{self.key_prop}:${param}}})"


def resolve_pivot(graph, alert_uid):
    """看触发事件的 BY 端是什么 → 返回最强可用 pivot;BY 缺失时退 FROM(外部请求无主体)、再退 ON_HOST。

    返回 None = 这条告警连 pivot 都解析不出来 ⇒ 调用方应产出 `_coverage.absent`,**绝不返回空 findings**。
    """
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$u})<-[:TRIGGERED]-(e:Event) "
        "OPTIONAL MATCH (e)-[:BY]->(subj) "
        "OPTIONAL MATCH (e)-[:FROM]->(src) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN labels(subj) AS subj_labels, subj{.*} AS subj, "
        "labels(src) AS src_labels, src{.*} AS src, h.hostname AS hostname LIMIT 1",
        u=alert_uid)
    if not rows:
        return None
    r = rows[0]
    for via, labels, node in (("BY", r.get("subj_labels"), r.get("subj")),
                              ("FROM", r.get("src_labels"), r.get("src"))):
        lbl = next((l for l in (labels or []) if l in _SUBJECT_TO_PIVOT), None)
        if lbl and node:
            kind, key = _SUBJECT_TO_PIVOT[lbl]
            if node.get(key) is not None:
                return Pivot(kind, lbl, key, node[key], via=via)
    if r.get("hostname"):
        return Pivot("host", "Host", "hostname", r["hostname"], via="ON_HOST")
    return None
