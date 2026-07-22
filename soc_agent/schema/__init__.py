"""从 model/graph_model.json 生成注入 LLM 提示的 v3 图 schema 文本。

程序化生成 → 图模型改了 schema 自动跟着变,不会漂移。
目标读者是 LLM:把真实 label / 键 / 谓语 / 告警层 / 经验层写全,
让它据此写对 Cypher(实测不喂 schema 会瞎猜 Host{name}/TRIGGER)。
"""
import json
from pathlib import Path

__all__ = ["load_model", "build_schema", "graph_schema"]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MODEL = _REPO_ROOT / "model" / "graph_model.json"


def load_model(path=None) -> dict:
    """读 graph_model.json。不传路径则用仓库 model/graph_model.json。"""
    p = Path(path) if path is not None else _DEFAULT_MODEL
    return json.loads(p.read_text(encoding="utf-8"))


def _fmt_keys(entity: dict) -> str:
    keys = entity.get("keys") or []
    s = "(" + ",".join(keys) + ")" if keys else "-"
    fb = entity.get("fallback_key")
    if fb:
        s += " 兜底(" + ",".join(fb) + ")"
    return s


def _entities_section(model: dict) -> str:
    lines = ["## 实体节点(名词;强键去重、跨事件共享)"]
    for e in model.get("entities", []):
        line = f"- :{e['name']}  键={_fmt_keys(e)}  属性: {', '.join(e.get('props', []))}"
        note = e.get("note")
        if note:
            line += f"  // {note}"
        lines.append(line)
    return "\n".join(lines)


def _event_section(model: dict) -> str:
    ev = model.get("event_node", {})
    edges = ev.get("edges", {})
    subj = edges.get("subject", {})
    pred = edges.get("predicate", {})
    lines = [
        "## 事件节点 :Event(动词的一次发生;节点只存 time+少量标量,语义全在边和实体上)",
        f"- 属性: {', '.join(ev.get('props', []))}",
        f"- (:Event)-[:{subj.get('name', 'BY')}]->(主语实体)   主语/actor",
        f"- (:Event)-[:<谓语>]->(宾语实体)   边类型=谓语(见谓语登记表)",
    ]
    for s in edges.get("secondary", []):
        lines.append(f"- (:Event)-[:{s['name']}]->({'/'.join(s.get('to', []))})   {s.get('note', '')}".rstrip())
    return "\n".join(lines)


def _verbs_section(model: dict) -> str:
    reg = model.get("verb_registry", {})
    lines = ["## 谓语登记表(事件类型 → 谓语[=事件宾语边=聚合边] → 主/宾/次要参与者)"]
    for r in reg.get("entries", []):
        sec = r.get("secondary") or []
        scal = r.get("scalars") or []
        line = f"- {r['source']}: (主){r['subject']} -[:{r['verb']}]-> (宾){r['object']}"
        if sec:
            line += f" ; 次要 {', '.join(sec)}"
        if scal:
            line += f" ; 标量 {', '.join(scal)}"
        lines.append(line)
    return "\n".join(lines)


def _agg_section(model: dict) -> str:
    agg = model.get("aggregate_edges", {})
    verbs = agg.get("verbs", [])
    props = agg.get("props", [])
    return (
        "## 聚合关系边(实体→实体,每对每谓语一条,带 " + "/".join(props) + ";路径查询走这层不爆炸)\n"
        "- 谓语同上表: " + ", ".join(verbs) + "\n"
        "- 例: (:Process)-[:ACCESSED {count,first_seen,last_seen}]->(:Process)"
    )


def _struct_section(model: dict) -> str:
    lines = ["## 结构边(实体↔实体的静态/归属关系)"]
    for e in model.get("structural_edges", {}).get("edges", []):
        line = f"- (:{e['from']})-[:{e['name']}]->(:{e['to']})"
        if e.get("note"):
            line += f"   // {e['note']}"
        lines.append(line)
    return "\n".join(lines)


def _alert_section(model: dict) -> str:
    al = model.get("alert_layer", {})
    lines = ["## 告警层(检测产物;告警挂在触发它的事件上=唯一溯源入口)"]
    for n in al.get("nodes", []):
        lines.append(f"- :{n['name']}  键=({','.join(n.get('keys', []))})  属性: {', '.join(n.get('props', []))}")
    for e in al.get("edges", []):
        lines.append(f"- (:{e['from']})-[:{e['name']}]->(:{e['to']})   {e.get('note', '')}".rstrip())
    return "\n".join(lines)


def _experience_section(model: dict) -> str:
    ex = model.get("experience_layer", {})
    lines = ["## 经验层(研判/处置结论写回图,挂在告警之后;每条告警的历史台账+情报参照)"]
    for n in ex.get("nodes", []):
        lines.append(f"- :{n['name']}  键=({','.join(n.get('keys', []))})  属性: {', '.join(n.get('props', []))}")
    for e in ex.get("edges", []):
        to = e["to"] if isinstance(e["to"], str) else "/".join(e["to"])
        lines.append(f"- (:{e['from']})-[:{e['name']}]->(:{to})   {e.get('note', '')}".rstrip())
    return "\n".join(lines)


def _keys_flow_section(model: dict) -> str:
    ck = model.get("connection_keys", {})
    parts = ["## 连接键与研判走法"]
    if ck:
        parts.append(f"- 强键: {', '.join(ck.get('strong', []))}   弱键: {', '.join(ck.get('weak', []))}")
    flow = model.get("investigation_flow")
    if flow:
        parts.append(f"- 研判走法: {flow}")
    return "\n".join(parts)


def build_schema(model: dict) -> str:
    """把图模型渲染成 LLM 可读的 v3 schema 文本。"""
    ver = model.get("version", "?")
    header = (
        f"# v3 知识图谱 Schema (version {ver})\n"
        "只用下面列出的 label / 键 / 谓语 / 边;别自创。写 Cypher 时严格照此。\n"
        "两层事实: 事件节点(:Event,取证标量) + 聚合关系边(结构/路径)。告警原文见 :Alert.raw。"
    )
    sections = [
        header,
        _entities_section(model),
        _event_section(model),
        _verbs_section(model),
        _agg_section(model),
        _struct_section(model),
        _alert_section(model),
        _experience_section(model),
        _keys_flow_section(model),
    ]
    return "\n\n".join(sections).strip()


def graph_schema(path=None) -> str:
    """便捷:load_model + build_schema。"""
    return build_schema(load_model(path))
