"""CLI 入口:研判单条告警(慢通道)。

流程:取 :Alert → seed(反查触发事件→涉及实体,骨架保底)→ 自主研判 → 写回经验层。
真客户端(Neo4j/qwen)在 server2 上跑;流程编排本机可测。
"""
import argparse
import sys
from pathlib import Path

from .config import Config
from .graph.client import Neo4jGraph
from .llm.qwen import QwenClient
from .models import Alert
from .orchestrator import AgentInvestigator
from .schema import graph_schema
from .skills_runtime import SkillRegistry
from .tools import default_toolbox

__all__ = ["investigate_alert", "render_result", "render_trace", "AlertNotFound", "main"]

_REPO_ROOT = Path(__file__).resolve().parents[1]


class AlertNotFound(Exception):
    pass


def investigate_alert(graph, investigator, alert_uid):
    """取告警 → seed → 研判 → 写回图。返回 InvestigationResult。"""
    node = graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    seed = graph.seed(alert)
    result = investigator.investigate(alert, seed=seed)
    graph.write_result(alert_uid, result)
    return result


def render_result(result) -> str:
    v = result.verdict
    lines = [
        f"# 研判结果  alert={result.alert_uid}  path={result.path}  skill={result.skill}",
    ]
    if v is not None:
        lines += [
            f"verdict   : {v.verdict}  (confidence={v.confidence})",
            f"summary   : {v.summary}",
            f"rationale : {v.rationale}",
        ]
        if v.evidence_refs:
            lines.append(f"evidence  : {v.evidence_refs}")
        if v.missing_evidence:
            lines.append(f"missing   : {v.missing_evidence}")
        if v.pattern:
            lines.append(f"pattern   : {v.pattern}")
        lines.append(f"agent     : {v.agent}")
    for d in result.dispositions or []:
        lines.append(f"处置(建议): {d.action} -> {d.target}  risk={d.risk}  status={d.status}")
    if not result.dispositions:
        lines.append("处置(建议): 无")
    return "\n".join(lines)


def render_trace(result) -> str:
    """研判留痕:每步工具调用(只打查询 + 行数/错误,不打行数据)。"""
    lines = [f"# 研判留痕({len(result.trace or [])} 步工具调用)"]
    for i, step in enumerate(result.trace or [], 1):
        tool = step.get("tool")
        args = step.get("args") or {}
        res = step.get("result") or {}
        if tool == "run_cypher":
            q = " ".join((args.get("query") or "").split())
            if isinstance(res, dict) and "error" in res:
                lines.append(f"[{i}] run_cypher ✗ {res['error']}")
            else:
                rows = res.get("rows") if isinstance(res, dict) else None
                lines.append(f"[{i}] run_cypher → {len(rows or [])} 行")
            lines.append(f"     q: {q[:240]}")
        else:
            lines.append(f"[{i}] {tool}: {args}")
    return "\n".join(lines)


def build(config: Config):
    """按配置装配真客户端 + 研判器。"""
    graph = Neo4jGraph(config.neo4j_uri, config.neo4j_user, config.neo4j_password, config.neo4j_database)
    llm = QwenClient(base_url=config.llm_api_base, model=config.llm_model, api_key=config.llm_api_key)
    investigator = AgentInvestigator(
        llm=llm, toolbox=default_toolbox(graph), schema=graph_schema(),
        registry=SkillRegistry(config.skills_dir), agent_name=config.llm_model,
        max_iterations=config.max_iterations,
    )
    return graph, investigator


def main(argv=None):
    ap = argparse.ArgumentParser(description="研判单条告警(慢通道)")
    ap.add_argument("alert_uid", help="要研判的 :Alert 的 alert_uid")
    ap.add_argument("--dotenv", default=str(_REPO_ROOT / ".env"), help=".env 路径(端点/口令)")
    ap.add_argument("--trace", action="store_true", help="打印研判留痕(每步 run_cypher + 行数)")
    args = ap.parse_args(argv)

    config = Config.from_env(dotenv_path=args.dotenv)
    graph, investigator = build(config)
    try:
        result = investigate_alert(graph, investigator, args.alert_uid)
    finally:
        graph.close()
    if args.trace:
        print(render_trace(result))
        print()
    print(render_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
