"""暴露给 LLM 的工具箱。

P1 两件:
  run_cypher       只读取证(过只读守卫;写被拦、图异常都包成 {error} 回给 LLM 让它改写,不崩循环)。
  finalize_verdict 终结工具(LLM 调它给结构化结论;由 orchestrator 特判、不走普通派发)。
后续加:graph_expand/bfs、recall_similar_cases(情报)等。
"""
from dataclasses import dataclass
from typing import Callable, Optional

from ..graph.guard import ReadOnlyViolation, assert_read_only
from ..models import DISPOSITION_ACTIONS

__all__ = ["Tool", "ToolBox", "default_toolbox", "FINALIZE"]

FINALIZE = "finalize_verdict"


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict                    # JSON Schema
    handler: Optional[Callable] = None  # (args:dict)->Any;terminal 工具为 None
    terminal: bool = False


class ToolBox:
    def __init__(self, tools: list):
        self._tools = {t.name: t for t in tools}

    def specs(self) -> list:
        """OpenAI tools 格式,直接喂 chat(tools=...)。"""
        return [
            {"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters}}
            for t in self._tools.values()
        ]

    def is_terminal(self, name: str) -> bool:
        t = self._tools.get(name)
        return bool(t and t.terminal)

    def dispatch(self, name: str, arguments: Optional[dict]):
        t = self._tools.get(name)
        if t is None:
            return {"error": f"未知工具: {name}"}
        if t.terminal:
            return {"error": f"{name} 是终结工具,应由 orchestrator 处理"}
        return t.handler(arguments or {})


def _run_cypher_tool(graph) -> Tool:
    def handler(args: dict):
        args = args or {}
        q = args.get("query", "")
        params = args.get("params") or {}
        if not isinstance(params, dict):
            return {"error": "params 必须是对象(键→值),用于绑定 Cypher 里的 $参数"}
        try:
            assert_read_only(q)
        except ReadOnlyViolation as e:
            return {"error": str(e)}
        try:
            return {"rows": graph.run_cypher(q, **params)}
        except Exception as e:                      # 图查询失败 → 回错误让 LLM 改写,不崩
            return {"error": f"查询失败: {e}"}

    return Tool(
        name="run_cypher",
        description=("对知识图谱执行**只读** Cypher 取证据(只能 MATCH/RETURN/变长路径等,"
                     "禁止 CREATE/MERGE/DELETE/SET/REMOVE 等写操作)。返回 {rows:[...]}。"),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "只读 Cypher 查询;要么内联具体值,要么用 $参数配合 params"},
                "params": {"type": "object",
                           "description": "可选:绑定查询里的 $参数,如 {\"sam\":\"jon.snow\",\"t0\":123}"},
            },
            "required": ["query"],
        },
        handler=handler,
    )


def _finalize_verdict_tool() -> Tool:
    return Tool(
        name=FINALIZE,
        description=("取证充分后调用它给出**结构化研判结论 + 建议处置**,结束本次研判。"
                     "证据不足时用 verdict=suspicious 并在 missing_evidence 说明缺什么。"),
        parameters={
            "type": "object",
            "properties": {
                "verdict": {"type": "string",
                            "enum": ["true_positive", "false_positive", "benign", "suspicious"]},
                "confidence": {"type": "number", "description": "0~1"},
                "summary": {"type": "string"},
                "rationale": {"type": "string", "description": "研判依据"},
                "evidence_refs": {"type": "array", "items": {"type": "string"},
                                  "description": "引用的关键证据(事件/实体标识)"},
                "missing_evidence": {"type": "array", "items": {"type": "string"},
                                     "description": "取不到的关键证据"},
                "pattern": {"type": "string", "description": "识别出的攻击模式名(可空)"},
                "dispositions": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "action": {"type": "string", "enum": sorted(DISPOSITION_ACTIONS),
                                   "description": "只能从词表里选;别自由发挥"},
                        "target": {"type": "string", "description": "作用实体(账号/IP/主机/进程)"},
                        "risk": {"type": "string", "enum": ["low", "high"]},
                    }, "required": ["action"]},
                    "description": ("建议处置(仅建议,不自动执行)。verdict=suspicious 或证据不足时"
                                    "用 escalate/monitor,别提高危动作。"),
                },
            },
            "required": ["verdict", "confidence", "rationale"],
        },
        handler=None,
        terminal=True,
    )


def default_toolbox(graph) -> ToolBox:
    """P1 默认工具箱:run_cypher + finalize_verdict。graph 需有 run_cypher(query)->list[dict]。"""
    return ToolBox([_run_cypher_tool(graph), _finalize_verdict_tool()])
