"""Web 路由公用小工具。"""
import json

NOOP_ACTIONS = (None, "", "none")


def run_spec(graph, spec):
    """跑一个 (cypher, params) 只读查询。"""
    cypher, params = spec
    return graph.run_cypher(cypher, **params)


def loads(s):
    """json 串 → 对象;非串/坏串原样返回(前端仍能显示)。"""
    if isinstance(s, str):
        try:
            return json.loads(s)
        except Exception:
            return s
    return s
