"""快通道签名引擎 —— 本身不认识任何攻击类型。

签名函数**与各自 skill co-located**(`skills/<layer>/<name>/signature.py::signature`),由 skills_runtime
按约定自动发现、挂到 `Skill.signature`。本引擎只做三件事:遍历注册表里所有 skill、跑其签名函数、
盖上 skill 名收集非 None。=「引擎 + 把算签名的函数配置进来」。

每个签名函数 `(graph, alert, seed) → {"layers", "bindings"} | None`:
- **自锚定**告警的触发事件、自己查图取证、算分层特征;★锚不到/取不到证据 → None(伪签名,不参与碰撞/沉淀)。
- `layers` 分层(exculpatory 先证伪在前 / incriminating 坐实);`bindings` 携本告警实例值(换实例填处置目标)。
- skill 名由本引擎按目录注入(函数里不写),少一处能漂的地方。判别全确定性、**不用大模型**。

加一个攻击类型 = 在其 skill 目录放一个 signature.py(挨着 recipe.py),引擎自动发现,无需改本文件。
"""


def _run_one(skill, graph, alert, seed):
    """跑单个 skill 的签名函数(无/锚不到→None);盖上 skill 名。每次调用 try 隔离,坏函数不拖垮全局。"""
    fn = getattr(skill, "signature", None)
    if fn is None:
        return None
    try:
        r = fn(graph, alert, seed)
    except Exception:
        return None
    if not r:
        return None
    r["skill"] = skill.name                  # ★skill 名由引擎按目录注入,不信函数自报
    return r


def run_all(registry, graph, alert, seed=None):
    """遍历注册表所有 skill、跑各自签名函数 → 收集非 None(过滤伪签名)。
    返回 [{"skill","layers","bindings"}, ...](可空:全是伪签名/无对口 signature.py)。"""
    out = []
    for skill in registry.all():
        r = _run_one(skill, graph, alert, seed)
        if r:
            out.append(r)
    return out
