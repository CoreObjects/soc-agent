"""独立 composer 环节:研判之后、拿结果组装基础处置原语成响应计划(不动研判)。

输入 = 研判 verdict + entity_frame(本告警涉及的角色实体)+ 该攻击的响应策略(skills/<skill>/response.md)
     + 处置接口文档(能调哪些原语)。
输出 = list[PrimitiveStepTemplate](角色绑定、实例无关)。慢通道组一次 → 固化进 openGauss 规则模板 →
      快通道 0 LLM 复用(按本实例角色值填目标)。

原则:composer 只**组装+调用**接口菜单里的原语,不发明动作;LLM 只挑原语+绑角色,不写脚本、不碰机器。
"""
import json

from ..response import default_interface
from .plan import PrimitiveStepTemplate

__all__ = ["Composer", "build_entity_frame"]


def _infer_kind(role):
    """从角色名推断实体 kind(供 composer 按 kind 绑参、防 host 参数绑到账号)。"""
    r = role.lower()
    if r.endswith("_host") or r == "host" or r.endswith("_hostname"):
        return "host"
    if r.endswith("_ip") or r == "ip":
        return "ip"
    return "account"


def build_entity_frame(bindings, seed=None):
    """判别器 bindings(角色→值)→ entity_frame {role: {value, kind}}。
    供 composer 知道有哪些角色可绑及其类型;空值角色、路由用的 <role>_domain 不进。"""
    frame = {}
    for role, val in (bindings or {}).items():
        if val in (None, "") or role.endswith("_domain"):
            continue
        frame[role] = {"value": val, "kind": _infer_kind(role)}
    return frame


def _load_strategy(skill) -> str:
    """读该 skill 的 response.md(响应策略);无 path/文件 → 空串(不崩)。"""
    path = getattr(skill, "path", None)
    if not path:
        return ""
    try:
        fp = path / "response.md"
        return fp.read_text(encoding="utf-8") if fp.exists() else ""
    except Exception:
        return ""


class Composer:
    """研判后独立的响应计划组装器。慢通道跑一次;产出被固化进规则模板供快通道复用。"""

    def __init__(self, llm, iface=None, agent_name="composer"):
        self.llm = llm
        self.iface = iface or default_interface()
        self.agent_name = agent_name

    def compose(self, result, disc, skill, seed=None):
        entity_frame = build_entity_frame((disc or {}).get("bindings") or {}, seed)
        if not entity_frame:
            return []                              # 无实体可作用 → 空计划,不烧 LLM
        strategy = _load_strategy(skill)
        system = self._system_prompt(strategy, entity_frame)
        user = self._user_prompt(result, entity_frame)
        resp = self.llm.chat([{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                             tools=[self._compose_spec(entity_frame)], tool_choice="required")
        for tc in (resp.tool_calls or []):
            if tc.name == "compose_response":
                return self._parse(tc.arguments or {}, entity_frame)
        return []

    # ---- 提示 ----
    def _menu(self):
        return sorted(self.iface.composer_menu_ids())

    def _system_prompt(self, strategy, entity_frame) -> str:
        lines = []
        for pid in self._menu():
            p = self.iface.get(pid)
            req = ",".join(p.required_params()) or "-"
            lines.append(f"- {pid}({p.category};必填参数:{req};风险:{p.risk_default};"
                         f"{'需人审' if self.iface.is_gated(pid) else '可自动'})：{p.summary}")
        parts = [
            "你是 SOC 处置编排器。研判已完成,现在只做一件事:从下面**可用处置原语**里挑选并排序,"
            "组装成对本次攻击的响应计划。只能调用列出的原语(不发明动作、不写脚本);每个原语参数**绑定到实体角色**"
            "(用下面 entity_frame 里的角色名),或必要时给字面量。破坏性动作前可先 collect_artifact 取证。",
            "## 可用处置原语(接口文档)\n" + "\n".join(lines),
            "## 可绑定的实体角色(entity_frame)\n" + json.dumps(
                {r: v.get("value") for r, v in entity_frame.items()}, ensure_ascii=False),
        ]
        if strategy.strip():
            parts.append("## 本类攻击的响应策略(红线/建议)\n" + strategy.strip())
        return "\n\n".join(parts)

    @staticmethod
    def _user_prompt(result, entity_frame) -> str:
        v = result.verdict
        payload = {"verdict": v.verdict if v else None, "lean": getattr(v, "lean", None),
                   "confidence": getattr(v, "confidence", None),
                   "rationale": getattr(v, "rationale", None),
                   "entity_roles": list(entity_frame)}
        return "研判结论:\n" + json.dumps(payload, ensure_ascii=False, indent=2)

    def _compose_spec(self, entity_frame) -> dict:
        roles = sorted(entity_frame)
        return {"type": "function", "function": {
            "name": "compose_response",
            "description": "组装对本次攻击的有序响应计划;每步选一个原语并把参数绑到实体角色/字面量。",
            "parameters": {"type": "object", "properties": {
                "steps": {"type": "array", "items": {"type": "object", "properties": {
                    "primitive": {"type": "string", "enum": self._menu()},
                    "params": {"type": "object",
                               "description": ("参数名→绑定。绑角色:{\"role\":\"<角色>\"}(角色取自 "
                                               + ",".join(roles) + ");或字面量:{\"value\": ...}")},
                    "risk": {"type": "string", "enum": ["low", "high"]},
                    "on_failure": {"type": "string", "enum": ["abort", "continue", "rollback_all"]},
                }, "required": ["primitive"]}}},
                "required": ["steps"]}}}

    # ---- 解析 ----
    def _parse(self, args, entity_frame) -> list:
        menu = self.iface.composer_menu_ids()
        steps = []
        order = 0
        for s in (args.get("steps") or []):
            prim = s.get("primitive")
            if prim not in menu:                    # 只认菜单内正向原语(过滤幻觉/纯 inverse)
                continue
            kf = self.iface.target_key_field(prim)
            want_kind = self.iface.kind_of(prim)
            params = {}
            drop = False
            for pname, spec in (s.get("params") or {}).items():
                if not isinstance(spec, dict):
                    continue
                if spec.get("role"):
                    role = spec["role"]
                    # ★主目标参数:绑定角色必须存在且 kind 匹配(防把 host 参数绑到账号角色,如 collect_artifact 绑 vagrant)
                    if pname == kf:
                        fr = entity_frame.get(role)
                        if not fr or (fr.get("kind") and fr["kind"] != want_kind):
                            drop = True
                            break
                    params[pname] = {"source": "entity_role", "role": role}
                elif "value" in spec:
                    params[pname] = {"source": "literal", "value": spec["value"]}
            if drop:                                # 主目标绑错 kind/无此角色 → 丢弃该步
                continue
            order += 1
            p = self.iface.get(prim)
            risk = s.get("risk") or (p.risk_default if p else "low")
            steps.append(PrimitiveStepTemplate(order=order, primitive=prim, params=params,
                                               risk=risk, on_failure=s.get("on_failure") or "abort"))
        return steps
