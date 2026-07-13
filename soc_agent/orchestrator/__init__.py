"""慢通道自主研判:AgentInvestigator。

骨架保底(先反查触发事件→涉及实体,由调用方作为 seed 传入)+ LLM 在骨架内自主:
用 run_cypher 按 skill 方法论取证 → 反复 → finalize_verdict 出结构化结论。
不是死流水线;带 max_iterations + 未结论兜底 + 非法输出归一(不崩循环)。
"""
import json

from ..models import DISPOSITION_ACTIONS, RISKS, VERDICTS, Alert, Disposition, InvestigationResult, Verdict
from ..skills_runtime import SkillNotFound
from ..tools import FINALIZE

__all__ = ["AgentInvestigator", "infer_layer"]

# technique → 层(仅用于"未命中具体 skill 时选该层通用兜底";具体 skill 按 technique 直配)
_LAYER_BY_PREFIX = {
    "identity": ["T1558", "T1649", "T1003.006", "T1550", "T1021", "T1207", "T1484"],
    "host": ["T1003.001", "T1003.002", "T1105", "T1547", "T1112", "T1059", "T1055", "T1218", "T1543"],
    "application": ["T1190", "T1505"],
    "network": ["T1071", "T1568", "T1571", "T1090", "T1041", "T1048"],
}


def infer_layer(alert: Alert):
    for t in alert.technique_ids or []:
        for layer, prefixes in _LAYER_BY_PREFIX.items():
            if any(t == p or t.startswith(p + ".") or t == p for p in prefixes):
                return layer
    return None


_SCAFFOLD = (
    "## 研判骨架(必守)\n"
    "1) seed 已给你触发事件与涉及实体,以此为起点。\n"
    "2) 用 run_cypher 按上面方法论**只读取证**(可多次;查到 A 再顺着查 B)。\n"
    "3) 判序:先证伪(最可能的良性解释)→看基线新颖度→看权限/资产价值→看时序与扇出→看横向落地。\n"
    "4) 证据充分、或确认图里已无更多可查 → 调用 finalize_verdict 给出结论并结束。\n"
    "取证只从图取,不臆造。**证据不足就 verdict=suspicious 并在 missing_evidence 写清缺什么,别硬判 TP/FP。**\n"
    "\n## 工具用法\n"
    "- run_cypher 可传 params 对象绑定 $ 参数(如 {query:'...WHERE a.sam=$sam', params:{sam:'jon.snow'}}),"
    "或直接把具体值内联进查询;seed 里给了触发事件的账号/时间/主机等具体值,别用没有值的 $ 参数。\n"
    "- 处置动作只能从词表选:disable_account/block_ip/isolate_host/kill_process/reset_password/"
    "revoke_sessions/quarantine_file/escalate/monitor/none。**verdict=suspicious 或证据不足时用 escalate/monitor,别提高危动作。**"
)


class AgentInvestigator:
    """可插拔的研判器(Investigator);默认实现 = 自主 tool-calling 循环。"""

    _MAX_NUDGES = 2      # "先取证再下结论"最多打回几次,防死循环

    def __init__(self, llm, toolbox, schema, registry, agent_name="agent",
                 max_iterations=12, min_queries=1):
        self.llm = llm
        self.toolbox = toolbox
        self.schema = schema
        self.registry = registry
        self.agent_name = agent_name
        self.max_iterations = max_iterations
        self.min_queries = min_queries      # 至少取证几次才允许 finalize(骨架保底:不准 0 取证下结论)

    # ---- 提示构建 ----
    def _system_prompt(self, skill) -> str:
        parts = [
            "你是资深 SOC 研判分析师。只依据知识图谱里的证据研判,绝不臆造。",
            "## 图 Schema(只用这里列出的 label/键/谓语写 Cypher,别自创)\n" + self.schema,
        ]
        if skill is not None:
            parts.append(f"## 研判方法论(skill: {skill.name})\n{skill.methodology}")
        parts.append(_SCAFFOLD)
        return "\n\n".join(parts)

    @staticmethod
    def _user_prompt(alert: Alert, seed) -> str:
        payload = {
            "alert": {
                "alert_uid": alert.alert_uid, "rule_id": alert.rule_id,
                "rule_description": alert.rule_description, "severity": alert.severity,
                "technique_ids": alert.technique_ids, "time": alert.time,
            },
            "seed(触发事件+涉及实体)": seed or {},
        }
        return "待研判告警:\n" + json.dumps(payload, ensure_ascii=False, indent=2)

    @staticmethod
    def _assistant_msg(resp) -> dict:
        return {
            "role": "assistant",
            "content": resp.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.name, "arguments": json.dumps(tc.arguments, ensure_ascii=False)}}
                for tc in resp.tool_calls
            ],
        }

    @staticmethod
    def _tool_msg(tool_call_id, result) -> dict:
        return {"role": "tool", "tool_call_id": tool_call_id,
                "content": json.dumps(result, ensure_ascii=False, default=str)}

    # ---- 结果构建 ----
    def _build_result(self, alert, skill, args, trace) -> InvestigationResult:
        v = args.get("verdict")
        if v not in VERDICTS:            # LLM 偶尔自由措辞/非法 → 归一,不崩
            v = "suspicious"
        verdict = Verdict(
            verdict=v,
            confidence=float(args.get("confidence") or 0.0),
            summary=args.get("summary") or "",
            rationale=args.get("rationale") or "",
            evidence_refs=list(args.get("evidence_refs") or []),
            missing_evidence=list(args.get("missing_evidence") or []),
            pattern=args.get("pattern"),
            agent=self.agent_name,
        )
        dispositions = []
        for d in args.get("dispositions") or []:
            risk = d.get("risk") if d.get("risk") in RISKS else "low"
            act = d.get("action") or "none"
            if act not in DISPOSITION_ACTIONS:       # 自由发挥的动作 → 归一为升级人工,不落废话
                act = "escalate"
            dispositions.append(Disposition(action=act, target=d.get("target"), risk=risk))  # 默认 proposed
        return InvestigationResult(
            alert_uid=alert.alert_uid, path="B", verdict=verdict, dispositions=dispositions,
            skill=(skill.name if skill else None), trace=trace,
        )

    def _fallback(self, alert, skill, trace, reason) -> InvestigationResult:
        verdict = Verdict(verdict="suspicious", confidence=0.0,
                          summary="未在预算内完成研判", rationale=reason,
                          missing_evidence=[reason], agent=self.agent_name)
        return InvestigationResult(alert_uid=alert.alert_uid, path="B", verdict=verdict,
                                   skill=(skill.name if skill else None), trace=trace)

    # ---- 主循环 ----
    def investigate(self, alert: Alert, seed=None) -> InvestigationResult:
        try:
            skill = self.registry.select(alert, layer=infer_layer(alert))
        except SkillNotFound:
            skill = None
        messages = [
            {"role": "system", "content": self._system_prompt(skill)},
            {"role": "user", "content": self._user_prompt(alert, seed)},
        ]
        specs = self.toolbox.specs()
        trace = []
        queries_done = 0
        finalize_nudges = 0
        for _ in range(self.max_iterations):
            resp = self.llm.chat(messages, tools=specs)
            if not resp.tool_calls:
                # 只给了文本没调工具 → 催它先取证再 finalize_verdict
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user",
                                 "content": "请用 run_cypher 按方法论查图取证后,再用 finalize_verdict 给结论。"})
                continue
            messages.append(self._assistant_msg(resp))
            for tc in resp.tool_calls:
                if self.toolbox.is_terminal(tc.name):        # finalize
                    if queries_done < self.min_queries and finalize_nudges < self._MAX_NUDGES:
                        finalize_nudges += 1                 # ★骨架保底:0 取证不准下结论,打回去查图
                        messages.append(self._tool_msg(tc.id, {
                            "error": "还没查图取证就下结论,不允许。请先用 run_cypher 按上面方法论取证"
                                     "(先证伪 → 看权限 privileged/组成员 → 看基线扇出 → 看是否跨域),再 finalize。"}))
                        continue
                    return self._build_result(alert, skill, tc.arguments or {}, trace)
                result = self.toolbox.dispatch(tc.name, tc.arguments)
                queries_done += 1
                trace.append({"tool": tc.name, "args": tc.arguments, "result": result})
                messages.append(self._tool_msg(tc.id, result))
        return self._fallback(alert, skill, trace, "达到最大研判轮次仍未结论")
