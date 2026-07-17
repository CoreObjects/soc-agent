"""慢通道自主研判:AgentInvestigator。

骨架保底(先反查触发事件→涉及实体,由调用方作为 seed 传入)+ LLM 在骨架内自主:
用 run_cypher 按 skill 方法论取证 → 反复 → finalize_verdict 出结构化结论。
不是死流水线;带 max_iterations + 未结论兜底 + 非法输出归一(不崩循环)。
"""
import json

from ..forensics import Forensics
from ..models import LEANS, VERDICTS, Alert, InvestigationResult, Verdict
from ..tools import FINALIZE, finalize_spec

__all__ = ["AgentInvestigator", "RecipeInvestigator", "SkillRouter", "build_result"]


def build_result(alert, skill_name, args, agent_name, trace=None, path="B", policy=None) -> InvestigationResult:
    """finalize 参数 → InvestigationResult(只出 verdict + 证据)。两种研判器共用。

    ★处置不再从 finalize 出 —— 研判保持干净;处置由独立 composer 环节在研判之后组装。
    """
    v = args.get("verdict")
    if v not in VERDICTS:
        v = "suspicious"
    lean = args.get("lean") if args.get("lean") in LEANS else None
    if v == "suspicious" and lean is None:
        lean = "unknown"                 # suspicious 必带倾向,缺则归一为 unknown(不留"纯黑洞")
    elif v != "suspicious":
        lean = None                      # 非 suspicious 不带 lean
    verdict = Verdict(
        verdict=v, lean=lean, confidence=float(args.get("confidence") or 0.0),
        summary=args.get("summary") or "", rationale=args.get("rationale") or "",
        evidence_refs=list(args.get("evidence_refs") or []),
        missing_evidence=list(args.get("missing_evidence") or []),
        agent=agent_name,
    )
    return InvestigationResult(alert_uid=alert.alert_uid, path=path, verdict=verdict,
                               dispositions=[], skill=skill_name, trace=list(trace or []))


class SkillRouter:
    """Agent Skills 的 Discovery→Activation,替 qwen 补上(qwen 无原生 skills)。

    把各 skill 的 name+description 给 LLM,LLM **按告警内容推理**选最匹配的 skill。
    不靠程序 match technique_id(那绑死检测器、换设备就废);读告警内容 → 设备无关、可移植。
    选出的 skill 交给 recipe/auto 研判。
    """

    def __init__(self, llm, registry, agent_name="agent"):
        self.llm = llm
        self.registry = registry
        self.agent_name = agent_name

    def route(self, alert, seed=None):
        """★泛化路由(可移植):只据【告警描述 + 触发它的底层事件】让 LLM 选 skill,**不依赖 technique_id/rule_id**
        (真设备未必给)。候选含 generic_*,拿不准就落该类兜底;都不像选 none。"""
        skills = self.registry.all()                 # 含 generic:让 LLM 泛化选,不做 technique→层推断
        if not skills:
            return None
        catalog = "\n".join(f"- {s.name}: {s.description or '(无描述)'}" for s in skills)
        names = [s.name for s in skills]
        ev = (seed or {}).get("event") if isinstance(seed, dict) else None    # 触发它的底层遥测事件(标准、可移植)
        system = ("你是 SOC 告警分派器。据【告警描述 + 触发它的底层事件】选**最匹配的一个**研判 skill;"
                  "拿不准就选对应大类的 generic_* 兜底;都明显不像选 none。\n\n## 可用 skills\n" + catalog)
        user = "告警:\n" + json.dumps({
            "rule_description": alert.rule_description, "source": alert.source,
            "sensor": alert.sensor, "severity": alert.severity,
            "触发它的底层事件": ev,
        }, ensure_ascii=False, indent=2, default=str)
        spec = [{"type": "function", "function": {
            "name": "select_skill",
            "description": "选出最匹配这条告警的研判 skill(拿不准选 generic_*、都不像选 none)",
            "parameters": {"type": "object", "properties": {
                "name": {"type": "string", "enum": names + ["none"]},
                "reason": {"type": "string"}},
                "required": ["name"]}}}]
        resp = self.llm.chat(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            tools=spec, tool_choice="required")
        name = None
        for tc in (resp.tool_calls or []):
            if tc.name == "select_skill":
                name = (tc.arguments or {}).get("name")
        fallback = next((s for s in skills if getattr(s, "is_generic", False)), None)   # 兜底:任一 generic
        if not name or name == "none":
            return fallback
        return self.registry.by_name(name) or fallback


_SCAFFOLD = (
    "## 研判骨架(必守)\n"
    "1) seed 已给你触发事件与涉及实体,以此为起点。\n"
    "2) 用 run_cypher 按上面方法论**只读取证**(可多次;查到 A 再顺着查 B)。\n"
    "3) 判序:先证伪(最可能的良性解释)→看基线新颖度→看权限/资产价值→看时序与扇出→看横向落地。\n"
    "4) 证据充分、或确认图里已无更多可查 → 调用 finalize_verdict 给出结论并结束。\n"
    "取证只从图取,不臆造。**证据不足就 verdict=suspicious 并在 missing_evidence 写清缺什么,别硬判 TP/FP;"
    "且 suspicious 必须带 lean(malicious/benign/unknown)标明倾向哪边、定优先级。**\n"
    "★只做定性(判 verdict),不用给处置 —— 处置由研判之后的独立环节按接口文档组装。\n"
    "\n## 工具用法\n"
    "- run_cypher 可传 params 对象绑定 $ 参数(如 {query:'...WHERE a.sam=$sam', params:{sam:'jon.snow'}}),"
    "或直接把具体值内联进查询;seed 里给了触发事件的账号/时间/主机等具体值,别用没有值的 $ 参数。"
)


class AgentInvestigator:
    """可插拔的研判器(Investigator);默认实现 = 自主 tool-calling 循环。"""

    _MAX_NUDGES = 2      # "先取证再下结论"最多打回几次,防死循环

    def __init__(self, llm, toolbox, schema, registry, agent_name="agent",
                 max_iterations=12, min_queries=1, policy=None):
        self.llm = llm
        self.toolbox = toolbox
        self.schema = schema
        self.registry = registry
        self.agent_name = agent_name
        self.max_iterations = max_iterations
        self.min_queries = min_queries      # 至少取证几次才允许 finalize(骨架保底:不准 0 取证下结论)
        self.policy = policy                # 处置护栏策略(含图派生的 DC/CA NEVER-TOUCH)

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
        return build_result(alert, skill.name if skill else None, args, self.agent_name, trace,
                            policy=self.policy)

    def _fallback(self, alert, skill, trace, reason) -> InvestigationResult:
        verdict = Verdict(verdict="suspicious", lean="unknown", confidence=0.0,
                          summary="未在预算内完成研判", rationale=reason,
                          missing_evidence=[reason], agent=self.agent_name)
        return InvestigationResult(alert_uid=alert.alert_uid, path="B", verdict=verdict,
                                   skill=(skill.name if skill else None), trace=trace)

    # ---- 主循环 ----
    def investigate(self, alert: Alert, seed=None, skill=None) -> InvestigationResult:
        # skill 由 SkillRouter(LLM 按 description)预选后传入,不在此程序 match technique
        messages = [
            {"role": "system", "content": self._system_prompt(skill)},
            {"role": "user", "content": self._user_prompt(alert, seed)},
        ]
        specs = self.toolbox.specs()
        trace = []
        queries_done = 0
        finalize_nudges = 0
        for _ in range(self.max_iterations):
            resp = self.llm.chat(messages, tools=specs, tool_choice="required")  # 逼它每轮必须调工具,别光说话
            if not resp.tool_calls:
                # tool_choice=required 下本不该走到这;真发生 = 模型/vLLM 没吐出可解析的工具调用
                trace.append({"tool": "no_tool_call", "content": (resp.content or "")[:400]})
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user",
                                 "content": "你必须调用工具:先用 run_cypher 按方法论查图取证,再用 finalize_verdict 给结论。"})
                continue
            messages.append(self._assistant_msg(resp))
            for tc in resp.tool_calls:
                if self.toolbox.is_terminal(tc.name):        # finalize
                    if queries_done < self.min_queries and finalize_nudges < self._MAX_NUDGES:
                        finalize_nudges += 1                 # ★骨架保底:0 取证不准下结论,打回去查图
                        trace.append({"tool": "finalize_too_early", "nudge": finalize_nudges})
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


_RECIPE_SCAFFOLD = (
    "## 定性(证据已备齐,不用再查图)\n"
    "下面「证据」是按方法论**已经确定性取好的**。你只需据此**定性**,直接调用 finalize_verdict:\n"
    "- **先证伪**:请求者域与目标域之间若有 **TRUSTS**(见证据「跨域信任」)= 跨域信任的正常 RC4 = "
    "**false_positive**;尤其请求者是机器账号/域控($ 结尾)+ 目标是被信任域时,基本可定 FP。\n"
    "- 再看:目标是否特权/属特权组、请求者 enc 基线、SPN 扇出。\n"
    "- 证据足 → 给明确 verdict;确实不足 → suspicious 并在 missing_evidence 写清缺什么。\n"
    "- ★出 suspicious **必须**带 lean(malicious=大概率攻击待确证 / benign=大概率正常但没法完全排除 / "
    "unknown=真两可)—— 别只甩「存疑」,要说往哪边倾、好定优先级。★只判 verdict,不给处置(处置另有独立环节)。"
)


class RecipeInvestigator:
    """确定性取证脚本(recipe)+ LLM 定性。

    orchestrator 跑 skill 的 recipe 把关键证据(含跨域信任)一次性收齐 → 喂给 LLM →
    LLM **只判断、不规划查询**(扬长避短:模型推理强、规划弱)。covered 告警类型走这条,稳。
    """

    def __init__(self, llm, graph, schema, registry, agent_name="agent", policy=None):
        self.llm = llm
        self.graph = graph
        self.schema = schema
        self.registry = registry
        self.agent_name = agent_name
        self.policy = policy                # 处置护栏策略(含图派生的 DC/CA NEVER-TOUCH)

    def _prompt(self, skill) -> str:
        parts = ["你是资深 SOC 研判分析师,只依据给你的证据判断,不臆造。",
                 "## 图 Schema(理解证据用)\n" + self.schema]
        if skill is not None:
            parts.append(f"## 方法论(skill: {skill.name})\n{skill.methodology}")
        parts.append(_RECIPE_SCAFFOLD)
        return "\n\n".join(parts)

    def _recall_similar(self, alert):
        """情报:图里同技术的历史判例(过去同类告警怎么判的),喂给 LLM 作参考。"""
        techs = alert.technique_ids or []
        if not techs:
            return None
        try:
            rows = self.graph.run_cypher(
                "MATCH (al:Alert)-[:CONCLUDED]->(v:Verdict) "
                "WHERE al.alert_uid <> $uid AND any(t IN coalesce(al.technique_ids,[]) WHERE t IN $techs) "
                "RETURN v.verdict AS verdict, count(*) AS n, collect(v.summary)[0..2] AS examples "
                "ORDER BY n DESC LIMIT 5",
                uid=alert.alert_uid, techs=techs)
            return rows or None
        except Exception:
            return None

    def investigate(self, alert: Alert, seed=None, skill=None) -> InvestigationResult:
        trace = []                                                  # skill 由 SkillRouter 预选传入
        forensics = Forensics.coerce(skill.recipe(self.graph, alert, seed))   # ★确定性取证 → 结构化(含跨域信任)
        evidence = dict(forensics.context)                          # 人读证据(喂 LLM)
        if forensics.findings:
            evidence["结构化发现(findings)"] = [f.to_dict() for f in forensics.findings]
        if forensics.blind_spots:
            evidence["_图盲区"] = forensics.blind_spots
        sim = self._recall_similar(alert)                           # ★情报召回:历史相似判例
        if sim:
            evidence["历史相似判例(情报)"] = sim
            trace.append({"tool": "recall_similar", "step": "历史相似判例", "rows": len(sim)})
        for name, res in evidence.items():
            trace.append({"tool": "recipe_step", "step": name,
                          "rows": len(res) if isinstance(res, list) else 1})
        user = "待研判告警 + 已备齐证据:\n" + json.dumps(
            {"alert": {"alert_uid": alert.alert_uid, "rule_id": alert.rule_id,
                       "technique_ids": alert.technique_ids, "time": alert.time},
             "证据": evidence}, ensure_ascii=False, indent=2, default=str)
        resp = self.llm.chat(
            [{"role": "system", "content": self._prompt(skill)},
             {"role": "user", "content": user}],
            tools=finalize_spec(), tool_choice="required")   # 只给 finalize,逼它直接定性
        result = None
        for tc in (resp.tool_calls or []):
            if tc.name == FINALIZE:
                result = build_result(alert, skill.name, tc.arguments or {}, self.agent_name, trace,
                                      policy=self.policy)
                break
        if result is None:
            result = build_result(alert, skill.name, {
                "verdict": "suspicious", "confidence": 0.0,
                "rationale": "recipe 已取证但模型未给结论", "missing_evidence": ["模型未 finalize"],
            }, self.agent_name, trace, policy=self.policy)
        result.findings = list(forensics.findings)      # ★findings/bindings 上浮:供经验沉淀/案例快照/处置重绑
        result.bindings = dict(forensics.bindings)
        return result
