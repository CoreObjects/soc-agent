"""装配 cascade 的 openJiuwen Workflow / WorkflowAgent。

图:Start → shallow(LLMComponent) → 条件分叉 → {deep | terminal} → End。
- 分叉:``${shallow.needs_deep} == true || ${start.force_deep} == true`` → deep;空串(else)→ terminal。
- 结果走组件写进的 `sink`(见 components),End 只做收敛,输出不被使用。
- `shallow_comp` 可注入(测试用假浅层,免真 LLM 端点);默认真 LLMComponent 接 qwen vLLM。
"""
from openjiuwen.core.application.workflow_agent import WorkflowAgent
from openjiuwen.core.foundation.llm import ModelClientConfig, ModelRequestConfig
from openjiuwen.core.single_agent.legacy import WorkflowAgentConfig
from openjiuwen.core.workflow import (
    BranchRouter,
    End,
    LLMComponent,
    LLMCompConfig,
    Start,
    Workflow,
    WorkflowCard,
)

from .components import CaptureComponent, DeepInvestigationComponent, ShallowTerminalComponent
from .prompt import SHALLOW_OUTPUT_SCHEMA, SHALLOW_PROMPT

__all__ = ["build_cascade_workflow", "build_cascade_agent", "build_shallow_probe"]

_ESCALATE_COND = "${shallow.needs_deep} == true || ${start.force_deep} == true"


def _shallow_component(llm_base, llm_model, llm_key, llm_timeout=600):
    cfg = LLMCompConfig(
        model_client_config=ModelClientConfig(
            client_provider="OpenAI", api_key=(llm_key or "EMPTY"),
            api_base=llm_base, verify_ssl=False,
            # ★qwen 慢:openJiuwen LLM 请求超时默认才 60s + 3 retry ≈ 4min 全废
            timeout=float(llm_timeout), max_retries=1),
        # ★关 qwen3 思维链:开着会吐 <think>/回显输入,污染 JSON→openJiuwen json.loads 崩(它不像 QwenClient 默认关);
        #   base_model_client 会把 model_config 的额外字段 dump 进请求 → extra_body 透传到 vLLM。低温更稳。
        model_config=ModelRequestConfig(
            model=llm_model, temperature=0.1,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}}),
        template_content=[
            {"role": "system", "content": SHALLOW_PROMPT},
            {"role": "user", "content": "{{alert_view}}"},
        ],
        response_format={"type": "json"},
        output_config=SHALLOW_OUTPUT_SCHEMA,
    )
    return LLMComponent(cfg)


def build_cascade_workflow(graph, run_deep, sink, *, llm_base=None, llm_model=None,
                           llm_key=None, llm_timeout=600, agent_name=None, shallow_comp=None):
    flow = Workflow(card=WorkflowCard(
        id="soc_cascade", name="soc_cascade", version="1.0",
        description="SOC 告警浅度分诊 + 判不动升级深度研判",
        input_params={"type": "object", "properties": {
            "alert_view": {"type": "string"},
            "alert_uid": {"type": "string"},
            "force_deep": {"type": "boolean"},
        }, "required": ["alert_view", "alert_uid"]}))

    shallow = shallow_comp or _shallow_component(llm_base, llm_model, llm_key, llm_timeout)
    deep = DeepInvestigationComponent(run_deep, sink)
    terminal = ShallowTerminalComponent(graph, sink, agent_name=agent_name)

    flow.set_start_comp("start", Start(), inputs_schema={
        "alert_view": "${alert_view}", "alert_uid": "${alert_uid}", "force_deep": "${force_deep}"})
    flow.add_workflow_comp("shallow", shallow, inputs_schema={"alert_view": "${start.alert_view}"})
    flow.add_connection("start", "shallow")         # start → 浅层(普通边;下面才是浅层的条件出边)

    router = BranchRouter()
    router.add_branch(_ESCALATE_COND, "deep")
    router.add_branch("", "terminal")               # 空串=else(无隐式默认,必须显式)
    flow.add_conditional_connection("shallow", router=router)

    flow.add_workflow_comp("deep", deep, inputs_schema={"alert_uid": "${start.alert_uid}"})
    flow.add_workflow_comp("terminal", terminal, inputs_schema={
        "alert_uid": "${start.alert_uid}",
        "confidence": "${shallow.confidence}",
        "rationale": "${shallow.rationale}"})

    # End 只收敛(真结果走 sink);两个分支各引用一个,未跑的那个解析为空,框架容忍。
    flow.set_end_comp("end", End({"responseTemplate": "{{deep_path}}{{term_path}}"}),
                      inputs_schema={"deep_path": "${deep.path}", "term_path": "${terminal.path}"})
    flow.add_connection("deep", "end")
    flow.add_connection("terminal", "end")
    return flow


def build_shallow_probe(sink, *, llm_base=None, llm_model=None, llm_key=None,
                        llm_timeout=600, shallow_comp=None):
    """只跑浅层分诊、把决策抓进 sink['shallow'] 的探针图(Start→shallow→capture→End)。
    ★不分叉、不升级、不写台账 —— 供 selftest 量 deferral / 眼验召回,可反复跑不污染。"""
    flow = Workflow(card=WorkflowCard(
        id="soc_shallow_probe", name="soc_shallow_probe", version="1.0",
        description="只跑浅层分诊、抓决策(量 deferral)",
        input_params={"type": "object", "properties": {"alert_view": {"type": "string"}},
                      "required": ["alert_view"]}))
    shallow = shallow_comp or _shallow_component(llm_base, llm_model, llm_key, llm_timeout)
    flow.set_start_comp("start", Start(), inputs_schema={"alert_view": "${alert_view}"})
    flow.add_workflow_comp("shallow", shallow, inputs_schema={"alert_view": "${start.alert_view}"})
    flow.add_connection("start", "shallow")
    flow.add_workflow_comp("capture", CaptureComponent(sink), inputs_schema={
        "needs_deep": "${shallow.needs_deep}", "verdict": "${shallow.verdict}",
        "confidence": "${shallow.confidence}", "rationale": "${shallow.rationale}"})
    flow.add_connection("shallow", "capture")
    flow.set_end_comp("end", End({"responseTemplate": "{{ok}}"}), inputs_schema={"ok": "${capture.ok}"})
    flow.add_connection("capture", "end")
    return flow


def build_cascade_agent(graph, run_deep, sink, *, llm_base=None, llm_model=None,
                        llm_key=None, llm_timeout=600, agent_name=None, shallow_comp=None):
    flow = build_cascade_workflow(graph, run_deep, sink, llm_base=llm_base, llm_model=llm_model,
                                  llm_key=llm_key, llm_timeout=llm_timeout, agent_name=agent_name,
                                  shallow_comp=shallow_comp)
    agent = WorkflowAgent(WorkflowAgentConfig(
        id="soc_cascade_agent", version="0.1.0", description="SOC 浅度分诊 cascade"))
    agent.add_workflows([flow])
    return agent
