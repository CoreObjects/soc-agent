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

from .components import DeepInvestigationComponent, ShallowTerminalComponent
from .prompt import SHALLOW_OUTPUT_SCHEMA, SHALLOW_PROMPT

__all__ = ["build_cascade_workflow", "build_cascade_agent"]

_ESCALATE_COND = "${shallow.needs_deep} == true || ${start.force_deep} == true"


def _shallow_component(llm_base, llm_model, llm_key):
    cfg = LLMCompConfig(
        model_client_config=ModelClientConfig(
            client_provider="OpenAI", api_key=(llm_key or "EMPTY"),
            api_base=llm_base, verify_ssl=False),
        model_config=ModelRequestConfig(model=llm_model),
        template_content=[
            {"role": "system", "content": SHALLOW_PROMPT},
            {"role": "user", "content": "{{alert_view}}"},
        ],
        response_format={"type": "json"},
        output_config=SHALLOW_OUTPUT_SCHEMA,
    )
    return LLMComponent(cfg)


def build_cascade_workflow(graph, run_deep, sink, *, llm_base=None, llm_model=None,
                           llm_key=None, agent_name=None, shallow_comp=None):
    flow = Workflow(card=WorkflowCard(
        id="soc_cascade", name="soc_cascade", version="1.0",
        description="SOC 告警浅度分诊 + 判不动升级深度研判",
        input_params={"type": "object", "properties": {
            "alert_view": {"type": "string"},
            "alert_uid": {"type": "string"},
            "force_deep": {"type": "boolean"},
        }, "required": ["alert_view", "alert_uid"]}))

    shallow = shallow_comp or _shallow_component(llm_base, llm_model, llm_key)
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


def build_cascade_agent(graph, run_deep, sink, *, llm_base=None, llm_model=None,
                        llm_key=None, agent_name=None, shallow_comp=None):
    flow = build_cascade_workflow(graph, run_deep, sink, llm_base=llm_base, llm_model=llm_model,
                                  llm_key=llm_key, agent_name=agent_name, shallow_comp=shallow_comp)
    agent = WorkflowAgent(WorkflowAgentConfig(
        id="soc_cascade_agent", version="0.1.0", description="SOC 浅度分诊 cascade"))
    agent.add_workflows([flow])
    return agent
