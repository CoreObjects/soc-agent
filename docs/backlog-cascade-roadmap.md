# 待办:浅度研判 cascade 路线图(scope A 之后)

> 这轮(scope A)只建了**浅度研判第二档**:openJiuwen WorkflowAgent = 浅层通用提示词直判 → 判不动才升级到现有深度研判。以下是**有意延后**的部分,按依赖排。

## 升级信号 v2(浅→深怎么决定升级)
- 现状 v1:保守提示词分类(浅层只终局判 FP)+ 确定性硬底线 `force_deep`(高危技战术 / 受保护主机)。**不用 LLM 自报置信度**(调研:自报不可靠)。
- v2:**自一致性**(浅层采样 N 次,结论打架就升级)→ 攒够"浅层判过、后被深度推翻"的样本后训**小探针 / pre-router**,把升级率标定到目标值。
- 触发条件:真机 selftest 出 deferral rate 后,若要进一步压误升级/漏升级再上。

## 浅层判例沉淀
- 现状:浅层终局判(path="S")**不进经验层**(不 sediment)。
- 待办:把浅层判例也纳入回归语料 / 蒸馏(需要先想清楚"无取证的 payload 直判"怎么形成可复用指纹——见下方 B 类经验)。

## B 类经验(经验情报层,当时划到断层的三块)
- **B2 payload 语义→类 的签名库**:LLM 蒸出的 payload 类别 + 归一器(非 recipe 确定性可复现,现机器表达不了,需新结构)。
- **B3 IP/域信誉**:外部情报喂数(图已留槽 `:IPAddress.reputation`/`:Domain.reputation`,无喂数)——见 [[backlog-telemetry-gaps]]。
- **B4 实体台账召回**:按 IP/端点/账号**实体键**查它自己的历史判例/处置/基线(现经验库只按 skill+finding 集召回,无实体索引;本质是图查询,跨 skill)。
- 三块都**只设计、不建**;经验层这轮一行没动。

## 真拆快/慢模型(9B / 122B)
- 现状:server2 单 qwen。深度档折叠成一个 LLM。
- 待办:真引第二个模型时,openJiuwen 的 **IntelliRouter**(`client_provider="intelli_router"`,需 `pip install intelli-router`)正好做**模型级** failover/成本路由——注意它是"哪个后端模型答这次调用",不是浅/深决策(浅/深仍是我们的 `BranchRouter`)。

## 深度层迁 openJiuwen(scope B/C)
- **B**:把整条 run_pipeline 重表达成 openJiuwen workflow(浅+深都在图里),skills/经验层内部不动。
- **C**:skills → openJiuwen `Skill`/`SkillManager`(`single_agent/skills/skill_manager.py`),经验层 → 它的 `agent_evolving` 自演进/RL。

## 部署硬约束(openJiuwen 引入的)
- **openjiuwen 要求 Python 3.11–3.13**;soc-agent 原 venv 是 3.10。**开 cascade 必须 3.11+ 环境**(dev 本机用 `.venv312`;server2 昇腾同理)。cascade 关闭时不 import openjiuwen,3.10 深度-only 照跑(灰度/回滚位)。
