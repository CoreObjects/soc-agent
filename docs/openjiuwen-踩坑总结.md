# openJiuwen(agent-core)踩坑总结与选型决策

> 面向:soc-agent 浅层研判(cascade)基于 openJiuwen `WorkflowAgent` 的落地。
> 结论先行:**openJiuwen 的工作流编排能用,但它的 LLM 客户端在持续负载下 ~50% 调用失败(实测),
> 且 `Runner` 进程单例 + 事件循环强耦合让并发很难做。浅层只是"包一次 LLM 判定",
> 决定改用直连昇腾 qwen 的 `QwenClient`(requests)——同一个昇腾端点、实测 100% 稳,并顺带删掉下列全部坑。**
> openJiuwen 的"昇腾亲和"= LLM 跑在昇腾 qwen 上,这一点换客户端后不变(仍打同一个昇腾 qwen)。

日期:2026-07-24。版本:agent-core(openJiuwen)当期 clone(`C:\Users\Core_Objects\Code\agent-core`)。

---

## 0. 我们用 openJiuwen 干了啥(范围)
只用它搭**浅层分诊**这一层:`Start → LLMComponent(浅层判 needs_deep/verdict)→ BranchRouter → {深度 | 终局} → End`。
即:**一次 LLM 判定**外面套了个 Workflow。深度研判、经验层、处置都不经 openJiuwen。

---

## 1. 工作流执行超时:默认才 60s(错误码 100101)
- **现象**:qwen 在昇腾单次调用常 >60s,工作流层直接掐断,报 `100101 workflow execute timeout`。
- **根因**:`WorkflowSession` 的执行超时从**进程 OS 环境变量 `WORKFLOW_EXECUTE_TIMEOUT`** 读;`Runner.run_agent(envs=...)` 传进去的 env **被丢弃**、不生效。
- **修**:进程级 `os.environ.setdefault("WORKFLOW_EXECUTE_TIMEOUT", str(seconds))`,且要**足够大**(包住可能多轮的深度)。

## 2. LLM 请求超时 + 重试放大(~4 分钟才失败)
- **现象**:单次 LLM 调用要等约 4 分钟才报失败。
- **根因**:`ModelClientConfig` 默认 `timeout=60` + `max_retries=3` ≈ 60×(1+3)。
- **修**:`ModelClientConfig(timeout=<真实需要>, max_retries=1)`。

## 3. qwen3 思维链没关 → 输出非 JSON(错误码 101004)
- **现象**:`101004 Json parse error`,openJiuwen `json.loads` 崩;直接 probe qwen 发现开思维链时会吐 `<think>…` 或回显输入。
- **根因**:openJiuwen 的 client **不像自研 QwenClient 那样默认关思维链**;qwen3 开思维链输出不是干净 JSON。
- **修**:`ModelRequestConfig(extra_body={"chat_template_kwargs": {"enable_thinking": False}})`。
  能透传是因为 `base_model_client.py` 会把 `ModelRequestConfig` 的额外字段 dump 进请求体 → `extra_body` 透到 vLLM。低温(temperature=0.1)更稳。

## 4. BranchRouter 条件表达式:字符串量必须加引号,否则被改坏
- **现象**:想按 `${shallow.verdict} == true_positive` 分叉,直接写裸词会崩或永假。
- **根因**:`condition/expression.py` 的 `RULES` 用**朴素正则**把 `true→True`、`false→False` **全局替换**(在保护字符串字面量之后)。于是裸词 `true_positive` 被改成 `True_positive`(未定义名)→ 求值报错。
- **修**:用**单引号字符串字面量** `${shallow.verdict} == 'true_positive'`(带引号的字面量在 RULES 前被保护、不被改)。`${x}` 不是文本替换,是解析成 `var_i` 再从 runtime dict 取值,所以 `var_i == 'true_positive'` 正常。

## 5. 会话必须在"运行中的事件循环内"创建
- **现象**:非运行循环里 `create_workflow_session()` 会出问题。
- **根因**:openJiuwen 内部用 `get_event_loop`。
- **修**:`create_workflow_session()` 放在 `await flow.invoke(...)` 的**同一个协程内**(即已在运行的 loop 里)创建。

## 6. ★Runner 是进程级单例,不能多线程并发调 `run_agent`
- **现象**:2 并发跑,工作流**跑不到出口**,结果 sink 空(下游拿不到,报 `'result'`)+ **挂死**。单线程时完全正常。
- **根因(读源码坐实)**:`runner.py` 底部 `GLOBAL_RUNNER = _RunnerImpl()` —— **Runner 是进程单例**,其异步态(`_resource_manager`/`_message_queue`/`_root_task_group`)**绑定单一 event loop**。多 worker 线程(各自 loop)并发调 `Runner.run_agent` → 共享 task-group/queue 打架 → 崩。
- **关键线索**:`flow.invoke()` **不碰**这个单例 —— 所以只用 `flow.invoke` 的那条路(浅层探针)一直没事,用 `Runner.run_agent` 的那条一并发就挂。
- **修/规避**:别用 `Runner.run_agent` 做并发;要么 `flow.invoke` 直接跑,要么把所有 openJiuwen 调用**收到一个专用单线程**上串行。

## 7. worker 线程要在"openJiuwen 同步构建之前"就 set 好事件循环
- **现象**:`There is no current event loop in thread 'ThreadPoolExecutor-…'`。
- **根因**:`build_*`(构建 agent/workflow)是**同步**代码、跑在协程之外;openJiuwen 在构建期**同步调 `get_event_loop`**,而非主线程默认没有 loop → 抛错。只在 `asyncio.run`/`run_until_complete` 里 set 太晚。
- **修**:在 build **之前** `asyncio.set_event_loop(asyncio.new_event_loop())`;并给线程池 `ThreadPoolExecutor(initializer=…)` 让每个 worker 线程一创建就有 loop。

## 8. ★★决定性坑:LLM 客户端在持续负载下 ~50% 调用失败(错误码 101003)
- **现象**:放开全量后台跑,处理 ~6.5 万条里 **~一半在浅层 LLM 调用崩**,报 `101003 component llm_invoke call failed, reason: invoke llm failed`(9.9 万条错误行=约 3.3 万条告警 ×3 重试)。
- **实测对照**:
  - 深度侧用**自研 `QwenClient`(requests)打同一个昇腾 qwen 端点 → 100% 成功**;
  - 浅层用 **openJiuwen 的 `LLMComponent` 客户端打同一个端点 → ~50% 失败**。
  - 日志前半/后半的 `101003` 计数 **350693 ≈ 352187**(几乎相等)→ **从头就 ~50% 崩、不是连接泄漏随时间恶化**。
- **判定**:**同端点、同模型,唯一变量是客户端** → 问题在 **openJiuwen 的 LLM 客户端本身**(在这种单线程串行、持续高频调用下不稳),不是昇腾后端、不是网络。
- **修(选型决策)**:浅层这次 LLM 判定**改用 `QwenClient`**(与深度同款、已证 100% 稳),不再走 openJiuwen 的 LLMComponent。顺带把坑 1/2/3/5/6/7 那一整套 openJiuwen 复杂度**全部删掉**,浅层反而更简单更稳。

## 9. SDK 仍在变动:一堆 Deprecation
- `WorkflowAgentConfig`/`AgentConfig` 已弃用 → 建议 `AgentCard + ReActAgentConfig`;
- `WorkflowSchema` → `WorkflowCard`;`DefaultResponse`、`BaseAgent(legacy)` 均弃用。
- **提示**:legacy API 弃用很快,跟版本要留意。

---

## 结论与建议
1. **浅层 LLM 判定改用 `QwenClient` 直连昇腾 qwen**(本仓已有、深度在用、实测 100% 稳)。昇腾亲和不变(仍打昇腾 qwen)。
2. 换掉后,openJiuwen 相关的**单例/事件循环/超时/思维链/表达式**那一整套坑(1–7)**随之消失**,浅层代码大幅简化。
3. openJiuwen 的**工作流编排**(BranchRouter/多组件)本身对**复杂多步**流程也许仍有价值;但对"**包一次 LLM 调用**"这种场景,收益远小于它带来的客户端不稳 + 并发困难 + 版本动荡的成本。
4. 若领导仍要求保留 openJiuwen:可把它降级为**仅编排骨架**、LLM 调用注入 `QwenClient`(绕开其 LLMComponent 客户端)——但坑 6(Runner 单例并发)仍需用"专用单线程串行"规避,不如直接 `QwenClient` 干净。

> 一句话:**openJiuwen 能编排,但它的 LLM 客户端扛不住我们的生产吞吐(实测 50% 失败),而直连昇腾 qwen 的 QwenClient 稳、简单、够用。**
