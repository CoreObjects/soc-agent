# openJiuwen(agent-core)Issue 草稿 —— 可直接粘贴到 GitCode

> 提交目标仓:**`openJiuwen/agent-core`**(https://gitcode.com/openJiuwen/agent-core)——仓名叫 `agent-core`,不是 `openjiuwen`(那是包名)。
> 一个 issue 一个问题。下面「详细环境信息」块每个 issue 的该字段**都填同一段**(都在同一环境跑出)。
> 源码定位以 **openjiuwen 0.1.16** 为准(`文件:函数` + 行号)。

---

## 详细环境信息(粘进每个 issue 的「详细环境信息」字段)

```
- 框架:openjiuwen 0.1.16(仓库 openJiuwen/agent-core)
- Python:3.11.6
- OS:openEuler 24.09
- 内核:6.6.0-45.0.0.54.oe2409.aarch64
- 架构:aarch64(ARM64)
- CPU:HiSilicon Kunpeng-920,256 核
- 内存:2.0 TiB
- 昇腾驱动:Version 25.5.2(ascendhal 7.35.23)——注:LLM 后端所在;openjiuwen 仅经 HTTP 连它,不直接用 NPU
- 关键依赖:openai 2.47.0 · httpx 0.28.1 · httpcore 1.0.9 · anyio 4.14.2 · pydantic 2.13.4 · aiohttp 3.14.3
- LLM 后端:昇腾 qwen(vLLM,OpenAI 兼容端点),模型 qwen3.5-9b / qwen3.5-27b
- 运行方式:后台轮询,单线程串行、持续高频调用(约 6.5 万次)
```

---

## Issue 1(P0·旗舰)

**标题**:`[Bug] LLM 客户端每次调用新建并销毁 httpx 连接、无连接池,持续高并发下大量调用失败(101003)`
**标签**:bug, performance, llm

### 现象
放开全量后台运行(约 6.5 万次调用),约 **一半** 在组件 LLM 调用处失败,报
`101003 component llm_invoke call failed, reason: invoke llm failed`。
对照:同一端点、同一模型,换用自研 requests 客户端直连 → 0 失败。日志前/后半段 101003 计数几乎相等
→ 从一开始就 ~50% 失败,不是随时间恶化的连接泄漏。

### 源码定位(疑似根因)
`openjiuwen/core/foundation/llm/model_clients/openai_model_client.py`
- `_create_async_openai_client`(L110-142):**每次调用**都新建 `httpx.AsyncClient(proxy=..., verify=...)`(L122-125),
  **未传 `limits`、未设 keepalive、未开 http2**;
- `invoke`(L222 创建)/ `stream`(L378 创建),且 `finally` 里**每次调用结束立即 `await async_client.close()`**(L288-290 / L451-453)。

即:**每次 LLM 调用都重新完成一次 TCP+TLS 握手再拆掉,连接不复用**。持续并发下 socket/临时端口/握手抖动剧烈,疑为大量失败的根因。

补充:框架其实**已实现连接池但未接入 LLM 路径**——`openjiuwen/core/common/clients/llm_client.py` 的 `HttpXConnectorPool`、
`openjiuwen/core/common/clients/connector_pool.py` 的 `ConnectorPoolManager`(limit/keepalive/ttl 齐全),但
`model_clients/` 下仅 openai/anthropic 直接用裸 `httpx.AsyncClient`,未引用这套池。

### 期望
LLM 客户端复用连接(连接池 + keepalive),不要每次调用新建/销毁,持续负载下稳定。

### 建议修复
给 `AsyncOpenAI(http_client=...)` 传一个**按 model_client 缓存复用**的 `httpx.AsyncClient`,配
`limits=httpx.Limits(max_keepalive_connections=..., max_connections=...)` 与合理 `keepalive_expiry`;
或直接把已实现的 `ConnectorPoolManager` 接到 LLM 路径。不要在每次 invoke/stream 里 new + close。

---

## Issue 2(P0·最易复现)

**标题**:`[Bug] Runner.run_agent(envs=...) / run_workflow(envs=...) 参数被忽略,不生效`
**标签**:bug, api

> 说明:本问题为纯 SDK 代码逻辑,与硬件/驱动无关,环境按模板附全。

### 现象
`Runner.run_agent(agent, inputs, envs={"WORKFLOW_EXECUTE_TIMEOUT": "600"})` 注入配置/超时**完全不生效**;
工作流执行超时仍按默认 60s(报 `100101 workflow execute timeout`),只能改进程级 OS 环境变量才生效。

### 源码定位
`openjiuwen/core/runner/runner.py`
- `run_agent`(L408-436):签名有 `envs: Optional[dict] = None`(L414),docstring 写着
  "Environment variables or configuration overrides"(L424),但**函数体从不引用 `envs`**
  ——`_prepare_agent(agent, inputs, session)` 与 `agent_instance.invoke(...)` 都不接收它。
- `run_workflow`(L359-378)、`run_agent_streaming`(L438+)同样声明 `envs`/`context` 却不使用。
- 实际超时只从 OS 环境变量/contextvar 读:`openjiuwen/core/session/config/base.py` `_load_env_configs`(L102-109,`os.environ.get(...)`)。

### 期望
`envs` 要么真正注入到 `WorkflowSession.config`(生效),要么从签名移除(别给误导性参数)。

### 建议修复
在 `run_agent/run_workflow` 里把 `envs` 传入会话构建、并入 `WorkflowSession` 的 env;
配置读取优先级建议统一为「调用参数 > 会话 env > OS 环境变量 > 默认」。

---

## Issue 3(P0·可观测性)

**标题**:`[Bug] 组件 LLM 调用失败(101003)默认吞掉真实异常原因,排障时看不到根因`
**标签**:bug, observability, error-handling

### 现象
LLM 调用失败时对外只拿到 `component llm_invoke call failed, reason: invoke llm failed`,
**看不到底层真实异常**(超时?连接重置?HTTP 状态码?),定位困难。

### 源码定位
`openjiuwen/core/workflow/components/llm/llm_comp.py` `LLMComponent.invoke`(L542-557):
默认 `UserConfig.is_sensitive()==True`(`openjiuwen/core/common/security/user_config.py` L26/L60-66,默认开)时,
`error_msg` 被硬编码成 `"invoke llm failed"`(L549),真实异常仅挂到 `cause=e`;非敏感分支才用 `str(e)`(L555)。
而 `openjiuwen/core/common/exception/errors.py` 的 `BaseError.__str__`(L84-85)与 `to_dict()`(L68-79)
**都不含 cause/__cause__** → 上层只打印 `str(err)` 就完全丢根因。
底层 `openai_model_client.py` 的 invoke 异常也只用 `str(e)`(L286,不带 `type(e)`;空 str 的异常连类型都丢,stream 路径 L427 已修)。

### 期望
失败时对外消息能看到真实异常类型/原因,不必设 `IS_SENSITIVE=false` 或手动遍历 `__cause__`。

### 建议修复
- `BaseError.__str__`/`to_dict()` 默认带上 `__cause__` 摘要(`type(e).__name__: str(e)`);
- 脱敏应只脱**业务内容**,不应脱**失败原因/异常类型**;
- `invoke` 的异常包装对齐 `stream`(带异常类型)。

---

## Issue 4(P0·并发)

**标题**:`[Bug] Runner 为进程级单例、绑单一事件循环,无法多线程并发执行(2 并发即挂死)`
**标签**:bug, concurrency

### 现象
单线程正常;**2 并发**即出现工作流跑不到出口、结果 sink 为空、进而挂死。

### 源码定位
`openjiuwen/core/runner/runner.py`:`GLOBAL_RUNNER = _RunnerImpl(...)`(L683)为**模块级单例**;
`_RunnerImpl.__init__`(L78-101)把 `ResourceMgr()`(L87)、`LocalMessageQueue()`(L88)、根任务组
`_root_task_group`(L97)挂在唯一实例上,根任务组由单个 owner 协程/单一 loop 持有(L137-150)。
对外 `Runner` 全是 `@classmethod` 转发到 `GLOBAL_RUNNER`(L820+),**无法干净地实例化第二个隔离 Runner**,
也无线程安全说明。多线程各自 loop 并发调用时共享 task-group/queue 打架。

### 期望
支持并发执行(生产轮询需多并发),或明确并发边界。

### 建议修复
提供**可实例化、相互隔离的 Runner**(各自绑独立 loop/队列/资源),或提供官方线程安全的并发执行入口;
至少在文档明确「单例 + 单 loop」的并发限制,避免误用。

---

## Issue 5(P1·表达式)

**标题**:`[Bug] BranchRouter 条件表达式对 true/false 做无词边界全局替换,误伤含 true/false 的标识符`
**标签**:bug, workflow

> 说明:本问题为纯 SDK 代码逻辑,与硬件/驱动无关,环境按模板附全。

### 现象
在分支条件里引用形如 `${is_true_flag}` 的变量/字段时求值失败或恒假。

### 源码定位
`openjiuwen/core/workflow/components/condition/expression.py`:`RULES`(L15-24)用
`re.compile(r"true")→"True"`、`r"false"→"False"`(L18-19,**无 `\b` 词边界**)做全局子串替换。
`convert_condition`(L129-159)虽对引号字符串做了保护(L136/149),但**未加引号的标识符仍被子串替换**
——`${is_true_flag}` 被改成 `${is_True_flag}`,随后变量名对不上、取值失败。

### 期望
关键字替换不应误伤标识符。

### 建议修复
表达式改用**词法/AST** 解析,或至少给 `true/false/and/or` 等关键字替换加 `\b` 词边界、只在词法记号层替换,
不要对整串做文本子串替换。

---

## 备选(要提再展开成完整草稿)
- **P1**:为思维链(reasoning/`enable_thinking`)模型提供**一等开关**——qwen3 默认开思维链会输出非 JSON、触发
  `101004 Json parse error`;现在只能靠 `ModelRequestConfig(extra_body={"chat_template_kwargs":{"enable_thinking":False}})` 手动透传关闭。
- **P2**:一组一致性/契约问题——`init_model()` 默认 `verify_ssl=False` 与 `ModelClientConfig` 默认 `True` 不一致;
  `Model.__init__` 猴补丁改写 client 方法;错误码 `codes.py` 串号(100010/101150 重复)。可合并成一个「代码质量」issue。

---

> 技术底稿:`docs/openjiuwen-踩坑总结.md`;改进汇报:`docs/openjiuwen-使用情况汇报.md`。
