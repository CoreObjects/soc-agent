# openJiuwen 使用情况汇报 —— 已有能力与改进建议（源码级）

> 面向：项目汇报 · 框架改进推动
> 定位：openJiuwen 是公司选定、**须持续使用**的国产 Agent 框架。本文**不讨论要不要用**，而是在继续使用的前提下，梳理其**缺失的能力**与**做得不好用的细节**，并给出**可落地的改进建议**，以推动其生产化。已有能力仅作简述。
> 依据：以已安装并实际运行的版本 **openJiuwen 0.1.16** 源码为准（`site-packages/openjiuwen/`），所有结论均标注 `文件:行号`，便于核对与反馈研发。
> 日期：2026-07-30 ｜ LLM 后端 = 昇腾 qwen（vLLM，OpenAI 兼容端点）

---

## 一、结论速览

我们用 openJiuwen 搭了 SOC 研判的**浅层分诊**一层（一次 LLM 判定外套一个工作流）。工作流编排、条件分叉、结构化输出**都能用、单条 demo 验通、昇腾亲和成立**。但在**并发 + 持续负载**的生产态下，暴露出若干**结构性能力缺失**与**细节易踩坑**，其中三项直接卡住生产化：

| 优先级 | 改进项 | 一句话 |
|---|---|---|
| **P0** | LLM 客户端无连接池/keepalive | 每次调用新建并销毁 httpx 连接；框架自带连接池却未接入 LLM 路径。高并发下疑为 ~50% 调用失败之源。 |
| **P0** | Runner 进程单例、不能并发 | `GLOBAL_RUNNER` 模块级单例、绑单一事件循环，2 并发即挂死。 |
| **P0** | 失败根因不可见 | 错误默认脱敏成 "invoke llm failed"，真实异常只进 `__cause__` 且不外露，排障看不到原因。 |
| P1 | 无组件级重试/退避、超时不细分 | 仅单一 60s 总超时，无 connect/read 区分、无退避熔断。 |
| P1 | 配置注入不统一 | `run_agent(envs=)` 声明却被忽略；超时只能从 OS 环境变量读。 |
| P1 | 默认值不合理 | timeout=60、retries=3、temperature=0.95、思维链默认不关、日志默认脱敏。 |
| P1 | 条件表达式脆弱 | `true→True` 等无词边界全局正则替换，误伤标识符。 |
| P1 | 事件循环耦合 | 同步上下文用已废弃 `get_event_loop`，会话/资源绑当前 loop，换线程即死锁。 |
| P2 | 缺标准可观测性/批量/限流 | 无 OTel/Prometheus 出口、无 batch 接口、无内建并发闸。 |
| P2 | API 一致性与弃用 | 猴补丁、参数顺序相反、`verify_ssl` 默认不一致、错误码串号；大量类将于 v1.0.0 移除。 |

---

## 二、使用范围与已有能力（简述）

**使用范围**：仅用它搭浅层分诊 `Start → LLMComponent（判 needs_deep/verdict）→ BranchRouter → { 升级深度 | 终局 } → End`。深度研判、经验层、处置执行不经过它。

**已有能力（能用，简述，不展开）**：

- **工作流编排**：`Start / LLMComponent / BranchRouter / End` 等组件可搭可跑，支持条件分叉与子工作流。
- **结构化输出**：schema 约束 + tool-call，稳定产出 JSON。
- **多模型客户端**：内置 OpenAI / Anthropic 客户端（`core/foundation/llm/model_clients/`），OpenAI 兼容端点即可接昇腾 qwen。
- **会话与追踪**：`WorkflowSession` + 内部 `Tracer`（`core/session/tracer/`）。
- **昇腾算力亲和**：LLM 运行在昇腾 qwen 上（这一点与客户端实现无关，始终成立）。
- **自演进（`agent_evolving`）/ 模型级路由（`IntelliRouter`）**：框架具备，但我们未使用，本文不评价。

> 这些能力对"编排一条 agent 流程"是够用的；问题集中在**下面的生产化短板**。

---

## 三、需要改进的地方（重心）

> 每条：**现象 → 源码依据 → 影响 → 改进建议**。

### A. 能力缺失（框架该有、但没有或没接上）

#### A1〔P0〕LLM 客户端无连接池 / keepalive，每次调用新建并销毁连接——而框架自带连接池却未接入

- **现象**：全量后台运行、持续高频调用时，浅层 LLM 约 **50% 报 101003 失败**；同一昇腾端点换直连客户端则 0 失败。
- **源码依据**：
  - 实际 LLM 调用走 `core/foundation/llm/model_clients/openai_model_client.py` 的 `_create_async_openai_client`（**L110–142**）：**每次 `invoke`（L222）/`stream`（L378）都 `httpx.AsyncClient(...)` 新建一个 client**（L122），且**未传 `limits`、未设 `keepalive`、未开 `http2`**；调用结束 `finally` 里立即 `await async_client.close()`（**L288–290 / L451–453**）——**连接不复用，每次请求重新 TCP+TLS 握手**。
  - 讽刺的是框架**自带连接池却没接到 LLM 路径**：`core/common/clients/llm_client.py` 的 `HttpXConnectorPool`（**L52**）+ `HttpXConnectorPoolConfig`（**L18**，`max_keepalive_connections=20` L26）、`core/common/clients/connector_pool.py` 的 `ConnectorPoolManager`（**L177**，`limit=100 / limit_per_host=30 / keepalive_timeout=60 / ttl=3600`）。grep 确认 `model_clients/` 下只有 openai/anthropic 直接 `httpx.AsyncClient`，**从未引用这套连接池**。
- **影响**：高并发下每次调用一套新建+销毁的 socket/TLS，句柄/临时端口抖动剧烈，是"持续负载 ~50% 失败"的**最可疑根因**（连接风暴 / 端口耗尽 / 握手失败）。
- **改进建议**：把 LLM 客户端接到已实现的连接池上——`AsyncOpenAI(http_client=...)` 传一个**复用的 `httpx.AsyncClient`**，配 `limits=httpx.Limits(max_keepalive_connections=…, max_connections=…)` 与合理 `keepalive_expiry`，并按 model_client 缓存/复用而非每次新建销毁。框架已有 `ConnectorPoolManager` 能力，接上即可。

#### A2〔P0〕Runner 进程单例，无法多线程并发执行

- **现象**：2 并发即"跑不到出口、结果 sink 空、挂死"；单线程完全正常。
- **源码依据**：`core/runner/runner.py`：`GLOBAL_RUNNER = _RunnerImpl(config=DEFAULT_RUNNER_CONFIG)`（**L683**）是**模块级单例**；`_RunnerImpl.__init__`（**L78–101**）把 `ResourceMgr()`（L87）、`LocalMessageQueue()`（L88）、根任务组 `_root_task_group`（L97）都挂在这个唯一实例上，且根任务组由**单个 owner 协程 / 单一 loop** 持有（`_root_task_group_owner_loop` L137–150）。对外 `Runner` 全是 `@classmethod` 转发到 `GLOBAL_RUNNER`（`run_agent` L820–846），**无法干净地实例化第二个隔离 Runner**，也无任何线程安全说明。
- **影响**：生产轮询需要多并发消化积压，这条路被堵死；只能收敛到"专用单线程串行"，与生产吞吐诉求相悖。
- **改进建议**：提供**可实例化、相互隔离的 Runner**（每个绑自己的 loop/队列/资源），或提供官方的线程安全并发执行入口；至少在文档中明确"单例 + 单 loop"的并发边界，避免误用。

#### A3〔P1〕无组件级重试/退避/熔断；非流式只有单一总超时，无 connect/read 细分

- **源码依据**：`LLMComponent.invoke`（`core/workflow/components/llm/llm_comp.py` **L543**）直接 `await self._llm.invoke(messages=…)`，**不传 timeout、不做组件级重试**；唯一重试是把 `max_retries`（默认 3）交给 openai SDK（`openai_model_client.py` L141）。`ModelClientConfig.timeout` 是**单一浮点**（`config.py` L49），透传成 `httpx.Timeout(all=…)`，**无 connect/read/write 区分**（流式另有 `stream_first_chunk_timeout/stream_idle_timeout`，非流式没有）。
- **影响**：慢模型或抖动时，要么被单一总超时一刀切，要么无退避地打满后端；缺熔断，故障会放大。
- **改进建议**：组件层支持可配置的**退避重试 + 熔断**；超时细分为 connect/read（非流式也应有 read/idle 概念）。

#### A4〔P0〕失败根因不可见：错误模型不带 cause，101003 默认吞根因

- **源码依据**：101003 定义在 `core/common/exception/codes.py` **L114**（`"component llm_invoke call failed, reason: {error_msg}"`）；抛出在 `llm_comp.py` `invoke`（**L542–557**）：默认 `UserConfig.is_sensitive()==True`（见 B5）时 `error_msg="invoke llm failed"`（**L549**，硬编码笼统串），真实异常只挂 `cause=e`；非敏感分支才 `error_msg=str(e)`（L555）。而 `core/common/exception/errors.py` 的 `BaseError.__str__`（**L84–85**）与 `to_dict()`（**L68–79**）**都不含 `cause/__cause__`** → 上层若只打印 `str(err)` 就**完全看不到根因**。更糟的是底层 `openai_model_client.py` 的 `invoke` 异常只用 `str(e)`（**L286**，不带 `type(e)`），空 `str()` 的异常（如 `RemoteProtocolError`）**连异常类型都丢**（stream 路径已修，L427）。
- **影响**：这正是"~50% 报 101003 却看不到原因"的直接成因，排障极难。
- **改进建议**：错误对外消息与 `to_dict()` **默认带 `__cause__` 摘要**（`type(e).__name__: str(e)`）；`invoke` 的异常包装对齐 `stream` 的写法（带类型）；敏感脱敏只脱**内容**、不应脱**失败原因/异常类型**。

#### A5〔P2〕缺标准可观测性、批量接口与内建限流

- **源码依据**：仅内部 `Tracer`（`core/session/tracer/`）+ 回调事件，**无 OpenTelemetry / Prometheus 标准出口**；LLM 只有 `invoke/stream`，**无 batch 接口、无内建限流/并发闸**（`llm_comp.py`）。
- **改进建议**：提供标准 metrics/tracing（OTel）、批量推理接口、以及可配置的并发/速率闸。

### B. 细节难用（易踩坑、别扭）

#### B1〔P1〕`envs` 参数声明却被忽略；超时只能从 OS 环境变量读——配置注入不统一

- **源码依据**：`WORKFLOW_EXECUTE_TIMEOUT` 默认 60（`core/session/config/base.py` **L160**），构造 session 时只从**OS 环境变量 / contextvar** 读（`_load_env_configs` **L102–109**，`os.environ.get(...)` L106），读取点在 `core/workflow/workflow.py` L376/L503。而 `core/runner/runner.py` 的 `run_agent`/`run_workflow`（L408–436 / L359–378）**签名里有 `envs`/`context` 形参，函数体从不使用**——`envs` 被直接丢弃。
- **影响**：用户以为能 `run_agent(envs={...})` 注入超时/配置，实际不生效，只能改进程级 OS 环境变量（污染全局、多实例互相干扰）。
- **改进建议**：让 `run_agent(envs=)` 真正生效并注入到 `WorkflowSession.config`；配置读取优先级统一为「调用参数 > 会话 env > OS 环境变量 > 默认」。

#### B2〔P1〕默认值不合理

- **源码依据**：`config.py`：`timeout=60.0`（L49）、`max_retries=3`（L61）、`temperature=0.95`（L124）、`top_p=0.1`（L125）；`ModelRequestConfig` 默认**不含 `enable_thinking`** → **框架默认不关思维链**（qwen3 开思维链会吐 `<think>…` 导致 `json.loads` 崩，需自己透传 `extra_body.chat_template_kwargs.enable_thinking=False`，靠 `base_model_client.py` `_build_request_params` L377–386 的 `model_dump(exclude=…)` 透传）；`is_sensitive` 默认 True（见 B5）。
- **影响**：对慢的大模型，60s×(1+3) 的组合易造成"约 4 分钟才失败"；思维链默认不关，是很多接入方第一脚就踩的坑。
- **改进建议**：超时/重试默认对大模型更友好或强制显式配置；为 qwen3 这类**思维链模型提供一等开关**（而非埋在 `extra_body`）；文档明确各默认值。

#### B3〔P1〕条件表达式 `true→True` 无词边界全局正则替换，误伤标识符

- **源码依据**：`core/workflow/components/condition/expression.py` 的 `RULES`（**L15–24**）用 `re.compile(r"true")→"True"`、`r"false"→"False"`（**L18–19**，**无 `\b` 词边界**）做全局子串替换；`convert_condition`（L129–159）虽对引号字符串做了保护（L136/149），但**未加引号的标识符仍被子串替换**——例如字段名 `${is_true_flag}` 会被改成 `${is_True_flag}`，随后变量名对不上取值失败。
- **改进建议**：表达式改用**词法/AST** 解析，或至少给关键字加 `\b` 词边界；`&&/||/and/or/true/false` 只在**词法记号**层替换，别做文本子串替换。

#### B4〔P1〕事件循环耦合：同步上下文用已废弃 `get_event_loop`，会话/资源绑当前 loop

- **源码依据**：`core/workflow/workflow.py` `_install_asyncio_exception_handler`（**L766–767** `asyncio.get_event_loop()`）；`core/common/clients/ref_counted.py` **L40**（资源池 `__init__` 即 `get_event_loop().time()`）；`tracer.py` L191 `run_until_complete`。`_create_workflow_session`（workflow.py **L696–716**）把 `ActorManager`/`StreamWriter`/消息队列**绑到当前运行 loop**（L707–711）；再叠加 Runner 单例根任务组绑第一次 start 的 loop。
- **影响**：一旦换线程/换 loop（多并发、多 uvicorn worker），这些绑定与 Runner 单例不在同一 loop → 死锁/挂死（与 A2 同源）。且 `get_event_loop` 在新版 Python 已废弃。
- **改进建议**：框架内部统一用 `asyncio.get_running_loop()` 并在明确入口管理 loop 生命周期；资源/会话绑定与执行 loop 解耦，支持多 loop/多线程。

#### B5〔P1〕日志默认脱敏，看不到 prompt / 响应 / 真实报错

- **源码依据**：`core/common/security/user_config.py`：`is_sensitive` **默认 True**（**L26**；`is_sensitive()` L60–66，需显式 `IS_SENSITIVE=false` 才关）。默认下 `base_model_client.py` `_build_request_params`（**L390–418**）**不记 messages/tools**（只记模型名/温度等元信息）；`llm_comp.py` 失败原因也被替换成笼统串（见 A4）。
- **影响**：生产排错"看不到真实响应/prompt/失败原因"，定位效率极低。
- **改进建议**：脱敏应**分级**（只脱业务内容、保留异常类型与失败原因）；提供"调试模式"一键放开且可脱指定字段；默认值与文档需醒目提示。

#### B6〔P2〕API 一致性与契约问题

- **源码依据**：`core/foundation/llm/model.py` `Model.__init__`（**L70–87**）对实例做**猴补丁** `self._client.invoke = fn`；`Model(model_client_config, model_config)`（L41–45）与 `BaseModelClient(model_config, model_client_config)`（base L71）**参数顺序相反**，极易传反；`init_model()`（model.py **L427**）默认 `verify_ssl=False` 而 `ModelClientConfig` 默认 `True`（config.py L62）**安全默认不一致**；`OpenAIModelClient` 的 `generate_image/speech/video` 抽象方法**静默 `pass` 返回 None**（openai_model_client.py L455–497）而非报"不支持"；错误码 `codes.py` 有**串号/冲突**（如 L79 注释 101010 却赋 100010；L108 与 L154 都用 101150）。
- **改进建议**：去猴补丁、统一构造签名与安全默认、未实现能力显式抛"不支持"、错误码去重并加测试守卫。

#### B7〔P2〕大量弃用，迁移压力

- **源码依据**：`core/single_agent/legacy/__init__.py` 用 `_deprecated_class`（L19–47）把 `AgentConfig`（L102）、`DefaultResponse`（L118）、`WorkflowAgentConfig`（L122）、`WorkflowSchema`（L140）、`BaseAgent`（→`LegacyBaseAgent` L88）等**一整批标弃用、实例化即 `DeprecationWarning`，承诺 v1.0.0 移除**；`Session` 也在 `session.py` L94 单独弃用。
- **改进建议**：提供稳定的迁移指南与兼容期时间表，减少接入方跟版本的返工。

### C. 我们当前的临时规避（现状说明，非最终方案）

为在上述问题未修复前继续推进，我们做了以下**治标规避**（根因仍需框架侧改进）：

1. 浅层 LLM 调用**改直连昇腾 qwen 的自研 `QwenClient`**（绕开 `LLMComponent` 客户端）——规避 A1/A4；昇腾亲和不变。
2. openJiuwen 调用**收敛到单线程串行**——规避 A2。
3. 超时改用**进程级 OS 环境变量**设定——规避 B1。
4. 透传 `extra_body` **手动关思维链** + 温度 0.1——规避 B2。
5. 排障时设 `IS_SENSITIVE=false` 看根因——规避 B5。

> 这些规避说明问题**可绕**，但都指向框架侧应做的改进；一旦 A1/A2/A4 被修复，openJiuwen 作为昇腾原生编排框架的价值会明显提升。

---

## 四、改进建议清单（按优先级，可直接反馈研发）

| 优先级 | 建议 | 源码位置 |
|---|---|---|
| P0 | LLM 客户端接入连接池/keepalive、复用连接（勿每次新建销毁） | `model_clients/openai_model_client.py` L110–142/288；`clients/connector_pool.py` L177 |
| P0 | 提供可实例化、相互隔离的 Runner / 官方并发执行入口 | `runner/runner.py` L62/L683/L820 |
| P0 | 错误对外消息与 `to_dict()` 默认带 `__cause__`；脱敏不脱失败原因 | `llm_comp.py` L542–557；`exception/errors.py` L68–85 |
| P1 | 组件级退避重试 + 熔断；超时细分 connect/read | `llm_comp.py` L543；`schema/config.py` L49 |
| P1 | `run_agent(envs=)` 真正生效，配置优先级统一 | `runner/runner.py` L408–436；`session/config/base.py` L102–109 |
| P1 | 合理默认值 + 思维链一等开关 | `schema/config.py` L38–128 |
| P1 | 条件表达式改词法/AST，关键字加词边界 | `condition/expression.py` L15–24 |
| P1 | 内部统一 `get_running_loop`，资源/会话与执行 loop 解耦 | `workflow/workflow.py` L696–767；`clients/ref_counted.py` L40 |
| P1 | 日志脱敏分级 + 调试模式 | `security/user_config.py` L25–66；`base_model_client.py` L390–418 |
| P2 | 标准 metrics/tracing(OTel) + 批量接口 + 限流 | `session/tracer/`；`llm_comp.py` |
| P2 | 去猴补丁/统一签名/统一安全默认/未实现显式报错/错误码去重 | `foundation/llm/model.py` L41–87/L427；`exception/codes.py` |
| P2 | 稳定迁移指南与弃用时间表 | `single_agent/legacy/__init__.py` L88–147 |

---

## 附：源码走读依据（file:line 索引，均以 0.1.16 已安装版为准）

- **Runner 单例**：`core/runner/runner.py` L62(`_RunnerImpl`)/L78–101(init)/L683(`GLOBAL_RUNNER`)/L820–846(`run_agent`)。
- **LLM 客户端连接**：`core/foundation/llm/model_clients/openai_model_client.py` L110–142/L222/L288–290/L264–287(err, str(e)@L286)。
- **未接入的连接池**：`core/common/clients/llm_client.py` L18/L52；`core/common/clients/connector_pool.py` L177。
- **101003 与吞根因**：`core/workflow/components/llm/llm_comp.py` L542–557/L588–600；`core/common/exception/codes.py` L114；`core/common/exception/errors.py` L68–79/L84–85。
- **配置默认 + 透传**：`core/foundation/llm/schema/config.py` L38–68/L121–128；`core/foundation/llm/model_clients/base_model_client.py` L377–386。
- **执行超时 & envs 被弃**：`core/session/config/base.py` L102–109/L160；`core/workflow/workflow.py` L376/L503；`core/runner/runner.py` L359–378/L408–436。
- **条件表达式**：`core/workflow/components/condition/expression.py` L15–24/L129–159/L46–52。
- **事件循环耦合**：`core/workflow/workflow.py` L696–716/L748–767；`core/common/clients/ref_counted.py` L40；`core/session/tracer/tracer.py` L191。
- **日志脱敏**：`core/common/security/user_config.py` L25–27/L60–66；`base_model_client.py` L390–418。
- **弃用**：`core/single_agent/legacy/__init__.py` L19–47/L88–147；`core/session/session.py` L94–96。
- **其它 API 问题**：`core/foundation/llm/model.py` L41–45/L70–87/L427；`core/common/exception/codes.py` L79/L108/L154。

> 技术底稿（开发期逐坑记录）：`docs/openjiuwen-踩坑总结.md`。后续路线（范围 B/C、升级信号 v2、IntelliRouter）：`docs/backlog-cascade-roadmap.md`。
