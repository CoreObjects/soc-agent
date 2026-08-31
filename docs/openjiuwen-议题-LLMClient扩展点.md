# 议题申报:为 openJiuwen 增加一等的 LLM 客户端扩展点 `LLMClient`

> 目标仓:`openJiuwen/agent-core`(https://gitcode.com/openJiuwen/agent-core)
> 类型:能力增强(新增扩展点,**不改变任何现有默认行为**)
> 申报方:SOC 智能研判项目组 ｜ 依据版本:openjiuwen **0.1.16**(已安装源码,含 `文件:行号`)
> 底稿:`docs/openjiuwen-使用情况汇报.md`(源码级)、`docs/openjiuwen-踩坑总结.md`(开发期逐坑)

---

## 一、一句话

**把"LLM 客户端"从框架内部实现细节,提升为一个有明确契约的公开扩展点** ——
框架负责编排、会话、结构化输出与错误码,**具体怎么把请求打到推理后端,允许接入方自带实现**;
框架内置的 OpenAI/Anthropic 客户端成为该契约的两个参考实现,默认路径一行不改。

---

## 二、动机

### 2.1 结构性理由(**即使内置客户端的已知缺陷全部修复,这个扩展点依然必要**)

openJiuwen 今天只有 `OpenAIModelClient` / `AnthropicModelClient` 两个内置客户端
(`core/foundation/llm/model_clients/`),**接第三种推理后端就必须改框架源码**。
而昇腾生态的现实是:

1. **推理后端不止一种协议**。同为昇腾算力,vLLM(OpenAI 兼容)、MindIE Service、Triton、
   各家自研推理网关的请求/响应格式并不一致;OpenAI 兼容只是其中之一。
2. **企业接入面天生"每家不一样"**:国密/内部 token 服务鉴权、mTLS、正反向代理、
   多租配额与速率闸、调用审计留痕。这些**不该进框架**,但必须**能接进框架**。
3. **可测试性**。今天要给一条工作流写确定性单测,绕不开真实模型或对内部类打补丁;
   有了注入点,塞一个假客户端即可,**工作流逻辑的测试不再依赖 NPU 资源**。
4. **风险隔离**。内置客户端一旦有缺陷,接入方目前**没有退路**——只能等框架版本。
   扩展点让"框架能力"与"某一个客户端实现的成熟度"解耦。
5. **框架自身受益**。客户端收敛成窄契约后,内置实现可以独立演进(接连接池、加熔断),
   而不必担心破坏接入方——因为接入方面对的是契约,不是实现。

### 2.2 直接触发:一次对照实验

我们把 SOC 浅层研判(`Start → LLMComponent → BranchRouter → {深度|终局} → End`)
放到 openJiuwen 上跑生产负载,得到一组**变量单一**的对照数据:

| 对照项 | 客户端 | 端点/模型 | 调用量 | 结果 |
|---|---|---|---|---|
| 浅层 | openJiuwen 内置 `LLMComponent` 客户端 | 同一昇腾 qwen(vLLM) | ~6.5 万次 | **约 50% 失败**(`101003`) |
| 深度 | 自研 requests 直连客户端 | **同一端点、同一模型** | 同期 | **0 失败** |

日志前半段与后半段的 `101003` 计数几乎相等(350693 ≈ 352187),说明**从第一次调用起就是 ~50%**,
不是随时间恶化的连接泄漏。**唯一变量是客户端实现**。

我们已按社区规范就该缺陷单独提交 issue(疑似根因:
`openai_model_client.py:_create_async_openai_client` L110–142 每次 `invoke`/`stream` 新建
`httpx.AsyncClient` 且 `finally` 立即 `close`,未传 `limits`/keepalive;
而框架自带的 `ConnectorPoolManager`(`common/clients/connector_pool.py` L177)**并未接到 LLM 路径**)。

**本议题与那个 bug 是两件事**:那是"内置实现要修",这是"框架该不该有扩展点"。
我们当时被堵住整整一个迭代,真正的原因不是那个缺陷本身,而是**没有任何合法的绕行方式**。

### 2.3 现状确认(源码依据)

- 对外**没有**公开的客户端契约或 Protocol;唯一近似"接口"的是抽象基类 `BaseModelClient`。
- 该基类**面过宽**:`generate_image / speech / video` 在 `OpenAIModelClient` 里是
  静默 `pass` 返回 `None`(L455–497),自定义实现无从判断哪些必须实现。
- **构造签名有陷阱**:`Model(model_client_config, model_config)`(`model.py` L41–45)与
  `BaseModelClient(model_config, model_client_config)`(base L71)**参数顺序相反**。
- `Model.__init__`(L70–87)对实例做**猴补丁** `self._client.invoke = fn` ——
  实现方无法预期自己的方法会不会被替换掉。

⇒ 结论:今天"自带客户端"这条路**技术上能硬走,契约上不成立**。

---

## 三、方案

### 3.0 设计原则

| 原则 | 含义 |
|---|---|
| **只加不改** | 不传 `client` 时,行为与 0.1.16 **逐字相同**;现有用户零改动。 |
| **窄契约** | 只暴露框架**真正调用**的那几个方法,不把 `BaseModelClient` 的全部面积公开。 |
| **结构化子类型** | 用 `typing.Protocol`,实现方**无需 import 框架基类、无需继承**,降低耦合与版本压力。 |
| **能力显式声明** | 客户端自报支持什么,框架在**构建期**校验,不把不匹配拖到运行期变成脏 JSON。 |
| **契约测试随行** | 框架提供一套可执行的契约测试;任何实现跑一遍即知合不合格。 |

### 3.1 契约定义

落点建议 `openjiuwen/core/foundation/llm/client.py`,对外从 `openjiuwen.llm` 导出。

```python
# ---- 请求(归一化;厂商方言由各实现自行翻译)---------------------------
@dataclass(frozen=True)
class Timeout:
    connect: float | None = None
    read:    float | None = None      # ★ 非流式也应有 read 概念
    write:   float | None = None
    total:   float | None = None

@dataclass(frozen=True)
class LLMRequest:
    messages: Sequence[Message]
    model: str
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    stop: Sequence[str] | None = None
    tools: Sequence[ToolSpec] | None = None
    tool_choice: str | None = None
    response_format: ResponseFormat | None = None   # text | json_object | json_schema
    enable_thinking: bool | None = None             # ★思维链一等开关,见 3.3
    timeout: Timeout | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)   # 逃生舱:厂商私有参数

# ---- 响应 -------------------------------------------------------------
@dataclass(frozen=True)
class LLMResponse:
    content: str | None
    tool_calls: Sequence[ToolCall] = ()
    finish_reason: str | None = None
    usage: Usage | None = None
    model: str | None = None
    raw: Any = None                  # 原始响应,排障用(受脱敏策略控制)

# ---- 契约 -------------------------------------------------------------
@runtime_checkable
class LLMClient(Protocol):
    @property
    def capabilities(self) -> ClientCapabilities: ...

    async def invoke(self, request: LLMRequest) -> LLMResponse: ...

    def stream(self, request: LLMRequest) -> AsyncIterator[LLMChunk]: ...

    async def aclose(self) -> None: ...
```

**只有这四项**。`generate_image / speech / video` 不进契约:需要时另立 `ImageClient` 等
平行契约,而不是让每个文本客户端去实现三个空方法。

`extra` 这个逃生舱是刻意留的:没有它,每一个厂商私有参数都会变成一个框架 PR。

### 3.2 并发与事件循环契约(**写进文档,不只写进代码**)

契约必须明文规定下面四条,否则每个新实现都会重犯同一类错误:

1. 同一个 `LLMClient` 实例**必须支持在同一事件循环内被并发 `invoke`**;
2. 实现**不得在构造期绑定事件循环**(不得在 `__init__` 里 `get_event_loop()`),
   要延迟到首次调用并用 `get_running_loop()`;
3. 实现**应当复用底层连接**(连接池 + keepalive),不得每次调用新建并销毁;
4. `aclose()` 幂等。

> 第 2、3 条正是框架内部现存问题的镜像(`ref_counted.py` L40 在构造期就
> `get_event_loop().time()`;`openai_model_client.py` 每次调用新建并销毁 client)。
> 把它们写成对外契约,内置实现也就同时有了整改标尺。

### 3.3 能力声明 + 构建期校验

```python
@dataclass(frozen=True)
class ClientCapabilities:
    stream: bool = True
    tool_call: bool = False
    json_schema: bool = False        # 原生结构化输出
    reasoning_toggle: bool = False   # 能否关闭思维链
    batch: bool = False
```

`LLMComponent` 在**构建期**(而不是首次调用时)校验:

- 组件配了结构化输出,而客户端 `tool_call=False and json_schema=False`
  → **构建期报错**,明确告知"该客户端不支持结构化输出";
- 请求要求 `enable_thinking=False`,而客户端 `reasoning_toggle=False` → **构建期告警**。

> 这一条直接消灭一类现存的运行期谜题:qwen3 默认开思维链会吐 `<think>…`、
> 触发 `101004 Json parse error`,而 `ModelRequestConfig` 默认不含 `enable_thinking`,
> 目前只能靠 `extra_body={"chat_template_kwargs": {...}}` 手工透传。
> 把它提升为 `LLMRequest.enable_thinking` 归一字段后,**由各客户端翻译成自己后端的方言**
> (vLLM/qwen 走 `chat_template_kwargs`,别的后端各按各的)——这才是它该待的层。

### 3.4 注入点(三级,由具体到声明式)

```python
# ① 实例注入 —— 最直接,适合程序化构建
model = init_model(..., client=MyAscendClient(...))

# ② 组件级 —— 一条工作流里不同组件可用不同后端
LLMComponent(..., client=MyAscendClient(...))

# ③ 注册表 + Card 引用 —— ★声明式路径必须能用,否则扩展点只覆盖一半场景
register_llm_client("ascend-mindie", lambda cfg: MyAscendClient(**cfg))
```

```yaml
# WorkflowCard 里
llm:
  client: ascend-mindie          # 注册名
  client_config: { endpoint: "...", pool_size: 32 }
```

> 第 ③ 级不是锦上添花:框架正在往 `AgentCard` / `WorkflowCard` 声明式方向走,
> 只做 ①② 等于扩展点在主推路径上失效。

### 3.5 生命周期与所有权

| 客户端来源 | `owned` | 谁负责 `aclose()` |
|---|---|---|
| 框架按配置/注册表构造 | `True` | **框架**,在会话/Runner 关闭时 |
| 用户注入现成实例 | `False` | **用户**;框架**永不**关闭它 |

> 这条写死是有针对性的:内置实现目前**每次调用结束就 close**
> (`openai_model_client.py` L288–290 / L451–453)。若把同样的习惯套到注入实例上,
> 用户跨会话共享的连接池会被框架关掉,而且症状会很难查。

### 3.6 错误契约

```python
class LLMClientError(Exception):
    retryable: bool                 # 驱动组件级退避重试
    status_code: int | None
    vendor_code: str | None
```

- 实现抛 `LLMClientError`,框架映射到 `101003`,但 **`to_dict()` / `__str__` 必须带
  `__cause__` 摘要**(`type(e).__name__: str(e)`);
- **脱敏只脱业务内容,不脱失败原因与异常类型**。

> 对应我们排障时最痛的一点:`101003 ... reason: invoke llm failed` 是硬编码的笼统串
> (`llm_comp.py` L549,默认 `is_sensitive=True`),真实异常只挂在 `cause` 上,
> 而 `BaseError.__str__`(`errors.py` L84–85)与 `to_dict()`(L68–79)都不含 cause
> ⇒ 上层只打印 `str(err)` 就**完全丢根因**。我们是靠读框架源码 + 设 `IS_SENSITIVE=false`
> 才定位到的,这个成本不该由每个接入方再付一遍。
> `retryable` 同时为"组件级退避/熔断"(目前完全没有)提供了判据。

### 3.7 与现有类型的关系(尽量不动存量)

| 现有 | 处置 |
|---|---|
| `BaseModelClient` | **保留**。声明它 implements `LLMClient`(结构上已基本满足),内置两个客户端不动。 |
| `Model` | 增加可选 `client=` 形参;不传时构造路径**逐字不变**。 |
| `LLMComponent` | 增加可选 `client=`;内部改为面向 `LLMClient` 契约调用。 |
| `ModelClientConfig` | 不动。仅供内置实现使用;自带客户端用自己的配置对象。 |

**命名冲突提醒**:仓内已有 `core/common/clients/llm_client.py`,但其内容是
`HttpXConnectorPool` / `HttpXConnectorPoolConfig` —— 那是一个 **HTTP 连接池**,并不是 LLM 客户端。
建议顺势更名为 `common/clients/httpx_pool.py`,把 `LLMClient` 这个名字留给对外契约;
若不便移动,本契约可命名为 `ChatClient`,方案其余部分不受影响。

### 3.8 参考实现(我们愿意贡献)

我们有一个在昇腾 qwen 上长期生产运行、**实测 0 失败**的客户端实现,可按本契约整理后回贡:
连接池 + keepalive、connect/read 分级超时、可配置退避、思维链一等开关、
失败原因完整外露、无事件循环绑定。可作为 `LLMClient` 的第三个参考实现或独立示例工程。

---

## 四、兼容性

- **默认行为零改动**:不传 `client` 时走原路径,现有用例逐字通过;
- 新增的都是**可选形参 + 新模块**,无签名破坏;
- 与 `v1.0.0` 弃用潮不冲突:本契约是新面,不依赖任何已标弃用的类
  (`AgentConfig` / `WorkflowAgentConfig` / `WorkflowSchema` / `BaseAgent(legacy)` 等);
- 契约用 `Protocol`,接入方**不 import 框架基类**,框架内部重构不波及实现方。

---

## 五、验收标准(怎么证明它成立)

| # | 验收项 | 判据 |
|---|---|---|
| 1 | **默认路径零回归** | 不注入客户端时,现有测试套件全绿**且行为逐字相同** |
| 2 | **契约测试可执行** | 框架提供 `assert_llm_client_contract(client)`:覆盖 invoke/stream/工具调用/超时/取消/并发 32/`aclose` 幂等;**内置客户端自己必须先过** |
| 3 | **能力校验在构建期** | 故障注入:给一个 `tool_call=False` 的客户端配结构化输出 → **构建期**报错,不得跑到运行期吐脏 JSON |
| 4 | **所有权正确** | 注入的实例在会话结束后**仍可用**(框架没关它);框架自建的在关闭后 `aclose` 确已被调用 |
| 5 | **根因可见** | 客户端抛带 cause 的异常 → 上层 `str(err)` / `to_dict()` **能看到异常类型与原因** |
| 6 | **可测试性兑现** | 用假客户端跑一条含分支的工作流单测,**不起任何模型**、结果确定 |
| 7 | **对照压测** | 同端点同模型,内置 vs 注入实现各 ≥5 万次:报成功率、p50/p95、`ss -s` 连接数曲线 |

> 第 7 项我们可以直接在昇腾环境上出数据 —— 这正是本议题的证据来源。

---

## 六、分期

| 阶段 | 内容 | 说明 |
|---|---|---|
| **一** | 契约 + 三级注入 + 生命周期 + 契约测试套件 | **不动内置客户端**,纯增量,风险最低 |
| **二** | 内置 OpenAI 客户端声明实现该契约,并接入已有 `ConnectorPoolManager` | 与已提交的连接池 issue 合流 |
| **三** | 注册表接入 Card 声明式路径;参考实现与示例工程回贡 | |

---

## 七、明确不做

- **不替换**内置 OpenAI/Anthropic 客户端,也不改其默认配置;
- **不引入新的运行时依赖**(契约仅用标准库 `typing` / `dataclasses`);
- **不做模型路由/选型** —— 框架已有 `IntelliRouter`,与本议题正交;
- **不做多模态** —— 图像/语音/视频另立平行契约,不塞进 `LLMClient`;
- **不做**跨进程/分布式客户端池 —— 超出扩展点范围。

---

## 附:证据环境

```
- 框架:openjiuwen 0.1.16(openJiuwen/agent-core)
- Python 3.11.6 · openEuler 24.09 · 内核 6.6.0-45.0.0.54.oe2409.aarch64
- 架构:aarch64 · HiSilicon Kunpeng-920,256 核 · 内存 2.0 TiB
- 昇腾驱动:25.5.2(ascendhal 7.35.23)——LLM 后端所在;openjiuwen 仅经 HTTP 连它
- 关键依赖:openai 2.47.0 · httpx 0.28.1 · httpcore 1.0.9 · anyio 4.14.2 · pydantic 2.13.4
- LLM 后端:昇腾 qwen(vLLM,OpenAI 兼容端点),qwen3.5-9b / qwen3.5-27b
- 运行方式:后台轮询,单线程串行、持续高频调用(约 6.5 万次)
```

**源码索引**(以 0.1.16 已安装版为准):
`model_clients/openai_model_client.py` L110–142 / L222 / L288–290 / L455–497 ·
`common/clients/connector_pool.py` L177 · `common/clients/llm_client.py` L18 / L52 ·
`workflow/components/llm/llm_comp.py` L542–557 · `common/exception/errors.py` L68–85 ·
`common/exception/codes.py` L114 · `foundation/llm/model.py` L41–45 / L70–87 ·
`foundation/llm/schema/config.py` L38–68 / L121–128 · `common/clients/ref_counted.py` L40
