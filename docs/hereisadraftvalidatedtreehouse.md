# 计划:soc-agent 研判+处置控制台(Web 前端 + 首个 API 层)

> 目标仓库 = **github.com/CoreObjects/soc-agent**(独立仓,已 clone 到 scratchpad 供勘查),
> **不是**本会话检出的靶场仓 `/home/user/repo`。按用户意愿:本轮**只设计、先改好设计,不落地实现**。
> 下文所有路径均相对 soc-agent 仓根。

## Context / 为什么

soc-agent 现纯 headless:研判/处置台账在 Neo4j(`Alert-[:CONCLUDED]->Verdict-[:LED_TO]->ResponsePlan-[:STEP]->Disposition-[:ON]->实体`,加 `Alert-[:HAS_FINDING]->Finding`),第二类经验在 openGauss。人只能靠 CLI(`respond_cli`)和 `scripts/ledger-stats.sh` 观察。poller 常驻消化存量、TP→`proposed`(待处置)挂起等人审。要给它做**第一个 HTTP/UI 层**:分析员用的研判+处置控制台——把台账溯源摊平、把"待处置→人审→执行/回退"搬进界面、展示"越用越省"的价值。

**产品级六面全做**,第一重心=研判作战台(队列+溯源+审批);首屏=待研判/待处置队列。**前端承接处置写路径**(approve/reject/execute/rollback + manual/auto 开关),但 **API 只做现有状态机/护栏/appliance 通道的 HTTP 薄封,绝不自建执行路径**。

**新增两面(本轮追加需求):**
- **⑤ 完整研判流程视图**:点开任一历史告警,把整条台账的**完整研判流程**展示出来——原始告警 → seed 图上下文 → 取证 findings(极性)→(命中经验则显示复用来源)→ verdict/path/method/置信度 → rationale + 证据/缺失证据 → 处置计划步骤+状态。**并非只摊平结论,而是全过程时间线**。
- **⑥ Copilot 助手页**:针对"之前研判过的某告警"做**聊天式深度分析**——以该告警的完整台账为上下文喂 LLM,多轮问答("为什么判 TP?""还缺哪些证据?""这个 IP 的历史?")。

## 勘查结论:可直接复用的真实契约(已逐一读源码核对)

**读(全部现成):**
- `soc_agent/graph/client.py` → `Neo4jGraph`:`recall_ledger(uid)`(摊平台账;summary/rationale/confidence 在 `CONCLUDED` 边上、dispositions 已滤 `__no_op__`)、`get_alert(uid)`(原始 Alert `a{.*}`)、`seed(alert)`(触发事件/主宾/次要实体)、`run_cypher(q,**p)`(只读事务)。
- `soc_agent/respond_cli.py` → `list_plans(graph, status)`(计划+有序步骤,内部用 `ledger.q_list_plans`+`q_plan_steps`)。
- `soc_agent/response/ledger.py` → 纯 Cypher builder:`q_list_plans` / `q_plan_steps` / `q_approve` / `q_reject` / `q_request_rollback` 等(返回 `(cypher, params)`,离线可测)。
- 经验库:`soc_agent/cli.py::_open_stores(cfg)` 返回 `(exp_store, case_store, payload_corpus)`,`exp_store.all()` → `list[Experience]`(字段:skill/kind/verdict/note/hit_count/origin_case_id/origin_verdict_id/status;`.to_dict()` 可序列化)。og 未配自动降级 InMemory。
- `scripts/ledger-stats.sh` 内那组 Cypher(进度/积压/毒告警、verdict×path、Disposition 状态、ResponsePlan 状态、TP 抽样)→ 直接搬进 stats 接口。
- **LLM 聊天面(Copilot 用)**:`soc_agent/llm/qwen.py::QwenClient.chat(messages)` → `LLMResponse.content`(OpenAI 兼容;传完整 messages 列表即多轮;`trust_env=False` 绕代理)。构造只需 `QwenClient(cfg.llm_api_base, cfg.llm_model, cfg.llm_api_key, cfg.llm_timeout)`,**无需整条 pipeline**。

**⚠ 关键勘查结论(影响流程视图设计):live 研判留痕 `InvestigationResult.trace`(逐条 cypher 查询/行数、喂大模型的 user prompt、recipe 取证步、护栏决策——见 `cli.render_trace`)**目前不落库**:`graph/client.write_result` 只写 verdict/dispositions/findings;`experience/cases.py::snapshot_case` 只存 findings+verdict 快照。故:
- 存量已研判的 10 万告警**没有 trace**,完整流程只能从台账**重建**(raw→seed→findings→verdict/rationale/证据→处置)。
- 要让**新研判**的告警可回看真·逐步流程,需**从此持久化 trace**(见下 B')。

**写(只 HTTP 薄封,不重写执行):**
- `soc_agent/respond_cli.py` → `approve(graph,pid,by,now)` / `reject(graph,pid,now,reason)` / `run_plan(graph,client,pid,now,lease)`(execute:CAS 领取→逐步 `client.execute`→回写 status+rollback_handle→计划终态)/ `rollback_plan(...)`(逆序回退)。
- `soc_agent/response/appliance_client.py` → `ApplianceClient(cfg.response_url, cfg.response_token)`(唯一出站控制面;`.enabled`、`.execute`、`.rollback`)。
- **护栏(NEVER-TOUCH:DC/CA 强制留待处置)在被封函数内层**:`cli.build` 的 `policy_from_graph(graph)`(composer 组装侧不产出 DC/CA 可执行处置)+ appliance 服务端双重把关。前端/API 都在护栏外层,拦不掉。
- `soc_agent/response/auto.py` → `STATUS_ZH` / `zh_status(status)`(proposed=待处置 / executed=已处置 全套中文标签);`auto_respond(graph, client, uid)`(auto 模式自动 approve/执行,复用上面的 approve/run_plan)。

**已存在但需改造的点:**
- `soc_agent/config.py`:`Config.response_mode` 字段已存在(默认 `manual`,读 `SOC_RESPONSE_MODE`)——但只在进程启动读一次,**不可运行时切**。
- `soc_agent/runtime/service.py::make_processor` 内 `if cfg.response_mode == "auto":` 是静态读——要改成读持久态。
- `soc_agent/runtime/poller.py` 的 `_BATCH_CYPHER` 印证 Alert 有 `arrival_ms` / `poller_skip`(队列排序/过滤用)。

**技术栈锚点(镜像靶场 platform,版本已核到):** Vue 3.4.27 / vue-router 4.3.2 / pinia 2.1.7 / element-plus 2.7.3 / axios 1.7.2 / vite 5.2.11 / vitest 1.6.0;后端 FastAPI(靶场用 0.111.0)。**pyproject 现无 fastapi/uvicorn,需新增。** Python `>=3.10`(server2 有 `.venv312`)。

## 架构与数据流

```mermaid
flowchart LR
  subgraph B[浏览器 Vue3+ElementPlus 轮询刷新]
    Q[研判队列] --> D[单告警·完整研判流程]
    D --> AP[处置审批 + manual/auto 开关]
    D --> CP[Copilot 深度分析聊天]
    ST[价值大盘] & EX[经验库]
  end
  B -- Bearer(SOC_WEB_TOKEN) --> API

  subgraph API[新 soc_agent/web · FastAPI/uvicorn · server2 原生]
    R[读路由\nalerts/plans/stats/experience]
    W[写路由\napprove/reject/execute/rollback\nconfig/response-mode]
    C[聊天路由\nalerts/:uid/chat]
  end

  R -->|薄封| G[(Neo4jGraph\nrecall_ledger/get_alert/seed\n+findings/trace/分页/stats Cypher)]
  R -->|薄封| E[(exp_store.all\n= cli._open_stores)]
  C -->|台账为上下文| LLM[QwenClient.chat]
  W -->|薄封, 不自建执行| RC[respond_cli.approve/reject\nrun_plan/rollback_plan]
  RC --> AC[ApplianceClient] --> APPL[[靶场 appliance\n护栏+真执行]]
  W --> CFG[(:Config{key:'response_mode'}\nNeo4j 持久)]

  subgraph P[独立进程 poller(不变的常驻研判)]
    PP[make_processor.process\n每条读活态 mode]
  end
  PP -. 每条读 .-> CFG
  PP --> G
```

要点:**API 与 poller 同机、分进程、同读一套 Neo4j/openGauss**;护栏在 `respond_cli`→`ApplianceClient`→appliance 链路的内层,API 只是最外层 HTTP 封装。

## 新增/改动

### A. API 层 —— 新 `soc_agent/web/`
- `web/queries.py`(**纯 Cypher builder,离线单测,仿 `ledger.py` 风格**):
  - `q_alerts_page(...)` + `q_alerts_count(...)`:`MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)`,按 `verdict` / `path=coalesce(c.path,v.path)` / 处置状态(`p.status`)/ `q`(rule_description 模糊)过滤,`ORDER BY coalesce(a.arrival_ms,0) DESC SKIP $skip LIMIT $limit`,返回 uid/rule_description/severity/technique_ids/verdict/path/plan_status/arrival_ms。
  - `q_findings(uid)`:`MATCH (a:Alert {alert_uid:$u})-[:HAS_FINDING]->(f:Finding) RETURN f{.finding_id,.polarity,.evidence_ref,.skill,.attrs}`(attrs 为 json 串,路由层 `json.loads`)。
  - `q_get_config(key)` / `q_set_config(key,value)`:读/写 `:Config{key}` 节点(set 走 `graph.run_write`)。
  - `q_trace(uid)`:`MATCH (a:Alert {alert_uid:$u})-[:HAS_TRACE]->(t:Trace) RETURN t.steps AS steps`(steps 为 json 串;无 → 空,前端回退重建流程)。
  - stats 相关 Cypher:直接移植 `ledger-stats.sh` 五段(进度/积压/毒告警、verdict×path、Disposition 状态、ResponsePlan 状态、TP 抽样)+ **越用越省**:`MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) RETURN c.method AS method, coalesce(c.path,v.path) AS path, count(*) AS n` → 路由层算 `reuse`(method='reuse' 或 path∈{S,A})占比。
- `web/deps.py`:进程级单例(FastAPI `Depends`,测试可 `dependency_overrides`)——`get_config()`=`Config.from_env(dotenv_path=".env")`;`get_graph()`=共享 `Neo4jGraph`(neo4j 驱动线程安全,同步路由跑线程池 OK);`get_exp_store()`=`cli._open_stores(cfg)[0]`;`get_appliance()`=`ApplianceClient(cfg.response_url, cfg.response_token)`;`get_llm()`=共享 `QwenClient(cfg.llm_api_base, cfg.llm_model, cfg.llm_api_key, cfg.llm_timeout)`(Copilot 用;惰性建、缺 LLM 端点则 chat 路由返回 503);`require_token`=`HTTPBearer(auto_error=False)` 比对 `SOC_WEB_TOKEN`,不符 401(**单一 operator token**,内训隔离环境足够;RBAC 分析员提议/主管审批分权明确列为后续,不进 v1)。
- `web/routes/`:
  - `alerts.py`:`GET /api/alerts`(队列,分页+筛选,调 `q_alerts_page`/`q_alerts_count`)、`GET /api/alerts/{uid}`(**完整研判流程**:拼 `get_alert`(raw)+`seed`+`q_findings`+`recall_ledger`+`q_trace`(有则返 live 逐步流程,无则前端用重建流程)+ 复用来源:method='reuse' 时经 `origin_verdict_id` 反查源判例 uid,附其 recall_ledger 摘要)。
  - `plans.py`:`GET /api/plans?status=proposed`(=`respond_cli.list_plans`);`POST /api/plans/{id}/{approve|reject|execute|rollback}` → 分别薄封 `respond_cli.approve` / `reject` / `run_plan` / `rollback_plan`(execute/rollback 注入 `get_appliance()`;返回体带 `STATUS_ZH` 中文态)。
  - `stats.py`:`GET /api/stats`。
  - `experience.py`:`GET /api/experience`(`exp_store.all()`→`.to_dict()`,可按 skill/kind 筛)。
  - `config.py`:`GET|PUT /api/config/response-mode`(读/写 `:Config`,值仅 `manual|auto`)。
  - `auth.py`:`POST /api/auth/login`(校验 operator token 并回显,给前端登录视图存 localStorage)。
  - `chat.py`(**Copilot**):`POST /api/alerts/{uid}/chat`,body `{messages:[{role,content}...]}`。服务端组 system prompt = 该 uid 的台账上下文(`get_alert` raw 摘要 + `q_findings` 极性 + `recall_ledger` verdict/rationale/证据/缺失证据 + `seed` 实体 + 有 trace 则附关键步),拼 `messages` 调 `llm.chat(...)`,回 `{reply}`。**只读取数据、不写台账、不碰机器**(纯 Q&A;无 tools/tool_choice)。单轮请求/响应(非流式;前端管多轮上下文,与"轮询刷新"一致)。
- `web/app.py`:`create_app()` 工厂 → `include_router(...)`;`/api/healthz`;**生产**用 `StaticFiles` 挂 `soc_agent/frontend/dist`(server2 原生无 nginx,故与靶场不同、用 FastAPI 直接托管,history 回退到 `index.html`);模块级 `app = create_app()` 供 `uvicorn soc_agent.web.app:app`。

### B. 运行时模式开关持久化(`:Config` 单一事实源)
- 在 `graph/client.py::build_constraints()` 追加 `CREATE CONSTRAINT config_key IF NOT EXISTS FOR (c:Config) REQUIRE c.key IS UNIQUE`。
- 新增小 helper `read_response_mode(graph, default)`(放 `response/auto.py`,与 auto 逻辑同域):跑 `q_get_config('response_mode')`,缺失回退 `default`(=`cfg.response_mode` 的启动值,首启动顺带 seed 一次)。
- 改 `runtime/service.py::make_processor.process`:把 `if cfg.response_mode == "auto":` 换成 `if read_response_mode(pl.graph, cfg.response_mode) == "auto":`(**每条读一次**;`:Config` 读是毫秒级只读,graph 线程安全,不进 `_Locked`)。auto 时仍走现有 `auto_respond`(DC/CA 被护栏留待处置不变)。
- API 的 `PUT /api/config/response-mode` 写 `:Config` → poller 下一条即生效。默认 `manual`。

### B'. 持久化研判留痕 trace(让新研判的告警可回看真·逐步流程)
- 改 `graph/client.py::build_write_statements`:在写 verdict 之后,若 `result.trace`,追加一条 per-alert `MATCH (a:Alert {alert_uid}) MERGE (a)-[:HAS_TRACE]->(t:Trace {alert_uid}) SET t.steps=$steps`(steps=`json.dumps(result.trace)`)。**复用 label + per-alert 唯一键**,仿 `_finding_stmts`/`__no_op__` 的收敛与 prune 友好写法;`build_constraints()` 加 `Trace.alert_uid` 唯一约束。
- **复用路径(method='reuse')不产 trace**(未真跑研判)→ 其"流程"即"复用经验 X + 本告警取证",前端据 `origin_verdict_id` 展示来源判例的流程链。
- 影响面小、纯追加:老告警无 `:Trace` → API `q_trace` 返回空 → 前端用**重建流程**(raw→seed→findings→verdict/证据→处置)兜底,零 regression。存量若要补,可后续跑一次 backfill(不在本轮)。

### C. 前端 —— 新 `soc_agent/frontend/`(Vite 工程,镜像靶场约定)
- 工程:`package.json`(锁版本,同上锚点)、`vite.config.js`(`@`→`src`;dev proxy `/api`→`http://localhost:8000`;默认 `dist` 产物)。`main.js`:`createPinia`+`router`+`ElementPlus`(全量 CSS + 全 icons)。
- `src/api/client.js`:单一 axios 实例 `baseURL:"/"`,请求拦截器加 `Authorization: Bearer <localStorage.soc_token>`,响应 401 拦截器→登出跳登录(仿靶场命名函数、便于单测)。
- `src/router/index.js`:`createWebHistory`,`meta.public` 登录页;全局 `beforeEach` token 门。Pinia `stores/auth.js`(options-store:token 存取)。
- 视图(`src/views/`):
  - `AlertQueue.vue`(首屏):`el-table`+筛选(verdict/path/处置状态/关键词)+分页(靶场未用 `el-pagination`,此处产品级需要,自建分页条);轮询刷新;行点开→溯源。
  - `AlertDetail.vue`(**完整研判流程**,面⑤):一条**时间线**贯穿全过程——原始告警 raw → seed 图上下文(触发事件/主宾/次要实体)→ 取证 findings(极性徽标)→(命中经验则一张"复用来源"卡:链到源判例 uid + 其结论)→ verdict/path/method/置信度 → rationale + 证据/缺失证据 → 处置计划步骤+状态。**有 `trace` 时**额外渲染真·逐步流程(每步 cypher 查询/行数、喂大模型的 prompt、护栏决策——用 `render_trace` 的语义分类);无 trace 用上面的重建流程。TP 且待处置→内嵌审批操作区。顶部"**深度分析**"按钮 → 携本 uid 打开 Copilot。
  - `Copilot.vue`(面⑥):聊天面板(左侧可选/搜历史告警 uid 作上下文,或从 AlertDetail 携 uid 进入)。消息列表 + 输入框,发送 → `POST /api/alerts/{uid}/chat` 携完整多轮 `messages`,渲染助手回复;前端维护会话历史。给出快捷追问("为什么判 {verdict}?""还缺哪些证据?""该实体历史?")。
  - `Approvals.vue`:待处置 plans 表 + 单/批量 approve/reject/execute/rollback + **manual/auto 开关**(调 `config/response-mode`);中文态用后端回的 `STATUS_ZH`。
  - `Dashboard.vue`:统计卡(自动结案率/吞吐/积压)+ verdict×path 图 + **越用越省曲线** + 毒告警数。
  - `Experience.vue`:经验表(skill/kind/verdict/note/hit_count/status;`origin_case_id` 链回溯源告警)。

### D. 打包/运行
- `pyproject.toml`:加 `[project.optional-dependencies] web = ["fastapi>=0.111", "uvicorn[standard]>=0.30"]`。
- `scripts/web.sh`:仿 `scripts/poller.sh`——`.venv312` 起 `uvicorn soc_agent.web.app:app --host 0.0.0.0 --port 8000`,feedback ferry 回仓(git commit/push,同 poller.sh 尾段)。前端 `npm --prefix soc_agent/frontend run build` 出 `dist`。

## 关键文件
- **新增**:`soc_agent/web/{app.py,deps.py,queries.py,routes/{alerts,plans,stats,experience,config,auth,chat}.py}`;`soc_agent/frontend/`(Vite 工程,含 `Copilot.vue`);`scripts/web.sh`;测试见下。
- **改**:`soc_agent/config.py`(response_mode 语义不变,新增 `SOC_WEB_TOKEN` 读取)、`soc_agent/runtime/service.py`(mode 改活态读)、`soc_agent/response/auto.py`(+`read_response_mode`)、`soc_agent/graph/client.py`(+`config_key`/`trace` 约束、`build_write_statements` 追加 trace 持久化)、`pyproject.toml`。
- **复用不改**:`response/ledger.py`、`respond_cli.py`、`response/appliance_client.py`、`llm/qwen.py`(`QwenClient.chat`)、`experience/store.py`+`opengauss.py`、`cli._open_stores`。

## 分期(TDD:RED→GREEN,mock graph/store,仿现有 `tests/test_poller.py::_FakeGraph` + FastAPI `TestClient` + `dependency_overrides`)
1. **API 读 + 完整流程**:`web/queries.py` 纯 builder 单测(断言 Cypher 关键片段:分页/筛选/`arrival_ms DESC`/`HAS_FINDING`/`HAS_TRACE`/`:Config`);路由 `/api/alerts`、`/api/alerts/{uid}`(**完整流程拼装**:`get_alert`+`seed`+findings+`recall_ledger`+`q_trace`+复用来源都被调、返回形状对,含 trace/无 trace 两分支)、`/api/plans`、`/api/stats`、`/api/experience`。
2. **API 写 + 鉴权**:approve/reject/execute/rollback 薄封断言(mock ApplianceClient),**护栏测**:execute 打 DC/CA 步骤→被 appliance 拒、计划不真执行;无/错 token→401。
3. **模式持久化**:`PUT response-mode=auto`→`:Config` 落值;`read_response_mode` 读到 auto;接现有 `tests/test_runtime_service.py` 断言 auto 走 `auto_respond`、manual 不执行。
4. **trace 持久化 + Copilot**:`build_write_statements` 在 `result.trace` 非空时产出 `HAS_TRACE`/`:Trace` 写句(仿 `tests/test_graph_write.py` 断言语句序列),reuse 路径不产 trace;`/api/alerts/{uid}/chat` 路由测(mock `QwenClient.chat`:断言 system prompt 含台账上下文、多轮 messages 透传、返回 `{reply}`;LLM 端点缺失→503;无 token→401)。
5. **前端**:Vitest 组件/store(队列筛选、**完整流程时间线渲染**含 trace 分支、审批按钮调 API、`STATUS_ZH` 映射、**Copilot 多轮消息追加**、token 拦截器);`vite build` 通过。
6. **真机(server2,ferry;本轮不做,列为落地验收)**:起 uvicorn+前端;队列加载真实台账;开一条 TP 看完整研判流程链(含 trace);Copilot 就该 TP 问答一轮;approve→execute 一个**非 DC** 处置到靶场、验护栏挡 DC/CA、manual 下无被动执行。

## 验证(端到端,落地时在 server2)
浏览器:① 队列按 `arrival_ms` 序、筛 TP/待处置正常;② 点开一条 TP,**完整研判流程时间线** raw→seed→findings(极性)→verdict/rationale/证据/缺失证据→dispositions 全链可见;新研判的告警额外显示逐步 trace,老告警走重建流程且不报错;③ **Copilot** 就该告警多轮问答,回复引用其台账(证据/缺失证据/实体);④ 审批一个非 DC 处置→图里 Disposition `proposed→executed`、appliance 真跑;⑤ 对 DC/CA 处置→护栏留待处置、不执行;⑥ 大盘自动结案率/越用越省/积压数与 `scripts/ledger-stats.sh` 对得上;⑦ manual/auto 开关切换→poller 行为随之变(auto 自动执行非 DC、DC 仍留)。

## 待用户复核的裁剪
- **单一 operator token**(RBAC 分权后置)——已确认保留。
- 本轮**只交付设计,不实现**;落地目标仓为 `CoreObjects/soc-agent`(与本会话检出的靶场仓不同),届时另起分支/PR。
