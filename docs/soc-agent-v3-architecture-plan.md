# Plan: soc-agent 告警研判 + 处置系统 · 架构设计

## Context —— 要做什么、为什么

在 **server2** 从零建一个**完整的告警研判 + 处置系统**(不是演示 MVP),只跟 **server1 的 v3 知识图谱**(bolt)+ **本地 qwen32b-ft** 交互,headless。**不迁移、不参照任何老 `soc/` 代码**(老实现是缝合屎山、其 pattern_key 有 bug),全部按已确认的需求模型重新设计。

**已确认的需求模型(唯一事实源,设计不得违背):**
1. **知识 = skills**:四层 playbook(`docs/research/alert-investigation-playbooks.md`,每类告警怎么研判)做成**活的研判模块**;agent 学会"遇到这类告警 → 调这个 skill 去查证"。skills 覆盖四层**所有**告警类别 + **每层一个通用兜底**(覆盖不到的类型走通用方法论)。
2. **两种"经验"分开放,别混**:
   - **图里** = 每条告警各自的历史 `Verdict/Disposition` 台账(**不可复用**)。用途 = 历史记录 + **情报参照**(某些方法论要"捞过去相似案例喂大模型做研判参考")。
   - **skills 里** = **可复用经验**;快通道复用它,**不去图里找可复用经验**。
3. **可复用经验 = 两块 = 快速通道(分层短路,命中哪块省哪块 agent 工作量)**:
   - **① 取证脚本**:某类告警研判过后,把**取证脚本**沉回 skill。取证不是一条 Cypher,是**多步依赖查询 +（BFS 等）算法的一段脚本**(查到 A→B 才能接着查)。下次同类 → 免重推"怎么查"。
   - **② 攻击模式判别 → 处置**:取证脚本查回的**证据子图**,用**固定判别逻辑**认已知攻击模式(例:暴力破解 = 一个 IP 多次登录,固定图形状),命中 → 直接对应**处置**,免重判整条。1000 条相同告警命中同模式 → 复用同一研判/处置——**降噪在 SOC 这做,不在入图人为剔**。
4. **研判 + 处置都要**;研判/处置结果**写回图**挂在 `:Alert` 上(v3 经验层,已建好,就是为这准备的)。
5. **实例无关**:换 IP/主机/账号仍算同一类/同一模式(否则换 IP 不命中、自进化废)。**做法 = 取证脚本以"告警的实体"为入参、模式判别只看结构与阈值,不做任何字段 hash**(老 pattern_key 的坑)。

## 核心分层(图 vs skills 的分工,一张图看清)

```
┌───────────────────── server1: v3 知识图谱 (Neo4j) ─────────────────────┐
│ 事实层(事件/实体/聚合边) + 告警 :Alert + 经验层 :Verdict/:Disposition   │
│   ▲ 取证:只读事实                        ▲ 研判/处置结果写回(台账+情报)  │
└───┼──────────────────────────────────────┼───────────────────────────┘
    │ bolt(读事实 / 写经验)                  │
┌───┼──────────────────── server2: soc-agent 引擎 ──────────────────────┐
│ 分流路由 ── 该告警类型有 active 取证脚本吗?                            │
│   ├─ 有 → 快通道:①跑 skill 现成取证脚本(查图取证据)→ ②跑模式判别      │
│   │        命中模式 → 直接套 verdict+处置(免研判) / 未命中 → 转慢通道定性│
│   └─ 无 → 慢通道:自主 agent 用 skill 方法论                            │
│           取证(composes 脚本, 查图/BFS) → 还原 → 定性 → 处置           │
│           └ 沉淀:① 取证脚本回 skill   ② 新模式判别+处置回 skill(draft→active)│
│                                                                        │
│ Skills(活知识, 文件/目录, git 版本化)= 方法论 + 取证脚本 + 模式判别→处置│
│   四层每类一个 + 每层通用兜底                                            │
│ qwen32b-ft(可插拔 Investigator) · 处置 Tool 适配(护栏/真做|模拟/回退/审计)│
└────────────────────────────────────────────────────────────────────────┘
```

**关键**:agent **取证只从图取事实**(不违背硬需求);但"怎么查 / 是不是已知模式 / 怎么处置"这些**可复用逻辑在 skills**,不去图里找。图的经验层只做"历史台账 + 情报参照"。

## 组件 / 仓库结构(soc-agent)

```
soc-agent/
  model/graph_model.json          # v3 图 schema(已存在,唯一权威;本设计几乎不改,见下)
  docs/research/*.md              # playbook(skills 方法论种子)+ 本设计
  skills/                         # 【知识=活的研判模块】
    <layer>/<alert_type>/
      SKILL.md                    #   方法论(决策树/取什么证据/误报/判定逻辑;从 playbook 生成)
      recipes/                    #   ① 取证脚本(参数化, 实际研判中沉淀/丰富)
      patterns/                   #   ② 攻击模式判别 + 处置模板
    _generic/<layer>.md           #   每层通用兜底方法论(未覆盖类型走这)
  agent/                          # 【引擎】
    graph/                        #   Neo4j 客户端:只读事实 + 遍历/BFS 原语 + 写经验(读写分权)
    llm/                          #   qwen 客户端 = 可插拔 Investigator 接口(后续可换 Claude)
    schema/                       #   从 graph_model.json 自动生成 v3 schema → 注入 system prompt
    skills_runtime/               #   加载 skill / 跑 recipe / 跑判别 / 沉淀回写 skill
    orchestrator/                 #   分流路由 + 慢通道调查循环(取证→还原→定性→处置骨架)
    disposition/                  #   处置 Tool 适配 + 护栏 + 回退 + 审计
    tools/                        #   暴露给 LLM 的工具(见下)
  scripts/                        # CLI:研判单条告警 / 轮询未研判 / 双跑复用验收
```

## Skills 设计(知识 = 活的研判模块)

- **形态 = 文件/目录**(每类告警一个目录),git 版本化、人可读可审、可被 agent 读写增补。**不进图**(图放历史台账,不放可复用经验)。
- **一个 skill 三部分**:
  1. `SKILL.md` **方法论**(初始态)——直接源自四层 playbook 的"决策树 → 取什么证据 → 误报场景 → 判定逻辑"。这是 agent"怎么想"的知识。
  2. `recipes/` **取证脚本**(初始可空,慢通道中沉淀/丰富)——见下"取证脚本"。
  3. `patterns/` **攻击模式判别 → 处置**(慢通道识别出稳定模式后沉淀)——见下"攻击模式"。
- **覆盖**:四层 playbook 的**所有类别**各一个 skill(LSASS/T1105/持久化/LOLBin/Kerberoast/ADCS/DCSync/横向/SQLi/XSS/LFI-RFI/RCE/Webshell/C2-beacon/横向网络维度…)+ `_generic/` 每层一个**通用方法论**兜底。
- **skill 选择**:分流按告警的 `technique_id`/规则/层 映射到具体 skill;无匹配 → 该层 `_generic` skill。

## 取证脚本(recipes)= 第①块经验

- **不是一条 Cypher,是一段可控制流的取证过程**:多步、后步依赖前步结果(查到 B 节点才能从 B 往下)、可含图算法(BFS/变长路径/最短路)。
- **表达 = 参数化的取证过程**(Python 可调用 / 受限步骤 DSL):入参 = **该告警绑定的实体**(host/account/ip/process…),过程调用 graph 原语(`run_cypher` 只读 + `expand/bfs/shortest_path`,由 `agent/graph` 提供,Neo4j 变长路径 / APOC 遍历实现 BFS)。返回**证据子图**。
- **实例无关的正确做法**:recipe **不硬编码任何实例值**,只把"告警的实体"作为入参在运行时绑定 → 换 IP/账号只是换入参,同一 recipe 通用。**这替代老 pattern_key**,不做字段 hash。
- **沉淀(自进化)**:慢通道里 agent 为某类告警实际跑通的查询序列 → 蒸馏成参数化 recipe → 存进该 skill 的 `recipes/`(draft→active)。下次同类 → 快通道直接跑 recipe,免 LLM 规划(**命中① = 省取证规划**)。

## 攻击模式判别(patterns → 处置)= 第②块经验

- **攻击模式 = 取证脚本查回的证据子图上的一个固定图模式**(例:brute_force = 一个 IP 对一台主机在窗口内失败登录 ≥N 次)。
- **判别器 = 对证据子图的结构化匹配**(参数化 Cypher/谓词),返回 `(命中?, 绑定实体, 置信)`;**只看结构/角色/计数/阈值,不看具体实例 → 天然实例无关**。
- **每个模式绑定**:模式名 + `verdict` 模板 + **处置模板**(动作序列 + 目标(用绑定实体填)+ 风险级)。
- **短路**:快通道跑完 recipe 拿到证据 → 跑该 skill 的 active 判别器 → 命中 → 直接套 verdict + 处置(**命中② = 省整条研判**);未命中 → 交慢通道定性。
- **沉淀**:慢通道定性时若 agent 认出一个**稳定可复用的模式**,产出"判别器 + 处置模板"草案(draft),经确认/验证 → active。**降噪**:同模式的海量重复告警从此走②、复用同一处置。

## 快慢通道路由(分层短路,`orchestrator`)

```
告警到达 → 定其 skill(technique/规则/层;无则该层 _generic)
  ├─ skill 有 active recipes?
  │    否 → 慢通道·取证(agent 用方法论 composes 脚本查图)  →(沉淀①)
  │    是 → 快通道·取证(跑现成 recipe,无 LLM)
  ├─ 拿到证据子图 → skill 有 active 判别器且命中?
  │    是 → 快通道·定性+处置(套模板)          → 写图 + 审计
  │    否 → 慢通道·还原→定性(agent 用方法论,可捞图中相似历史案例作情报)
  │           →(若认出稳定模式)沉淀② → 处置
  └─ 无论快慢:Verdict/Disposition 写回 :Alert(台账+情报);全程审计
```
- 三态短路:①省"取证规划"、②省"定性+处置";两者都命中 = 全快通道(秒级、无 LLM)。

## 慢通道自主 agent

- **可插拔 Investigator 接口**;首实现 = qwen32b-ft(vLLM,OpenAI 兼容,`trust_env=False`,native tool calling,32K)。
- **system prompt** = 自动生成的 v3 schema(从 `graph_model.json`)+ 该告警选中的 skill 方法论 + 骨架规程(取证→还原→定性→处置)。
- **给 LLM 的工具**:`run_cypher`(**只读事实**守卫)、`graph_expand/bfs/shortest_path`、`recall_similar_cases`(捞图中同技术/同模式的历史 Verdict 作情报)、`propose_disposition`、`write_verdict`(经专用写路径写经验层)。
- **骨架保底 + LLM 自主**:骨架强制"反查触发事件→涉及实体→(情报)历史经验";在骨架内 LLM 自主决定深挖方向、何时够、出结论(**不是死流水线**)。带 `max_iterations` + token 预算 + 防重复查询。

## 处置层(`disposition`)

- **统一 Tool 适配**接口:`execute(tool, action, params) → {动作,目标,结果,是否真实,可回退,回退句柄}`。
- **真做 / 模拟**:能触达的控制面**真做**(GOAD 拓扑下如禁 AD 账号 / 隔离 VM / 封 IP,视可达性);触达不了的**模拟并标 `simulated=true` + 审计**(不假装成功)。
- **护栏**:高危(封网段/禁账号/隔离主机)= **gated**(建议+二次确认或可回退);低危(封单 IP)= 自动。NEVER-TOUCH 名单(管理/安全区、网关、保护账号/主机)硬拒。
- **回退 + 审计**:真实动作带回退句柄;所有处置/确认/回退落审计。

## 经验入图(情报参照 + 历史台账)

- 每次研判完:`(:Alert)-[:CONCLUDED]->(:Verdict)-[:LED_TO]->(:Disposition)-[:ON]->实体` 写回(v3 已有)。
- 慢通道方法论可 `recall_similar_cases`:按 `technique` + (可选)识别出的模式名,捞过去相似 Verdict 作情报喂大模型。
- **图模型改动 = 近乎为零**:事实/告警/经验层都已在 `graph_model.json`。**唯一可选微调**:允许 `Verdict` 带一个"识别出的模式名"属性,便于情报按模式检索(模式的**定义/判别器仍在 skills,不进图**)。

## 建设分阶段(设计=完整系统;建设分层推进,每阶段可独立验)

- **P1 骨架 + 单类闭环**:`agent/graph`(读事实+写经验, 只读守卫)+ qwen Investigator + schema 注入 + 1 个 skill(如 Kerberoast 方法论)→ 慢通道对一条真告警研判 → 写 Verdict + 建议处置 → 图里可见。(暂无快通道)
- **P2 skills 全覆盖 + 慢通道成熟**:四层所有 playbook 类别的 `SKILL.md` + 每层 `_generic` + 取证工具(含 BFS 原语)+ `recall_similar_cases` 情报。
- **P3 沉淀① + 快通道取证**:慢通道蒸馏取证脚本回 skill(参数化);快通道复用 recipe(命中①省规划)。
- **P4 沉淀② + 快通道定性**:模式判别器 + 处置模板;慢通道识别新模式沉淀;快通道命中②省整条研判;draft→active。
- **P5 处置层**:Tool 适配 + 护栏 + 真做/模拟 + 回退 + 审计。
- **P6 运行形态 + 验收**:轮询未研判告警;**换实例双跑复用验收**。
- (驾驶舱 UI / 一键下发编排:后续可选,不在首期;首期结果先用现有 graph viz 看。)

## 验证(端到端兑现)

- **单类端到端**:喂一条真 Kerberoast(T1558.003)告警 → 慢通道用身份层 skill 方法论 → composes 取证脚本查图 → (识别或不识别模式)→ 出 verdict + 建议处置 → Verdict/Disposition 入图 → 取证脚本沉入 skill。
- **换实例双跑复用(头号验收,实例无关)**:第二条**同类不同实例**(换 account/IP/host)告警 → 快通道:复用 recipe(**无 LLM 规划**)+ 判别命中同模式 → 套同一 verdict+处置。断言:run-2 走快通道、无 LLM 规划、结论正确、**换实例仍命中**。
- **降噪**:同模式重复告警批量走②、复用处置。
- **覆盖**:四层所有 playbook 类别有 skill + 每层通用兜底可被选中。
- **处置护栏**:高危 gated、低危 auto、NEVER-TOUCH 硬拒、全审计、可回退。

## Critical Files

- `soc-agent/model/graph_model.json` —— v3 权威 schema(几乎不改;可选给 `Verdict` 加"模式名"属性)。
- `soc-agent/docs/research/alert-investigation-playbooks.md` —— 四层 playbook = skills 方法论种子。
- 新建:`soc-agent/skills/**`(SKILL.md + recipes + patterns + _generic)、`soc-agent/agent/**`(graph / llm / schema / skills_runtime / orchestrator / disposition / tools)、`soc-agent/scripts/**`(研判/轮询/双跑验收 CLI)。
- LLM:qwen32b-ft `http://<server2>:8000/v1`(无 key/EMPTY,`trust_env=False`);图:`bolt://<server1>:7687`。端点走 env,不入公开仓。
