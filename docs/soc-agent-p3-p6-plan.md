# Plan: soc-agent 主线 P3–P6 —— 快通道 + 攻击模式规则库 + 自动处置(真做)+ 台账回写 + 自进化

> 原 P1–P6 架构:`soc-agent/docs/soc-agent-v3-architecture-plan.md`(粗糙)。靶场完善已收口。本文件重设计 P3–P6,选型/架构经与用户逐条对齐后锁定。

> **📌 归档状态(2026-07-15)**
> - **P3'(快通道 + 图外攻击模式规则库 openGauss + 运行态生成 + 图台账收敛)已建成并真机验通**(换实例双跑通过;详见 memory `soc-agent-p3-built` + git 提交)。
> - **本文件 Section 七(自动处置)已被重新定调、将由单独的 P4 详细方案取代**:处置面不是几个高级罐头动作,而是**靶场开放一组"基础处置原语"接口(可组合/可回退/可审计)+ 产出处置接口文档**,agent 侧起**独立 composer 环节**(不动研判)拿研判结果+接口文档**组装**原语成响应计划,慢通道一次、固化进规则模板、快通道复用;所有遏制**人审后才真做**;真企业部署=换接口文档。产品级、非 MVP。P4 详细方案另行规划。
> - Section 八(daemon)/ P6'(铺开+迁移+recall 排除精修)仍有效,待 P4 之后。

## Context —— 为什么、要什么

**已完成(P1/P2)**:基建(图读写+只读守卫、qwen 客户端、schema 注入)+ 知识(16 skill 的方法论+recipe,12 个具体 skill 的**取证已在真数据上验牢**)。当前每条告警:LLM 路由选 skill → recipe 确定性取证 → **一次 LLM finalize_verdict** → 护栏(仅提议)→ 回写 `(:Alert)-[:CONCLUDED]->(:Verdict)-[:LED_TO]->(:Disposition)`。

**本轮要做、且原设计太糙需重来的**:① **快通道**(命中已知攻击模式→直接套结论+处置、免 LLM);② 自动处置**真执行**;③ 台账回写的**收敛**(同结论别在图里堆重复节点);④ 攻击模式**沉淀 + 自进化**。不设计死就做必然跑偏、反复改越改越坏——先锁设计。

**关键 reframe(已确认)**:本机 qwen32b-ft **只会"判"、不会 planning/author**(给对证据判得好,现场写不出正确取证脚本/规则)。所以:**可复用逻辑离线用强模型(Claude)写(少数大类,慢更新来得及);攻击模式规则运行态确定性生成(成千上万,离线来不及)**。qwen 只在慢通道"读齐证据后定性"。

**已锁的岔路**:处置**真做**、且**给靶场加处置面本轮就做**(非模拟);判别 = **图模式为主 + 代码钩子**;图内重复靠设计避免;权威规则库 = **openGauss 系(信创)** + Redis 热读。

## 一、三存储彻底分离(硬边界,反复确认过)

| # | 放哪 | 存什么 | 谁写、多快 |
|---|---|---|---|
| 1 | **skills/ git 文件** | recipe 取证脚本 + **判别 spec**(怎么抽判别特征/怎么分桶/非结构走哪个钩子)+ 方法论 | 离线 Claude,**少数大类**,慢 |
| 2 | **Neo4j(图)** | 告警 → 研判结果 → 处置**台账** + 情报参照(**纯历史:发生了什么**),台账挂 `pattern_id` 溯源 | 运行态,每条告警 |
| 3 | **openGauss + Redis** | **攻击模式 → 处置方法 规则**(判别特征签名 → verdict+处置模板) | 运行态确定性生成,**成千上万**,去重 |

**铁律**:可复用**逻辑**→ skills;**历史台账/情报**→ 图(**图里绝不放可复用规则**);可复用**攻击模式规则**→ openGauss+Redis(**图外**)。

## 二、判别 spec:图模式为主 + 代码钩子(离线 Claude 写,每 skill 一份)

`skills/<skill>/discriminator.py`(或 .yaml+py):把一条告警的证据**确定性投影**成**判别特征签名**。
- **图模式为主**:判别特征多数从图结构算——如 kerberoast 的 `req_is_machine`(账号 sam 结尾$)、`same_domain`、`enc`、`spn_fanout_bucket`(短窗 REQUESTED 到多少不同 Service,分桶 <5 / ≥5)。这些是**结构/计数/阈值**,查证据子图得。
- **代码钩子(补非结构)**:图答不了的几个是非题用小 Python 函数——`decoded_is_benign`(base64 解码看内容)、`writer_is_security_agent`(查已知代理名单,复用 `recipe_lib.security_agent`)。
- **先证伪分层(泛化旋钮)**:spec 分层——**先算豁免层特征**(如机器账号+跨域)出**豁免签名**,查有没有 FP 规则;没有再算**坐实层特征**出更细签名查 TP 规则。→ 豁免能在扇出高时压过坐实;各层内**精确签名**、一条告警每层至多命中一条规则(无 priority 冲突)。
- **泛化 = spec 选哪几个特征 + 怎么分桶**:实例值(账号/IP/具体 SPN)**不进签名**,只留着填处置目标 → 换实例同判别特征照样命中;要那几个判别特征全中才算 → 不太松。**不 hash 整坨证据、不自动相似度**——跟作废的 pattern_key 两回事。
- 加载与 recipe 同法,**每文件 try/except 隔离**(坏文件不拖垮 daemon)。

## 三、攻击模式规则库(openGauss 权威 + Redis 热读)—— 运行态生成

**openGauss `patterns` 表**(权威、ACID、审计、生命周期):

| 列 | 作用 |
|---|---|
| `skill` + `sig_layer`(exculpatory/incriminating) + `feature_sig`(签名规范串) + `sig_hash` | **唯一约束 → 去重**(`ON DUPLICATE KEY UPDATE`/`ON CONFLICT`,方言层适配);键是**作者选的判别特征值**,非盲哈希 |
| `verdict_template` / `disposition_template`(json/text blob,整块取不内部查询) | 复用的结论 + 处置(action + target_kind + target_field) |
| `status`:pending / active / deprecated | TP/FP 自动 active;可疑 pending 待人采纳;误判可 deprecate |
| `stats`:hit_count / last_hit / tp_confirmed / fp_reverted | 精度反馈——被分析师回退多了自动降权/停用 |
| `provenance`:source_alert_uid / minted_by(path) / minted_at / adopted_by / adopted_at / skill_spec_version / version | 可解释 + 审计 + 版本化(软停用+新版本,不硬删) |

- **运行态生成**:每出一个 verdict → 照 spec 抽判别特征签名 → **upsert** 一条规则(键=skill+层+签名),绑 verdict+处置模板。**确定性机器动作,不是 qwen/离线写。**
- **处置模板怎么来**:慢通道 LLM 首判给出 verdict+处置建议时,运行时把"处置目标"**映射回它来自的证据字段**(如 `vagrant`→`target_field=requester`),存成模板;下次命中拿本实例的 requester 填。
- **Redis 热读**:active 规则按 `sig_hash` 缓存(快通道每条告警查一次,须亚毫秒);规则生命周期变更→失效/刷新。openGauss 是写路径+冷查+审计。
- **仓储接口抽象**:隔离 openGauss 方言(UPSERT/认证),换库不动上层。

## 四、快通道 + 路由(命中即复用,0 LLM)

1. **路由**:`technique_ids → skill` 确定性直达(唯一映射时连路由 LLM 都省);空/多映射/歧义 → 退回 `SkillRouter`(LLM 读 description)。
2. **取证**:跑 recipe(证据子图在图里)。
3. **判别 + 查规则(快通道)**:跑 skill 的判别 spec → **先豁免层**:抽豁免签名 → Redis/openGauss 查 active FP 规则,命中→套 FP 结论(证伪优先);未命中 → **坐实层**:抽签名 → 查 active 规则,命中→套 verdict+处置模板、`target_field` 解析成真实体、填处置 → 出结果(**path A,0 LLM**)。
4. **没命中** → 慢通道:RecipeInvestigator(recipe 证据 → 1 次 LLM finalize,path B)→ 出 verdict → **当场生成 pattern**(第三节 upsert)。

## 五、图内台账回写 + 收敛(先 fork、迁移合并)

图只存**历史**:`(:Alert)-[:CONCLUDED {at, path, confidence}]->(:Verdict)-[:LED_TO]->(:Disposition)-[:ON]->真实体`。收敛:
- **命中同 pattern 的告警共享一个 Verdict 台账节点**(键=`pattern_id`/规范结论,配唯一约束防并发 MERGE 重复);每条告警的 per-alert 历史(时间/置信/本条证据)在 **`CONCLUDED` 边**上。Verdict 节点挂 `pattern_id` 溯源到 openGauss 规则(规则本体不在图)。
- **处置台账按真实体一条条记**(封两个不同 IP = 两条 Disposition,是真历史);补 `(:Disposition)-[:ON]->真实体` 边,目标 0/多命中→不硬造边、降级 escalate。
- **慢通道未命中的先 fork**(各建各的 Verdict,接受暂时重复);离线补出该类 skill/规则后,**迁移**:拿规则重跑各 fork 的**存档证据**、把同结论 fork 收编到共享节点、`CONCLUDED` 边重指、删孤儿。迁移幂等、可重跑、容忍并发。
- `_recall_similar` 情报回喂**排除已收敛共享节点/按节点去重**(否则误标节点强锚定带偏弱模型)。

## 六、研判结果 → 采纳 → 沉淀 + 两类 miss

- **TP/FP**:结论确定 → 自动生成 **active** 规则 + 回写台账。
- **可疑(suspicious 带 lean)**:呈现给用户(证据+建议处置)→ **用户采纳** → 规则转 active;未采纳 → 规则留 pending(可疑告警指向它、不重复烧 LLM;provisional 只允许 escalate/monitor,绝不触发 gated)。
- **两类 miss(分开,别混)**:
  - **pattern-miss**(有 skill/recipe,只是没这签名的规则)→ 慢通道判 + **当场生成规则**(运行态自积累,离线零参与)。
  - **skill-miss**(路由到 `_generic`/无对口 skill 的**陌生告警类型**)→ **收集进旁路库**(Alert+证据+seed+路由结果)→ 交**离线 Claude 补新 skill**(recipe+方法论+判别 spec)。skill 是少数大类,离线慢更新来得及。**这就是"没提前备好 skill 的告警"的去处。**

## 七、自动处置真执行 + 给靶场加处置面(本轮做)

- **处置目标绑定**:模板 `target_kind+target_field` → 解析成真实体(account 按 sam、host 按**主机名组件精确匹配**、ip 按 ip);0/多命中→escalate。
- **护栏(在 P5a 上补)**:NEVER-TOUCH **子串→组件精确匹配**(现 `dc01∈adc01` 会误判);`block_ip` 加**共享/NAT 出口 IP 检查**;daemon 里 policy **定期刷新**;gated 高危→人审队列、auto 低危。
- **执行器(可插拔适配器)**:每动作一适配器,**真做 / 模拟(dry-run) / 回退句柄 / 全审计**。
- **★靶场处置面(GOAD 侧,本轮建)**,复用现有基建让 SOC 真执行:`block_ip`→网关容器 nftables(Phase1 已有网关);`disable_account`→ansible/WinRM 禁 AD 账号(仿良性发生器 become:runas);`isolate_host`→网络隔离规则;`kill_process`/`quarantine_file`→经主机 agent。每个带**回退**(封 IP 记规则句柄、解封即回退)+审计;gated 人审后才真跑。

## 八、daemon 运行形态

- **发现**:轮询 `(:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND a.ingest_time < now-Δ`——**settle 窗口 Δ**(佐证事实在触发事件之后才到齐,太早判会漏算错判)。
- **不重判**:**原子 claim/lease**(不用 CONCLUDED 边当锁,有 TOCTOU;CAS 领取、租约过期可重领),防并发/重启双判双烧 LLM。
- **并发**:快通道(无 LLM)宽;**慢通道 qwen 严限 1–2 在飞**(单弱 vLLM);按 severity 优先。

## 九、分阶段(先打通窄闭环,再铺开)

- **P3'(首刀)· Kerberoast 单类端到端**:① `kerberoast/discriminator.py`(豁免层:跨域机器账号引荐票;坐实层:spray)+ 钩子;② openGauss `patterns` 表 + Redis 缓存 + 仓储层;③ 快通道接线(确定性路由+先证伪查规则+命中套模板);④ 图内台账:命中同规则共享 Verdict 节点(+唯一约束)、`:ON` 边;⑤ 慢通道当场生成规则。**验收(换实例双跑)**:两条不同实例 kerberoast 都走快通道、命中同规则、**0 LLM、结论正确、图里指同一 Verdict 节点、openGauss 里只一条去重规则**;豁免层扇出高时仍压过坐实层。
- **P4'· 处置真执行 + 靶场处置面**:执行器 + 护栏补丁 + GOAD 处置面(先 `disable_account`/`block_ip`)+ 真回退/审计;gated 人审。
- **P5'· daemon**:claim/lease + settle + 限流;轮询真告警自动研判回写。
- **P6'· 铺开 + 自进化闭环**:skill-miss 旁路收集库;离线给其余已验 skill 补判别 spec;慢通道 fork 的历史 → **迁移工具**收编。

## Critical Files
- **soc-agent 新增**:`skills/<skill>/discriminator.py`(图模式判别+钩子+签名);`soc_agent/patterns/`(规则库仓储:openGauss 权威+Redis 缓存+方言层、签名匹配、先证伪/分层、pattern 生成/upsert);`soc_agent/collect/`(skill-miss 旁路收集);`soc_agent/daemon.py`(轮询+claim/lease+settle+限流);`soc_agent/disposition/`(执行器+适配器+目标解析+护栏补丁)。
- **soc-agent 改**:`soc_agent/orchestrator/__init__.py`(快通道 path A、确定性路由、pattern 生成接线、recall 排除收敛节点);`soc_agent/graph/client.py`(Verdict 台账按 pattern_id 收敛、per-alert 归 CONCLUDED 边、唯一约束、`:ON` 边、claim/lease);`soc_agent/models.py`(Verdict/Disposition 台账语义键、pattern_id 溯源列);`model/graph_model.json`(补 `:ON` File、pattern_id、字段漂移)。
- **GOAD 新增(处置面)**:`deploy/ansible/response-*.yml`(禁账号/隔离,仿 benign-*.yml become:runas)、网关 nftables 封 IP 接口、`deploy/setup/6x-*.sh` 自 ferry runner。
- **复用**:`recipe_lib`(钩子复用 security_agent/decode_chain)、`graph/guard.py` 只读守卫、`apply_guardrail`、现有网关容器。

## 验证(端到端)
- **首刀验收(头号)**:换实例双跑——两条不同实例都走快通道、**0 LLM、结论正确、图里指同一 Verdict 台账节点、openGauss 里去重成一条规则**;豁免层扇出高时压过坐实层(先证伪)。
- **规则库**:并发生成不产重复(唯一约束);Redis 热读命中;pending→采纳→active 生命周期;精度反馈能停用误规则。
- **处置真做**:gated `disable_account` 人审→真禁 AD 账号→审计有记录→回退能解禁;NEVER-TOUCH 硬拒 DC/krbtgt/传感器;`block_ip` 不误封 NAT。
- **daemon**:并发/重启不双判(claim/lease);< Δ 的告警不判;慢通道限流不打爆 qwen。
- **自进化**:skill-miss 落旁路库→离线补出可用 skill;慢通道 fork 的历史被迁移收编到共享节点(图内外一致)。

## 明确要避免的坑(压力测试固化)
- 判别**别读原始中文键证据**(嵌套/条件缺失/表示漂移,一改 recipe 就崩)——判别 spec 直接查图事实 + 钩子读 recipe 计算量,产**规范签名**。
- 规则键**只认判别 spec 给的签名**,不认 LLM 自由文本 `pattern`(qwen 写乱、当键会裂)。
- openGauss 唯一约束**必配**(并发 upsert 防重复);Redis 与 openGauss 一致性(生命周期变更即失效)。
- claim **别用 CONCLUDED 边**(TOCTOU 双判)。
- 可疑 pending 的**粗分组只去抖/归组,绝不触发 gated**(provisional 只 escalate/monitor)。
- 迁移**必须有存档证据**重判归属(光按 technique 会把不同因错并)。
- **图里绝不放可复用规则**(pattern 全在 openGauss;图只台账+`pattern_id` 溯源)。
