# 第二类经验层:设计与现状

> 第二类经验（取证结果 ↔ 研判结论 ↔ 处置剧本 的映射）的**设计-of-record**。
> §1–§5 是设计原文;§3.3 是"指纹只召回/规则才验证"的分工铁律;§7 当前实现落点;§8 已知偏差与待补;§9 下一步。
> 状态:P1–P6 已建成 + 两分支真机验通（误报 e2e 8/8、威胁 e2e 12/12），但威胁收敛有洞（§8），daemon 未建（§9）。

## 1. 核心正名:一条流水线三阶段，不是两条独立路
> **快通道和慢通道不是并行的两条独立路。**（重要的事说三遍）

告警 → **取证** → **研判** → **处置**，每阶段"有经验用经验、没有走大模型"，**哪一步有经验就用哪一步**:

| 阶段 | 经验（0 LLM） | 大模型兜底 | 产出 |
|---|---|---|---|
| 取证 | skill recipe（第一类,已完成） | AgentInvestigator 现场写 Cypher | 取证结果 = findings |
| 研判 | 第二类:指纹/规则 匹配 findings | finalize_verdict LLM | 结论 T/F + 处置建议 |
| 处置 | 第二类:复用剧本模板 + 重绑实体 | Composer 现场组 | 真处置调用剧本 |

★经验检查在**「取证之后、对 findings 匹配」**（不是看原始告警字段）——这是与旧签名的本质分界:旧=看原始告警拟合;新=看取证结果、映射由千问学、**结构上不可能离线拟合靶场**（没真实取证结果就无从蒸馏）。

## 2. 三类经验（别混）
1. **离线取证脚本**（一类告警一取证法）—— `skills/*/recipe.py` + `SKILL.md`。**已完成。**
2. **取证结果 ↔ 研判结论 ↔ 处置剧本 的映射**（处置无也是处置）—— **本文主题**。由千问蒸馏、存 openGauss。
3. **历史研判结果 + 处置台账**（存图）—— `CONCLUDED→Verdict`、`LED_TO→ResponsePlan/STEP/Disposition`。**已完成。**

★第二类**一定是千问大模型沉淀的，不是离线拟合的**。findings 词典=方法论（第一类,离线 OK,与 recipe 同性质）;findings→结论/剧本 的映射=第二类（只千问学）。

## 3. 第二类 = 两形态

### 3.1 行为指纹（模糊召回）
从取证结果提炼的、**格式无关的规范化发现集合**，代表一次告警的"行为本质"。
- 构造（层层归一,对无关差异钝感、对决定性差异敏感）:取证结果=离散发现列表（一条发现=语义观察+原始证据,因果表达为发现本身、不依赖时序）;发现归一到**按告警类的发现词典（规范 finding ID）**免疫措辞;实例值抽象为占位符（`<USER>/<HOST>/<IP>`）免疫环境;连续值分桶免疫抖动;时间戳/PID/随机端口禁入;最终指纹=无序去重的规范发现集。
- 两类,蒸馏方式不同:
  - **威胁指纹**:蒸自真威胁案例=定性所依据的**红发现**集。命中后**不直接定性,进入威胁规则比对**。
  - **误报业务指纹**:蒸自误报案例=导致假告警的那个业务行为的**白发现**集（漏扫资产/合法签名软件/备份任务/白名单业务…）。命中→**直接判误报**+复用压/归档剧本,配抽样回看兜底。
- 匹配:同告警类分区内,**规范 finding ID 的倒排召回 + 决定性发现优先的加权重合度打分（不用全等）**。

### 3.2 威胁判定规则（确定性验证）
用受限**解释性语言（DSL）**描述的、可确定性执行的简短判定规则,表达真威胁的定性条件。
- 表达力克制:规范发现存在性 + 数值/桶比较 + AND/OR/NOT + 同源关联谓词,仅此。JsonLogic/CEL 类骨架,谓词绑定发现词典。
- 由千问研判真威胁时**顺手蒸馏**。业务侧写**解释器**:输入=规则+取证结果,输出=是否命中,确定、可解释。
- 存储:openGauss（JSONB 存表达式树+元数据）,热缓存供快通道执行。

### 3.3 ★指纹只召回、规则才验证（分工铁律）
- **指纹只负责"召回"**——哪些 finding **类型**在场（规范 ID 的加权重合度,非全等）。换实例（7 张票→12 张票、换服务名、换账号）finding 类型集不变 → 照样召回。
- **规则才负责"验证"**——值/桶/阈值的精确判断（`exists rc4`、`in bucket [high,massive]`、`gte fanout 5`、`not exists 机器账号`）全在 DSL 规则里,由千问蒸馏时用桶/阈值/存在性表达（别钉死裸值）。
- **误报指纹命中即终局**（降噪主力,量大从宽）;**威胁定性必须过规则这道确定性核验**（指纹只召回,规则才验证）。

## 4. 整体流程
```
告警 →【取证】skill recipe 有则复用 / 无则大模型现场查 → 取证结果(findings)
     →【研判】① 误报业务指纹命中 → 直接判 FP（复用剧本,终局）
              ② 威胁指纹命中 且 威胁规则命中 → 判 TP（复用剧本）
              ③ 其余（只中其一/都不中/误报命中但有威胁信号）→ 落 LLM 完整研判
                 （把"命中了哪条指纹/规则 + 它蒸自哪条告警的原始台账"作为已知信息喂进 LLM;
                   命中经验只存来源告警 VID(=origin_case_id),FALLTHROUGH 时按 VID 从图台账
                   捞回原告警字段/Verdict 结论·理由/处置 —— 台账永久保存,永久可捞）
     →【处置】命中经验 → 复用已沉淀剧本模板（重绑实体）
              走完整研判 → Composer 现场组
     →（回流）完整研判的新案例 → 蒸馏 指纹+规则+剧本 → 经验库增厚（越用越宽）
```
★核心逻辑:误报指纹命中即终局;威胁定性必须过规则确定性核验;命中经验直接复用剧本,只有完整研判才现场生成并回流沉淀。

## 5. 生死线（质量与生命周期）
- 入库前过"考试":回放原案例**必须命中** + 历史反类案例回归**不得误命中**（威胁别中历史 FP,误报别中历史 TP）,过关才 active。语料=`cases` 表存每案例的 findings 快照（图台账不存 findings,故另存）。
- 记命中数/被人工推翻数;被推翻的降级"仅提示",长期零命中的归档。

## 6. 研判决策 + 处置策略
- **研判（D2）**:`威胁指纹 ∧ 威胁规则 都命中`→ TP;`误报指纹命中 且 无任何威胁信号`→ FP（★安全否决:同时有威胁信号→不自动、落 LLM,防模仿良性）;其余→落 LLM。
- **★处置执行(坐实自动、可疑人审)**:
  - `true_positive` 且 confidence ≥ 阈值（如 0.8）→ **自动 approve+execute**（走 appliance /execute,真做）。
  - `suspicious`（或 TP 低置信）→ 组 proposed 计划,**留人 respond_cli 审**。
  - `false_positive/benign` → 无处置单例。
  - 安全阀=置信阈值 + 现成 NEVER-TOUCH（DC/CA/krbtgt/传感器提议时已降级 escalate）。
- **台账不需加新节点**:`(:Verdict)-[:LED_TO]->(:ResponsePlan{status})-[:STEP]->(:Disposition{status})` 的 **status 就是"是否处置/是否审核"的记录**（proposed=待处置/待审、approved=审过、executed=已处置、rolled_back=已回退）。"处置过没"=看 plan status;"研判过没"=有无 CONCLUDED 边。

## 6.5 研判台账图模型（2026-07-21 完善，真机 e2e-threat 25/25 验通）
整条链在图里一次查回，含复用溯源：
```
LLM 研判:  (:Alert)-[:CONCLUDED{method:'llm', at,confidence,summary,rationale}]->(:Verdict)
                                                     -[:LED_TO]->(:ResponsePlan)-[:STEP]->(:Disposition)-[:ON]->实体
           (:Alert)-[:HAS_FINDING]->(:Finding{finding_key=uid#fid, finding_id,attrs(json),polarity,evidence_ref})  # 取证入图
复用(AUTO): (:Alert2)-[:CONCLUDED{method:'reuse'}]->(旧 Verdict)   # 直接指向源判例 Verdict,下游完全复用(不新建/不写)
           (:Alert2)-[:HAS_FINDING]->(:Finding …)                 # 只写自己的取证
```
- **取证入图**:findings 作 `:Finding` 挂 Alert(分析层,永久;prune 不碰);之前只在 openGauss cases,链缺这节。
- **真复用**:经验记 `origin_verdict_id`(distill 从 `result.verdict.verdict_id` 存);复用告警 CONCLUDED 直接指向旧 Verdict、`method='reuse'`(coalesce 保护源判例 llm 标记不被降级)、下游处置完全复用。`origin_verdict_id` 空(旧经验)→ 优雅退回新建。
- **展示**:从复用告警一条 Cypher 查回 源告警 + 两边取证 + 处置(e2e 实证 origin/a2取证/a1取证/处置 全查回)。
- **ResponsePlan+Disposition 未合并**(概念上是处置的语义+执行两面、可合;但真合=重构审批/执行/回退状态机,非必须,按用户决定不改)。
- 落点:`graph/client.py`(build_write_statements 复用分支 + `_finding_stmts` + Finding 约束)、`models.py`(InvestigationResult.reuse_verdict_id)、`cli.py`(_reuse_* 带 origin_verdict_id)、`experience/{store,opengauss,distill}.py`(origin_verdict_id round-trip)、`reset_pristine`(连带清 :Finding)。

## 7. 实现落点与现状（P1–P6 已建成、真机验通）
- `soc_agent/forensics.py`:`Finding`/`Forensics`/`coerce`/`from_legacy`。
- `soc_agent/experience/{dsl,fingerprint,matching,store,opengauss,cases,distill,exam,consult}.py`。
- `cli.py`:`collect_forensics` / `Pipeline` / `build_pipeline` / `run_pipeline`（取证→consult→AUTO 短路 | FALLTHROUGH 走 LLM→TP 组 Composer 处置→写台账→存案例→回流 sediment）。
- 存储:openGauss（`soc.experience` / `soc.cases`,JSON 用 text 存;进程内缓存 `ExperienceCache`,不上 Redis）。
- **先行迁移 kerberoast + lsass 两 recipe 的 findings 词典**;其余 14 recipe 走 `from_legacy`（永远走 LLM、零 regression）,逐 skill 迁移即铺开。
- 真机:误报 e2e 8/8、威胁 e2e 12/12（新研判机 9b）。

## 8. 偏差修复现状（2026-07-20 一轮修完 Fix 1–4a）
- ✅ **指纹越权 → 威胁收敛脆**（`826381a`）:曾 `fingerprint.py::_fid_matches` 逐个校验 canon attr **值一致**（`spn_fanout.distinct_targets=7` 钉死）→ 换实例掉链。**已修:`match` 加 `recall_only`,`matching.fingerprint_hit` 让威胁指纹走纯 finding-ID 召回,值/桶判断全归 DSL 规则（§3.3）。误报半不动（仍比对 src_image 等白标记,守红线）。**
- ✅ **命中信息喂 LLM 从"计数"→"哪条+为什么+原始台账"**（`348fbb1`+`f353768`):命中经验只存来源告警 VID（`origin_case_id`=alert_uid,已存,不加副本）;FALLTHROUGH 时 `cli._recall_hit_ledgers` 按 VID 用 `graph.recall_ledger` 从图台账捞回（★summary/rationale 在 CONCLUDED 边;`__no_op__` 单例过滤）,`consult.MatchReport.as_context` 逐条渲染。顺带补存被丢的 `note`（distill→Experience→openGauss,幂等 ALTER 迁旧表）。
- ✅ **收敛守卫**（`530af05`）:`exam.sediment` 在 add 前查"已有 active 同类经验能否 fire 在这些 findings 上",能就不新增、只记一次命中（替代删掉的 `pattern_id` 去重;防批量重派生/竞态膨胀）。
- ⏳ **生命周期只做了一半**:`bump_hit` 已接（AUTO 命中 + 收敛复用都 +1）。**未接:被人工推翻→`bump_override`+降级 `hint_only`、长期 0 命中→`archived`。** 卡点=处置计划(plan_id)与所复用经验(exp_id)之间无干净链接,且 `respond_cli` 走 Neo4j 图、经验库在 openGauss（跨库）;0 命中归档还需 age 策略。→ **留到 daemon 阶段一并设计（lifecycle 的自然归属）,见 §9。**
- **误报那半基本符合设计**（阈值 0.8、单门、占位符抽象、值比对未动）→ 稳。

## 9. 下一步（本文之后单独立项）
- **告警轮询 daemon**:轮询未研判告警（`NOT (a)-[:CONCLUDED]->()` + settle 窗）→ 逐条跑 `run_pipeline` → 台账+沉淀。单实例、串行（收敛修好后稳态几乎全 AUTO,冷启动量=模式数不是告警数）。毒告警死信、`--once/--selftest/常驻`。骨架照搬被删的那版、接到新 `run_pipeline`。
- **并发**:vLLM 能并发（max-num-seqs 256）,客户端唯一阻塞=共享 psycopg2 连接（要连接池/每 worker 一连接）+ `ExperienceCache` 加锁。先串行、按需再上。
- **生命周期（§8 未接的那半）在此并入**:daemon 是周期性维护的自然归属 —— 需先给 plan↔exp 建干净链接（AUTO 复用时把 exp_id 落到台账/plan 属性,而非埋在 rationale 文本）,`respond_cli` reject/rollback 时按之 `bump_override`+跨库降级 `hint_only`;再加"created_at 够老且 0 命中→archived"的归档巡检。
- 顺序:① 修威胁收敛（§8,✅ 已完成 Fix 1–4a）→ ② 真告警批量定量验复用（沉淀行数 vs AUTO 命中率、FALLTHROUGH 上下文非空）→ ③ daemon 串行版（并入生命周期链接）→ ④ 按需并发/放开处置。
