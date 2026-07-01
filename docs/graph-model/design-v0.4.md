# 全场景图模型设计 · v0.4 增量（经验复用层）

> 增量自 v0.3（结构定稿）。**v0.4 只加一件事：经验复用闭环。** 完整模型以 [`../../model/graph_model.json`](../../model/graph_model.json) 为准（单一事实源），可视化见 `../../model/graph-model.html`。

## 为什么加这一层（评审澄清）

v0.3 的应用层能力被此前低估。实际上 v0.3 已经能做到：
- **应用层事实检索**：✅（HttpRequest / WafHit / Uri / Service / FileWriteEvent + `TARGETS`/`ON`/`CORRELATED_WITH`/`ABOUT`/`MAPS_TO`/`MATCHES`）
- **相似告警召回**：✅ 基本可以（某 URI/rule_id/payload/host_header 过去有没有类似攻击、是否反复出现 SQLi/XSS/Webshell、是否关联主机文件写入）

**真正缺的是"历史经验复用"**——回答：以前类似告警怎么判的？为什么判误报？当时用了哪些证据？处置建议是什么？适用/不适用条件是什么？这些应沉淀在 **Case / Finding / Experience** 层，而 v0.3 把 Case/Finding 标为延后，所以经验闭环不完整。

## v0.4 变更

1. **Case / Finding 从"延后"提为"一期最小落库"**（经验的来源）。Case 补 `case_id/created_at`，Finding 补 `finding_id/statement`。
2. **新增 `Experience`（L4 研判产物）** —— 经验复用核心：
   `exp_id, title, scenario, verdict_pattern, evidence_pattern, false_positive_reason, true_positive_reason, handling_advice, applicable_conditions, exclusion_conditions, confidence, source_case` + 时效 `valid_from/valid_to/updated_at`
   关系：`Experience DERIVED_FROM Case`｜`HAS_FINDING Finding`｜`APPLIES_TO Alert/Technique/Service/Uri`｜`HAS_EVIDENCE @observable`｜`MATCHES_PATTERN AttackPattern`
3. **新增 `AttackPattern`（L3 富化知识）** —— 相似召回的锚（组合特征，非单字段）：
   `pattern_id, pattern_key, tier, attack_type, technique_ids, normalized_uri, method, param_keys, payload_features, waf_rule_ids, file_write_features`
   关系：`Alert MATCHES_PATTERN AttackPattern`｜`Experience MATCHES_PATTERN AttackPattern`｜`HttpRequest MATCHES_PATTERN AttackPattern`（其他观测事件同理）
   > ★**泛化决策(待确认)**：评审原名 `AppPattern` + 应用层字段。按"全场景/非场景定制"铁律，已泛化为 `AttackPattern`（加 `tier`），使主机/身份/网络的经验召回走同一机制。如需保留 app 专属，改回即可。
4. **新增边类别 `experience`（经验复用）**。

## 经验复用检索流程（架构原则，写入模型 principles）

**不要把用户问题直接丢向量库。** 走混合：

```
当前 Alert
 → 抽取 HttpRequest/WafHit/Uri/Service/payload 特征
 → 生成 pattern_key / AttackPattern
 → 【图】召回相似 Alert / Case / Experience（准确找相似场景）
 → 【RAG】读经验文本（读懂历史判定理由/条件）
 → 【Agent】判断能否套用（applicable_conditions / exclusion_conditions）
```

分工：**图 = 找准相似场景；RAG = 读懂经验文本；Agent = 判断能否套用。** 图模型负责"结构化召回"这一环，文本理由走 RAG，判断留给 Agent。

## 覆盖结论
- 应用层**事实检索** ✅ · **相似告警召回** ✅ · **历史经验复用** ✅（本版补齐）
- 未纳入本版（可选后续）：`BusinessBaseline`（每 Service/Uri 的"正常业务"基线，用于"是否正常业务"的正向判定，区别于"历史判过没"）——需要再评估是否加。

---
_模型权威在 `model/graph_model.json`(v0.4)。下一步仍待你确认 AttackPattern 泛化 + 是否要 BusinessBaseline；确认后可锁模型、转入 skill 逐项深挖。_
