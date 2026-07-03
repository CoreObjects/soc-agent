# soc-agent

安全告警研判 Agent —— 以**本体知识图谱 + GraphRAG 上下文召回 + 大模型自主研判**，对 SOC 告警做自动化研判与攻击链还原。

> 🚧 早期阶段：架构设计进行中，尚无实现代码。设计见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 这是什么

- 面向 SOC 告警的**自主研判 Agent**：从单条告警出发，在图上召回上下文、还原攻击链、判定真伪、给出处置建议。
- 以真域靶场（GOAD）产出的真实日志 / 告警作为验证数据源。
- **本仓库跑在 server2（SOC 大脑，挨着本地大模型）**，通过 bolt 远程**查询**图，不负责填图。

## 仓库分工（清晰的部署边界，避免混装）

| 仓库 | 角色 | 部署 |
|---|---|---|
| **soc-agent（本仓库）** | 研判 Agent（查图）+ **图模型权威源** `model/graph_model.json`（Agent 要靠它决定怎么查）+ 图 viz + 设计/研究文档 | **只 server2** clone |
| **[CoreObjects/soc-graph-ingest](https://github.com/CoreObjects/soc-graph-ingest)** | 填图 pipeline（读 ES → 写 Neo4j），按本仓库的图模型契约实现 | **只 server1** clone |

- **图引擎（Neo4j）** = server1 的 Docker 容器，不在任何代码仓。
- 图模型 JSON 只此一份（本仓库权威）；pipeline 侧按契约实现、不复制 JSON，避免两份漂移。改模型 → 改本仓库 `model/graph_model.json` + 同步 pipeline 的 `ingest/cypher.py` 白名单/映射 spec。

## 状态

初始化中。架构与技术选型待对齐（见 `docs/DESIGN.md`），确定后再落地代码。

## 配置与密钥

所有密钥 / 端点一律走**环境变量**，见 [`.env.example`](.env.example)。
**切勿把任何密钥、令牌、内网地址、真实 IP 提交进仓库。**

## 许可

保留所有权利（All rights reserved）。未经许可，不得复制、修改或再分发。
