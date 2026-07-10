# soc-agent

安全告警研判 Agent —— 以**本体知识图谱 + GraphRAG 上下文召回 + 大模型自主研判**，对 SOC 告警做自动化研判与攻击链还原。

> 🚧 建设中（P1：慢通道单类闭环）。架构见 plan / `docs/`，研判知识见 `docs/research/alert-investigation-playbooks.md`。

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

## 运行

**本机（纯逻辑单测，不需服务器）：**
```
python -m venv .venv && ./.venv/bin/pip install -q pytest
./.venv/bin/python -m pytest        # 引擎逻辑全绿
```

**server2（真研判，接 server1 图 + 本地 qwen）：**
```
cp .env.example .env    # 填 NEO4J_*（→server1）、LLM_API_BASE（→本地 qwen :8000）
python scripts/preflight.py                     # 验连通 + 列可研判的 alert_uid
bash scripts/run_investigation.sh <alert_uid>   # 慢通道研判一条告警（结果写回图经验层）
```

## 引擎结构（`soc_agent/`）

| 模块 | 作用 |
|---|---|
| `schema` | 从 `model/graph_model.json` 生成 v3 schema，注入 LLM 提示 |
| `graph` | Neo4j 客户端：只读取证（READ 事务 + 守卫双保险）+ 写回经验层 |
| `llm` | 可插拔 Investigator 接口 + qwen（OpenAI 兼容，`trust_env=False`）|
| `skills_runtime` | 加载 skill（`skills/<layer>/<type>/SKILL.md` 方法论）+ 按告警选取 |
| `tools` | 给 LLM 的工具：`run_cypher`（过守卫）、`finalize_verdict`（终结）|
| `orchestrator` | 慢通道自主研判循环（schema+方法论→系统提示→tool-calling→结论）|
| `cli` | 研判单条告警：取告警→seed→研判→写回图 |

**知识 = skills**（`skills/`，方法论初始态，取证脚本/模式判别后续沉淀）。经验分两处：图里放每条告警历史台账（`Verdict`/`Disposition`）；可复用经验（取证脚本、模式判别→处置）在 skills，不在图。

## 配置与密钥

所有密钥 / 端点一律走**环境变量**，见 [`.env.example`](.env.example)。
**切勿把任何密钥、令牌、内网地址、真实 IP 提交进仓库。**

## 许可

保留所有权利（All rights reserved）。未经许可，不得复制、修改或再分发。
