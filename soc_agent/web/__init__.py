"""soc-agent Web 层:研判+处置控制台的第一个 HTTP/API。

- queries.py  纯 Cypher builder(只读查询,离线单测)。
- deps.py     进程级单例依赖(graph/exp_store/appliance/llm/token 门)。
- routes/     读(alerts/stats/experience)+ 写(plans 审批)+ config + auth + chat。
- app.py      FastAPI 工厂 + 前端 dist 静态托管。

★读走现成查询(graph/client.py、experience/store.py),写走现有状态机(respond_cli/ledger + appliance),
API 只做 HTTP 薄封,护栏在被封函数内层,不自建执行路径。与 poller 分进程、同读一套 Neo4j/openGauss。
"""
