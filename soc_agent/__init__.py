"""soc-agent —— 告警研判 + 处置引擎(server2)。

只跟 v3 知识图谱(server1,bolt)+ 本地 LLM 交互,headless。
分层(见 docs 设计):
  schema         —— 从 model/graph_model.json 自动生成 v3 schema 文本,注入 LLM 提示
  graph          —— Neo4j 客户端:只读事实 + 遍历原语 + 写经验(读写分权)
  llm            —— 可插拔 Investigator 接口 + qwen(OpenAI 兼容)实现
  skills_runtime —— 加载 skill / 跑 recipe / 跑模式判别 / 沉淀回写
  orchestrator   —— 分流路由 + 慢通道调查循环(取证→还原→定性→处置)
  disposition    —— 处置 Tool 适配 + 护栏 + 回退 + 审计
  tools          —— 暴露给 LLM 的工具
"""

__version__ = "0.1.0"
