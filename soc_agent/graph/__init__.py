"""graph —— Neo4j 客户端与只读守卫。

- guard: run_cypher 的只读守卫(第一道防线;第二道 = READ 会话)。
- client(后续): 连接 server1、读事实、遍历原语、经专用写路径写经验层(读写分权)。
"""
