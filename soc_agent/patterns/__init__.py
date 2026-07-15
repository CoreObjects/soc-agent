"""攻击模式规则子系统(图外经验:攻击模式→处置规则)。

分工(硬边界):
- 判别 spec(skills/<skill>/discriminator.py,离线 Claude 写)把证据确定性投影成【分层判别特征签名】;
- 规则(openGauss 权威 + Redis 热读,运行态确定性生成、去重)= 签名 → verdict+处置模板;
- 图(Neo4j)只存台账/情报,挂 pattern_id 溯源,不放规则本体。

本包:signature(签名规范化)· rule(规则/模板 dataclass)· repository(仓储接口 + 内存 fake)。
openGauss/Redis 具体适配另建。
"""
