"""server2 预检:验证图 / LLM 连通,并列出可研判的告警(给 alert_uid)。

用法: .venv/bin/python scripts/preflight.py
输出请直接贴给我(别 commit 进公开仓——含真实端点/告警标识)。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_agent.config import Config  # noqa: E402


def main():
    root = Path(__file__).resolve().parents[1]
    cfg = Config.from_env(dotenv_path=str(root / ".env"))
    print("== 配置 ==")
    print("NEO4J_URI   :", cfg.neo4j_uri or "(空!需填)")
    print("LLM_API_BASE:", cfg.llm_api_base or "(空!需填)", "| model:", cfg.llm_model)

    # ---- 图连通 + 列 Kerberoast 告警 ----
    from soc_agent.graph.client import Neo4jGraph
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        n = g.run_cypher("MATCH (a:Alert) RETURN count(a) AS n")[0]["n"]
        print(f"\n== 图 == 连通 OK,:Alert 共 {n} 条")
        rows = g.run_cypher(
            "MATCH (a:Alert) WHERE any(t IN a.technique_ids WHERE t STARTS WITH 'T1558.003') "
            "RETURN a.alert_uid AS uid, a.technique_ids AS tech, a.rule_id AS rule LIMIT 5")
        if rows:
            print("Kerberoast(T1558.003)告警样例(挑一个 uid 研判):")
            for r in rows:
                print("  ", r["uid"], r["tech"], "rule=", r["rule"])
        else:
            print("无 T1558.003;随便列几条:")
            for r in g.run_cypher("MATCH (a:Alert) RETURN a.alert_uid AS uid, a.technique_ids AS tech LIMIT 5"):
                print("  ", r["uid"], r["tech"])
    finally:
        g.close()

    # ---- LLM 连通 + native tool calling ----
    from soc_agent.llm.qwen import QwenClient
    llm = QwenClient(base_url=cfg.llm_api_base, model=cfg.llm_model, api_key=cfg.llm_api_key)
    r = llm.chat([{"role": "user", "content": "只回复两个字:就绪"}])
    print(f"\n== LLM == 连通 OK,回复={r.content[:40]!r} finish={r.finish_reason}")

    print("\n预检通过 → 研判: bash scripts/run_investigation.sh <alert_uid>")


if __name__ == "__main__":
    main()
