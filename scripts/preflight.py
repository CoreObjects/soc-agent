"""server2 预检:验证图 / LLM 连通,并列出可研判的告警(给 alert_uid)。

用法: .venv/bin/python scripts/preflight.py
输出请直接贴给我(别 commit 进公开仓——含真实端点/告警标识)。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_agent.config import Config  # noqa: E402


def _mask(url):
    """隐去 host,只留 scheme+port —— 避免真实地址进公开仓。"""
    import re
    if not url:
        return "(空!需填)"
    m = re.match(r"(\w+://)([^:/]+)(:\d+)?", url)
    return f"{m.group(1)}***{m.group(3) or ''}" if m else "***"


def main():
    root = Path(__file__).resolve().parents[1]
    cfg = Config.from_env(dotenv_path=str(root / ".env"))
    print("== 配置(端点已打码)==")
    print("NEO4J_URI   :", _mask(cfg.neo4j_uri))
    print("LLM_API_BASE:", _mask(cfg.llm_api_base), "| model:", cfg.llm_model)

    # ---- 依赖守卫:别用系统 python3 裸跑(会 ModuleNotFoundError: neo4j)----
    try:
        import neo4j  # noqa: F401
    except ModuleNotFoundError:
        print("\n!! 依赖未装(neo4j)。别用系统 python3 裸跑,用自带 venv 的入口:")
        print("     bash scripts/selftest.sh          # 批量自测(自动建 venv,推荐)")
        print("     # 或手动:python3 -m venv .venv && ./.venv/bin/pip install -e .")
        print("     #         再 .venv/bin/python scripts/preflight.py")
        raise SystemExit(1)

    # ---- 图连通 + 列告警 ----
    from soc_agent.graph.client import Neo4jGraph
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        n = g.run_cypher("MATCH (a:Alert) RETURN count(a) AS n")[0]["n"]
        print(f"\n== 图 == 连通 OK,:Alert 共 {n} 条")
        print("按技战术分组(每类给一个样例 uid,挑来研判):")
        rows = g.run_cypher(
            "MATCH (a:Alert) UNWIND coalesce(a.technique_ids,['(none)']) AS t "
            "WITH t, count(*) AS n, collect(a.alert_uid)[0] AS sample "
            "RETURN t AS tech, n, sample ORDER BY n DESC LIMIT 20")
        for r in rows:
            print(f"  {str(r['tech']):18} 共{r['n']:>6}  样例 uid={r['sample']}")
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
