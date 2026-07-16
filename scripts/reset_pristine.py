"""全量对称重置 → 最初态(只有事实、零研判)。图台账 与 openGauss 规则【一起清】,保持两边同步。

清:
- 图(Neo4j):所有 :Verdict / :Disposition / :ResponsePlan 节点 + 其边(CONCLUDED/LED_TO/STEP/ON)—— 研判/处置台账。
  ★事实(Alert/Event/账号/主机… + ingest 的所有边)一律不动。
- openGauss:app.patterns 全清 —— 攻击模式规则(可复用经验,研发阶段可重建)。

★三态一致(真执行引入的第三态=range 真实状态,如禁掉的账号/隔离规则/nft):本脚本在 server2,碰不到 range 态。
  清图【前】先对账:若台账里有已执行处置,警告必须先在靶场那台跑 `bash deploy/setup/61-response-reset.sh`
  (blunt 恢复 range 态:重启用 lab 账号/删 SOC-Isolate 规则/flush soc-response nft),否则清图后这些真实副作用
  变成孤儿、下次攻击剧本复现不了(攻击者登不上)。顺序:range 态 → 图台账 → openGauss。

用途:研发阶段每次小测收尾、或这台(ephemeral)下线前跑一次;避免"图脏了一堆已研判告警、openGauss 经验却没了"两边对不上。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
from soc_agent.response.appliance_client import ApplianceClient

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("neo4j=%s  og=%s db=%s enabled=%s  appliance=%s"
      % (cfg.neo4j_uri, cfg.og_host, cfg.og_db, cfg.og_enabled, cfg.response_url or "OFF"))

# ---- 图:清研判台账,保留事实 ----
_LEDGER = "n:Verdict OR n:Disposition OR n:ResponsePlan"
graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
try:
    # ★对账硬拦:台账有【已执行】(未回退)处置 → range 真实态是脏的 → 中止,先恢复 range 再清图。
    #   (server2 碰不到 ansible,不能自动恢复;恢复走靶场那台。避免"图清了、账号还禁着、状态看不懂"。)
    executed = graph.run_cypher(
        "MATCH (d:Disposition) WHERE d.status='executed' RETURN count(d) AS n")[0]["n"]
    if executed:
        client = ApplianceClient(cfg.response_url, cfg.response_token)
        if client.enabled:
            # ★一台机器搞定:server2 直接调靶场 /reset 恢复 range 态,成功了再清图(顺序 range→图→OG)
            print("台账有 %d 个已执行处置 → 调靶场 /reset 恢复 range 态(%s)..." % (executed, cfg.response_url))
            try:
                r = client.reset(accounts=True)
            except Exception as e:
                print("⛔ 调靶场 /reset 失败:%s → 中止,未清图(检查 RESPONSE_URL 连通 / 服务是否起)。" % e)
                sys.exit(3)
            if r.get("status") != "executed":
                print("⛔ 靶场复位未成功:%s → 中止,未清图。" % r)
                sys.exit(3)
            print("  ✅ 靶场已复位 range 态。")
        elif os.environ.get("FORCE") != "1":
            print("⛔ 中止:台账有 %d 个【已执行】处置(禁账号/隔离/nft 等 range 副作用),未清图。" % executed)
            print("   没配处置面 appliance(RESPONSE_URL)→ 得手动恢复 range 再清,二选一:")
            print("     · 精确回退:server2 `respond_cli rollback <plan>` → 靶场 `bash deploy/setup/60-response-run.sh`")
            print("     · blunt:靶场 `bash deploy/setup/61-response-reset.sh`(账号加 RESET_ACCOUNTS=1)")
            print("   或配 RESPONSE_URL 让本脚本自动调 /reset;确认已恢复要强清:  FORCE=1 bash scripts/reset_pristine.sh")
            sys.exit(2)   # finally 会 close;SystemExit 传播 → 不清图、不清 OG(顺序卡死)
        else:
            print("⚠️ FORCE=1:跳过恢复,强清 %d 个已执行处置的台账(请自行确认 range 态已恢复)。" % executed)

    n_before = graph.run_cypher("MATCH (n) WHERE " + _LEDGER + " RETURN count(n) AS n")[0]["n"]
    graph.run_write("MATCH (n) WHERE " + _LEDGER + " DETACH DELETE n")   # DETACH 连带删 CONCLUDED/LED_TO/STEP/ON
    n_after = graph.run_cypher("MATCH (n) WHERE " + _LEDGER + " RETURN count(n) AS n")[0]["n"]
    alerts = graph.run_cypher("MATCH (a:Alert) RETURN count(a) AS n")[0]["n"]
    conc = graph.run_cypher("MATCH ()-[c:CONCLUDED]->() RETURN count(c) AS n")[0]["n"]
    print("图台账:Verdict+Disposition+ResponsePlan %d → %d;残留 CONCLUDED 边=%d(应0);事实 Alert=%d(保留)"
          % (n_before, n_after, conc, alerts))
finally:
    graph.close()

# ---- openGauss:清规则 ----
if cfg.og_enabled:
    import psycopg2
    c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                         user=cfg.og_user, password=cfg.og_password)
    c.autocommit = True
    tbl = "%s.patterns" % cfg.og_schema
    with c.cursor() as cur:
        try:
            cur.execute("SELECT count(*) FROM " + tbl); r0 = cur.fetchone()[0]
            cur.execute("DELETE FROM " + tbl)
            cur.execute("SELECT count(*) FROM " + tbl); r1 = cur.fetchone()[0]
            print("openGauss 规则:%d → %d" % (r0, r1))
        except psycopg2.errors.UndefinedTable:
            print("openGauss:%s 尚不存在 → 本就无规则" % tbl)
    c.close()
else:
    print("openGauss 未启用(内存fake)→ 跳过(重启进程即空)")

print("PRISTINE OK:图台账 + openGauss 规则已双清,恢复'只有事实、零研判'最初态,两边同步")
