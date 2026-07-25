"""全量重置 → 最初态(只有事实、零研判)。清【图研判/处置台账】+ 复原【靶场真实状态】。

清:
- 图(Neo4j):所有 :Verdict / :Disposition / :ResponsePlan 节点 + 其边(CONCLUDED/LED_TO/STEP/ON)—— 研判/处置台账。
  ★事实(Alert/Event/账号/主机… + ingest 的所有边)一律不动。

★三态一致(真执行引入的第三态=range 真实状态,如禁掉的账号/隔离规则/nft):清图【前】先对账——
  若台账里有已执行处置,自动调 appliance `/reset`(或警告手动跑靶场 `bash deploy/setup/61-response-reset.sh`)
  复原 range 态,否则清图后这些真实副作用变成孤儿、下次攻击剧本复现不了。顺序:range 态 → 图台账。

用途:研发阶段每次小测收尾、或重构前跑一次,从干净态起步。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 从脚本位置推导仓根,不硬编码 ~/soc-agent
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
from soc_agent.response.appliance_client import ApplianceClient

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("neo4j=%s  appliance=%s" % (cfg.neo4j_uri, cfg.response_url or "OFF"))

# ---- 图:清研判台账,保留事实 ----
# ★含 :Finding —— 取证结果是研判产物(挂在 Alert 上的分析层),reset 要连带清,否则残留脏取证。
_LEDGER = "n:Verdict OR n:Disposition OR n:ResponsePlan OR n:Finding"
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
    print("图台账:Verdict+Disposition+ResponsePlan+Finding %d → %d;残留 CONCLUDED 边=%d(应0);事实 Alert=%d(保留)"
          % (n_before, n_after, conc, alerts))
    # ★清 poller 运行态(poller_skip/poller_retries 是研判运行标记、非事实)→ 让全部告警重新可捞
    poison = graph.run_cypher(
        "MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n")[0]["n"]
    graph.run_write("MATCH (a:Alert) WHERE a.poller_skip IS NOT NULL OR a.poller_retries IS NOT NULL "
                    "REMOVE a.poller_skip, a.poller_retries")
    print("清 poller 运行态:毒告警停放 %d → 0(poller_skip/poller_retries 已清,全部告警重新可捞)" % poison)
finally:
    graph.close()

# ---- openGauss:清第二类经验库 + 案例库(未配 OG → 内存,重启即空,跳过)----
if cfg.og_enabled:
    try:
        from soc_agent.experience.opengauss import wipe
        ne, nc = wipe(cfg)
        print("openGauss 经验库:experience %d → 0;cases %d → 0" % (ne, nc))
    except Exception as e:
        print("⚠️ openGauss 清理失败(经验库未清,不影响图台账):%s" % str(e)[:120])
else:
    print("openGauss:未配 OG_HOST → 经验层在内存(重启即空),跳过")

print("PRISTINE OK:图台账已清(靶场态经 appliance /reset 复原)+ openGauss 经验库已清,恢复'只有事实、零研判'最初态")
