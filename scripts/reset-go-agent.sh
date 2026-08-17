#!/usr/bin/env bash
# 【清空重置 / server2 侧】停 poller → 备份经验库 → 清经验库 → 交回要人手改的两处。
#
# ★**默认 dry-run**,只打印。加 --execute 才真动手。
#
# ★为什么 server2 必须做:靶场那边重建 Neo4j 之后**密码变了**,
#   poller 还拿旧密码连 → 连不上,而且它会一直重试、看起来像"研判不工作"。
#
# ★备份不用 gs_dump:上一版栽在"容器里没有 gs_dump/pg_dump"。
#   而经验库只有三张表(experience / cases / payload_cases),
#   直接用 soc-agent 自己那条连接(`OG_*` 配置)把行 dump 成 JSON 就够了 ——
#   要的是"能恢复",不是"要标准 dump 格式"。
#
# 用法(server2,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/reset-go-agent.sh              # dry-run
#   bash scripts/reset-go-agent.sh --execute    # 真做
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
EXEC=0; [ "${1:-}" = "--execute" ] && EXEC=1
mkdir -p feedback backup
FB="feedback/reset-go-agent.out"
ferry_guard "$FB" "feedback: reset-go-agent$([ $EXEC = 1 ] && echo ' EXECUTED') $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

run() {
  if [ "$EXEC" = "1" ]; then echo "   \$ $*"; eval "$@" 2>&1 | sed 's/^/     /'
  else echo "   [dry-run] $*"; fi
}

{
  echo "=== 清空重置(server2 侧) $([ $EXEC = 1 ] && echo '★★ EXECUTE ★★' || echo '(dry-run,不动手)') $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo

  echo "########## [1] 停 poller(靶场重建图之后它拿旧密码会一直连不上)##########"
  echo "-- 我们自己的 poller --"
  pgrep -af 'soc_agent|poller_cli|run_poller' 2>/dev/null | sed 's/^/   /' || echo "   (无)"
  echo "   ★注意:上一轮 pgrep 匹配到的 973 edac-poller 是**内核 EDAC 进程**,不是我们的,别动。"
  run "pkill -f 'soc_agent' || true"
  echo "-- crontab --"
  crontab -l 2>/dev/null | grep -vE '^\s*#' | sed 's/^/   /' || echo "   (空)"
  echo

  echo "########## [2] 经验库:先量再备份(★备份不用 gs_dump,直接 dump 行)##########"
  PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8 - "$EXEC" <<'PY' 2>&1 | sed 's/^/   /'
import json, os, sys, datetime
EXEC = sys.argv[1] == "1"
TABLES = ("experience", "cases", "payload_cases")
try:
    from soc_agent.config import Config
    cfg = Config.from_env()
    print(f"OG_HOST={cfg.og_host or '(空)'} OG_PORT={cfg.og_port} "
          f"OG_DATABASE={cfg.og_database} OG_USER={cfg.og_user}")
    if not cfg.og_host:
        print("!! OG_HOST 为空 ⇒ 经验层本来就降级成「永远走 LLM」,没有东西要清。")
        raise SystemExit(0)
    import psycopg2
    con = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_database,
                           user=cfg.og_user, password=cfg.og_password, connect_timeout=10)
    cur = con.cursor()
    # ★schema 名靠**发现**,不猜(上一版就是猜出来的错)
    cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_name = ANY(%s)", (list(TABLES),))
    found = cur.fetchall()
    if not found:
        print(f"!! 三张表({', '.join(TABLES)})一张都没找到 —— 经验库是空的/没建过。")
        raise SystemExit(0)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
    path = os.path.join("backup", f"opengauss-{stamp}.json")
    dump, total = {}, 0
    for sch, t in found:
        cur.execute(f'SELECT count(*) FROM "{sch}"."{t}"')
        n = cur.fetchone()[0]
        total += n
        cur.execute(f'SELECT * FROM "{sch}"."{t}"')
        cols = [d[0] for d in cur.description]
        dump[f"{sch}.{t}"] = {"columns": cols,
                              "rows": [[str(v) for v in r] for r in cur.fetchall()]}
        print(f"{sch}.{t:<20} {n} 行")
    print(f"合计 {total} 行")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(dump, f, ensure_ascii=False)
    sz = os.path.getsize(path)
    print(f"★备份 → {path}  {sz} 字节")
    if total > 0 and sz < 100:
        print("!! 备份文件疑似为空 —— **不要继续清**"); raise SystemExit(3)
    if not EXEC:
        print("[dry-run] 不清表。要清请加 --execute")
    else:
        for sch, t in found:
            cur.execute(f'TRUNCATE TABLE "{sch}"."{t}"')
            print(f"已清空 {sch}.{t}")
        con.commit()
        for sch, t in found:
            cur.execute(f'SELECT count(*) FROM "{sch}"."{t}"')
            print(f"复核 {sch}.{t} = {cur.fetchone()[0]} 行")
    con.close()
except SystemExit:
    raise
except Exception as e:
    print(f"!! {type(e).__name__}: {str(e)[:240]}")
    print("   ★若是连不上:openGauss 是 podman 容器,宿主一重启就恒 Exited(0) ——")
    print("     `podman start opengauss` 即可,别去排查磁盘/OOM/配置。")
    raise SystemExit(1)
PY
  RC=$?
  [ "$RC" = "0" ] || { echo "   ⚠ 经验库这一步没成功(退出码 $RC),**先别往下走**"; }
  echo "   (备份落 backup/,已加进 .gitignore,不进 git)"
  echo

  echo "########## [3] 要**人手**改的两处 ##########"
  echo "   ① .env 的 NEO4J_PASSWORD 改成靶场 reset-go.sh --execute 打出来的**新密码**"
  echo "      当前 .env 里是:$(grep -E '^NEO4J_PASSWORD=' .env 2>/dev/null | sed 's/=.*/=<已隐去>/' || echo '(没有这一行)')"
  echo "      核对连通:PYTHONPATH=. $PY -c \"from soc_agent.config import Config;"
  echo "                from soc_agent.graph.client import Neo4jGraph as G;"
  echo "                c=Config.from_env();g=G(c.neo4j_uri,c.neo4j_user,c.neo4j_password,c.neo4j_database);"
  echo "                print(g.run_cypher('RETURN 1 AS ok'))\""
  echo "   ② 等靶场那边灌进一批数据、图里有 :Alert 了,再起 poller"
  echo

  echo "########## [4] 起 poller(★冷启动:经验库空了,命中率必然 0)##########"
  echo "   经验库清空之后,第一级签名复用命中率 **0** ⇒ 每条告警都会走到大模型。"
  echo "   所以**先 2 并发**,看住 vLLM 负载再往上加;头几十条结论要人抽查"
  echo "   (没有历史台账可召回,深度研判少一层输入)。"
  echo "   用稳定入口(别新造 wrapper):"
  echo "     bash scripts/poller-fix-restart.sh 300 2"
  echo "   ★现在**先不要起** —— 图还是空的,起了只会空转。等靶场灌上数据。"
  echo "=== done ==="
} 2>&1 | tee "$FB"
