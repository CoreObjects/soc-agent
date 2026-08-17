#!/usr/bin/env bash
# 【Phase 0 / server2 侧】清空重置前的**只读盘点**:经验库 + poller + 图台账。
#
# ★经验库删了不可逆。这里先把条数、表名、以及**一份 pg_dump 备份**拿到手,
#   再谈清空。用户已同意清,但"清"和"没备份"是两件事。
#
# 用法(server2,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/reset-plan-agent.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
set -a; . ./.env; set +a
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback backup
FB="feedback/reset-plan-agent.out"
ferry_guard "$FB" "feedback: reset-plan-agent $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

# ★openGauss 是 podman 容器,宿主重启后恒 Exited(0) —— 连不上的头号原因就是它,
#   别去排查磁盘/OOM/配置。先看状态,必要时 podman start。
OG=opengauss

{
  echo "=== 【Phase 0 / server2】只读盘点 $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo "★只读 + 一份备份;不清任何东西"
  echo

  echo "########## [1] openGauss 活着吗 ##########"
  podman ps -a --format '{{.Names}}  {{.Status}}' 2>/dev/null | grep -i gauss | sed 's/^/   /' || echo "   (没找到容器)"
  if [ -x scripts/og_probe.sh ]; then
    echo "-- og_probe --"; bash scripts/og_probe.sh 2>&1 | tail -20 | sed 's/^/   /'
  fi
  echo

  echo "########## [2] 经验库有什么(★删了不可逆)##########"
  PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8 - <<'PY' 2>&1 | sed 's/^/   /'
import os
try:
    from soc_agent.config import Config
    cfg = Config.from_env()
    import psycopg2
    dsn = dict(host=os.environ.get("PG_HOST", "127.0.0.1"),
               port=os.environ.get("PG_PORT", "5432"),
               dbname=os.environ.get("PG_DB", "postgres"),
               user=os.environ.get("PG_USER", "gaussdb"),
               password=os.environ.get("PG_PASSWORD", ""))
    con = psycopg2.connect(**{k: v for k, v in dsn.items() if v})
    cur = con.cursor()
    cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1,2")
    tabs = cur.fetchall()
    print(f"表 {len(tabs)} 张:")
    for sch, t in tabs:
        try:
            cur.execute(f'SELECT count(*) FROM "{sch}"."{t}"')
            print(f"  {sch}.{t:<40} {cur.fetchone()[0]} 行")
        except Exception as e:
            print(f"  {sch}.{t:<40} 查不了:{str(e)[:60]}")
    con.close()
except Exception as e:
    print(f"!! 连不上或缺依赖:{type(e).__name__}: {str(e)[:200]}")
    print("   ★若是 Exited(0):podman start opengauss(宿主重启后的头号原因,别排查磁盘/OOM)")
PY
  echo

  echo "########## [3] 备份(清空之前必须有这一份)##########"
  BK="backup/opengauss-$(date -u '+%Y%m%d-%H%M%SZ' 2>/dev/null || echo now).sql"
  if podman exec "$OG" bash -lc 'command -v gs_dump || command -v pg_dump' >/dev/null 2>&1; then
    podman exec "$OG" bash -lc \
      'gs_dump -U ${PG_USER:-gaussdb} ${PG_DB:-postgres} 2>/dev/null || pg_dump -U ${PG_USER:-gaussdb} ${PG_DB:-postgres}' \
      > "$BK" 2>/dev/null
    echo "   → $BK  $(du -h "$BK" 2>/dev/null | cut -f1)  $(wc -l < "$BK" 2>/dev/null) 行"
    [ -s "$BK" ] || echo "   ⚠ 备份是空的!★没有可用备份就不要进 Phase 2"
  else
    echo "   ⚠ 容器里没有 gs_dump/pg_dump —— ★备份拿不到,Phase 2 清经验库这一步先停"
  fi
  echo "   (备份**不进 git**:见 .gitignore;它留在 server2 本地)"
  echo

  echo "########## [4] 研判台账(图里那一份,同样不可逆)##########"
  echo "   图 = ${NEO4J_URI:-?}"
  PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8 - <<'PY' 2>&1 | sed 's/^/   /'
try:
    from soc_agent.config import Config
    from soc_agent.graph.client import Neo4jGraph
    cfg = Config.from_env()
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    for label, q in (("告警总数", "MATCH (a:Alert) RETURN count(a) AS n"),
                     ("已研判(有 verdict_id)", "MATCH (a:Alert) WHERE a.verdict_id IS NOT NULL RETURN count(a) AS n"),
                     ("处置台账", "MATCH (r) WHERE 'Response' IN labels(r) RETURN count(r) AS n")):
        try:
            print(f"{label:<26} {g.run_cypher(q)[0]['n']}")
        except Exception as e:
            print(f"{label:<26} 查不了:{str(e)[:60]}")
    g.close()
except Exception as e:
    print(f"!! {type(e).__name__}: {str(e)[:200]}")
PY
  echo

  echo "########## [5] poller 在跑吗(Phase 1 停完必须为空)##########"
  pgrep -af 'poller' 2>/dev/null | sed 's/^/   /' || echo "   (无)"
  echo "-- crontab --"; crontab -l 2>/dev/null | grep -vE '^\s*#' | sed 's/^/   /' || echo "   (空)"
  echo
  echo "★结论要人看的两个数:①经验库总行数 ②备份文件是否非空。"
  echo "  备份为空 ⇒ **不要进 Phase 2**。"
  echo "=== done ==="
} 2>&1 | tee "$FB"
