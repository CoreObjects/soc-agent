#!/usr/bin/env bash
# 【清空重置 / server2】清空经验库 —— **先备份再清**,用现成的 `opengauss.wipe()`。
#
# ★为什么单独一个脚本:上一版 `reset-go-agent.sh` 判成"没东西要清"是错的 ——
#   它的 `Config.from_env()` **没传 dotenv_path**,`.env` 里的 `OG_*` 全取空
#   ⇒ `OG_HOST=(空)` ⇒ 以为库没配。实际库里有 **10.3 万案例 + 28 条指纹**。
#   (`Config.from_env()` 只读 os.environ,`.env` 不会自动进环境 —— config.py:81。)
#
# ★清空动作用**现成的** `soc_agent.experience.opengauss.wipe(cfg)`
#   (reset_pristine 用的就是它:DELETE experience / cases / payload_cases,返回清前条数),
#   不自己手写 TRUNCATE —— 手写的迟早和它漂开。
#
# ★默认 dry-run(只备份 + 报数),`--execute` 才真清。
#
# 用法(server2,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/og-wipe.sh              # dry-run:只备份 + 报数
#   bash scripts/og-wipe.sh --execute    # 真清
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
EXEC=0; [ "${1:-}" = "--execute" ] && EXEC=1
mkdir -p feedback backup
FB="feedback/og-wipe.out"
ferry_guard "$FB" "feedback: og-wipe$([ $EXEC = 1 ] && echo ' EXECUTED') $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== 经验库清空 $([ $EXEC = 1 ] && echo '★★ EXECUTE ★★' || echo '(dry-run:只备份+报数)') $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo

  PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8 - "$EXEC" <<'PY'
import datetime, json, os, sys

EXEC = sys.argv[1] == "1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) if "__file__" in dir() else "."
# ★表清单从 opengauss 模块 import,**不在这里硬编码**。
#   以前这里和 wipe() 各写一份:加一张表只改 wipe() 的话,备份和清后复核都会漏掉它 ——
#   于是新表**没备份就被删了**,而且输出看起来一切正常。
from soc_agent.experience.opengauss import WIPE_TABLES as TABLES

from soc_agent.config import Config
# ★必须传 dotenv_path。不传的话 .env 里的 OG_* 全取空 ⇒ 会误判成"库没配、没东西要清"
#   —— 上一版就是这么跳过去的。
cfg = Config.from_env(dotenv_path=".env")
print(f"OG: {cfg.og_user}@{cfg.og_host}:{cfg.og_port}/{cfg.og_database} schema={cfg.og_schema}")
if not cfg.og_host:
    print("!! OG_HOST 仍为空 —— 检查 .env(这一步不该发生了)")
    raise SystemExit(1)

import psycopg2
con = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_database,
                       user=cfg.og_user, password=cfg.og_password, connect_timeout=10)
cur = con.cursor()

print("\n-- 清前条数 --")
before = {}
for t in TABLES:
    cur.execute(f"SELECT count(*) FROM {cfg.og_schema}.{t}")
    before[t] = cur.fetchone()[0]
    print(f"   {cfg.og_schema}.{t:<16} {before[t]} 行")

# ---- 备份:不用 gs_dump(容器里没有),直接 dump 行成 JSON。要的是"能恢复"。----
stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
path = os.path.join("backup", f"experience-{stamp}.json")
dump = {}
for t in TABLES:
    cur.execute(f"SELECT * FROM {cfg.og_schema}.{t}")
    cols = [d[0] for d in cur.description]
    dump[t] = {"columns": cols, "rows": [[None if v is None else str(v) for v in r]
                                        for r in cur.fetchall()]}
with open(path, "w", encoding="utf-8") as f:
    json.dump(dump, f, ensure_ascii=False)
sz = os.path.getsize(path)
print(f"\n★备份 → {path}   {sz} 字节")
total = sum(before.values())
if total > 0 and sz < 200:
    print("!! 有数据但备份文件几乎是空的 ⇒ **不清**,退出码 3")
    raise SystemExit(3)
con.close()

if not EXEC:
    print("\n[dry-run] 没清。确认备份没问题后:bash scripts/og-wipe.sh --execute")
    raise SystemExit(0)

# ---- 用现成的 wipe(reset_pristine 用的就是它),不手写 TRUNCATE ----
from soc_agent.experience import opengauss as OG
cleared = OG.wipe(cfg)                     # {表名: 清前行数}
print("\n已清:" + "、".join(f"{t} {n} 行" for t, n in cleared.items()))

con = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_database,
                       user=cfg.og_user, password=cfg.og_password, connect_timeout=10)
cur = con.cursor()
print("-- 复核(都应为 0)--")
bad = []
for t in TABLES:
    cur.execute(f"SELECT count(*) FROM {cfg.og_schema}.{t}")
    n = cur.fetchone()[0]
    print(f"   {cfg.og_schema}.{t:<16} {n} 行")
    if n:
        bad.append(t)
con.close()
if bad:
    print(f"!! 这些表没清干净:{bad}")
    raise SystemExit(4)
print("\n✅ 经验库已清空(备份在 backup/,不进 git)")
PY
  RC=$?
  echo
  echo "[退出码] $RC"
  case "$RC" in
    0) [ "$EXEC" = "1" ] && echo "✅ 清完了。★接下来才起 poller —— 它一起来就会开始写新经验。" \
                         || echo "ℹ dry-run 完成。看过备份没问题再加 --execute。" ;;
    3) echo "⚠ 备份可疑,**没清**。别硬来,先弄清备份为什么是空的。" ;;
    4) echo "⚠ 清了但没清干净,看上面哪张表还有行。" ;;
    *) echo "⚠ 看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
