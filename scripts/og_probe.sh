#!/usr/bin/env bash
# server2:第二类经验库 openGauss 驱动/连通探针(Phase 3 首步)。结果 ferry 回来。
# 前置:在 .env 填好 OG_HOST/OG_PORT/OG_DATABASE/OG_USER/OG_PASSWORD/OG_SCHEMA
#       (原生 openGauss 5432,先在库里建好 database + user + 授 schema 权限)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/og_probe.sh
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }
# 装 psycopg2(优先 binary 轮子;ARM 昇腾若无轮子会报错 → 反馈里能看到,再议源码装 + libpq)
echo "== 安装 psycopg2-binary(若已装则跳过)=="
./.venv/bin/pip install -q "psycopg2-binary>=2.9" 2>&1 | tail -3 || echo "!! psycopg2-binary 安装失败(见上;ARM 可能需源码装:apt install libpq-dev 后 pip install psycopg2)"

mkdir -p feedback
FB="feedback/og-probe.out"
{
  echo "=== og-probe  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
cfg = Config.from_env(dotenv_path=".env")
print("  og_enabled=%s host=%s port=%s db=%s user=%s schema=%s"
      % (cfg.og_enabled, cfg.og_host or "(空)", cfg.og_port, cfg.og_database, cfg.og_user, cfg.og_schema))
if not cfg.og_enabled:
    print("  [SKIP] OG_HOST 未配 —— 在 .env 填 OG_* 后重跑(先在 openGauss 建 database+user)")
    sys.exit(0)
try:
    import psycopg2  # noqa
    print("  [OK] psycopg2 可用:%s" % psycopg2.__version__)
except Exception as e:
    print("  [FAIL] psycopg2 不可用:%s — 见上安装日志(ARM 可能要源码装)" % e)
    sys.exit(1)
from soc_agent.experience.opengauss import open_stores
from soc_agent.experience.store import Experience
from soc_agent.experience.cases import Case
from soc_agent.forensics import Finding
try:
    exp_store, case_store = open_stores(cfg)       # 连接 + 建表(schema/experience/cases)
    print("  [OK] 连接 + 建表(%s.experience / %s.cases)" % (cfg.og_schema, cfg.og_schema))
    e = Experience(skill="__probe__", kind="threat", verdict="true_positive",
                   fingerprint={"finding_ids": ["x"]}, rule={"exists": "x"},
                   playbook=[{"order": 1, "primitive": "disable_account"}])
    eid = exp_store.add(e)
    got = exp_store.get(eid)
    ok_exp = got is not None and got.rule == {"exists": "x"} and got.fingerprint == {"finding_ids": ["x"]}
    case_store.add(Case(skill="__probe__", alert_uid="probe1", verdict="true_positive",
                        findings=[Finding("kerberoast.rc4_requested", {"enc_type": "0x17"})]))
    cs = case_store.by_skill("__probe__")
    ok_case = len(cs) == 1 and cs[0].finding_ids() == {"kerberoast.rc4_requested"}
    # 清理探针行(直连 DELETE;不污染真库)
    with exp_store.conn.cursor() as cur:
        cur.execute("DELETE FROM %s.experience WHERE skill='__probe__'" % cfg.og_schema)
        cur.execute("DELETE FROM %s.cases WHERE skill='__probe__'" % cfg.og_schema)
    exp_store.conn.commit()
    print("  [%s] 经验读写往返(rule/fingerprint 无损):%s" % ("PASS" if ok_exp else "FAIL", ok_exp))
    print("  [%s] 案例读写往返(findings 无损):%s" % ("PASS" if ok_case else "FAIL", ok_case))
    print("  [DONE] 探针行已清理。openGauss 驱动 + schema + 读写全通 → Phase 6 可直接用。"
          if (ok_exp and ok_case) else "  [DONE] 有 FAIL,见上。")
    sys.exit(0 if (ok_exp and ok_case) else 1)
except Exception as ex:
    import traceback
    print("  [FAIL] %s: %s" % (type(ex).__name__, ex))
    print("  ↳ 若是认证方式(SHA256/md5)或权限(public 被拒→用自建 schema)问题,把这段报错发我调。")
    traceback.print_exc()
    sys.exit(1)
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: og-probe $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
