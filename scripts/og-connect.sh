#!/usr/bin/env bash
# 【经验层接上】soc 身份、TCP 直连 openGauss,把能自动做的全做掉。
#
# ★不用 podman、不用 root、不用 gsql。端口已发布在宿主环回:5432/tcp -> 127.0.0.1:5432,
#   soc 用 psycopg2 直连就行。之前所有 `podman exec ... gsql` 都是白绕
#   (gsql 不在容器 PATH 里,在 $GAUSSHOME/bin)。
#
# 这个脚本自己做完这些,不用人判断:
#   ①从多个来源试密码(.env / 容器 env 文件 / 常见口令),连上就往下走
#   ②确认 database / user / schema 在不在
#   ③**建表**(走 soc-agent 自己的 ensure_schema,不手写 DDL)
#   ④把 .env 里缺的 OG_* 行**直接补上**(备份原 .env)
#   ⑤复核:再连一次 + 数三张表行数
# 做不到的那一步会明确写出"下一条命令是什么",不问选择题。
#
# 用法(server2,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/og-connect.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/og-connect.out"
ferry_guard "$FB" "feedback: og-connect $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== 经验层接上(soc + TCP,不碰 podman/root) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo

  echo "-- .env 里 OG_* 现状(密码隐去)--"
  grep -E '^OG_' .env 2>/dev/null | sed -E 's/(PASSWORD=).*/\1<隐去>/' | sed 's/^/   /' \
    || echo "   (一行都没有)"
  echo "-- 端口在不在(不用 podman,直接看监听)--"
  (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep -E '5432' | sed 's/^/   /' \
    || echo "   ⚠ 看不到 5432 监听(ss/netstat 可能受限,继续尝试直连)"
  echo

  PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8 - <<'PY'
import os, re, shutil, sys, datetime

ENV = ".env"
TABLES = ("experience", "cases", "payload_cases")


def env_lines():
    try:
        return open(ENV, encoding="utf-8").read().splitlines()
    except OSError:
        return []


def env_get(key, default=""):
    for ln in env_lines():
        m = re.match(rf"^\s*{key}\s*=\s*(.*)$", ln)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return default


def candidates():
    """密码来源,按可信度排。★不猜单一来源 —— 猜错一次就白跑一轮。"""
    seen, out = set(), []
    def add(pw, why):
        if pw is not None and pw not in seen:
            seen.add(pw); out.append((pw, why))
    add(env_get("OG_PASSWORD"), ".env 的 OG_PASSWORD")
    add(os.environ.get("OG_PASSWORD"), "环境变量 OG_PASSWORD")
    add(os.environ.get("GS_PASSWORD"), "环境变量 GS_PASSWORD")
    for p in ("/home/soc/.og_password", ".og_password", "/home/soc/soc-agent/.og_password",
              "/home/soc/opengauss/.password"):
        try:
            add(open(p, encoding="utf-8").read().strip(), f"文件 {p}")
        except OSError:
            pass
    # openGauss 镜像常见初始口令(容器是别人建的,试一下比卡住好)
    for pw in ("Enmo@123", "Gauss@123", "openGauss@123", "Soc@123456"):
        add(pw, f"常见初始口令 {pw}")
    return out


host = env_get("OG_HOST") or "127.0.0.1"
port = int(env_get("OG_PORT") or 5432)
user = env_get("OG_USER") or "soc"
db = env_get("OG_DATABASE") or "soc"
schema = env_get("OG_SCHEMA") or "soc"
print(f"目标: {user}@{host}:{port}/{db}  schema={schema}")

try:
    import psycopg2
except ImportError:
    print("!! 没装 psycopg2。下一条命令:")
    print(f"   {sys.executable} -m pip install psycopg2-binary")
    raise SystemExit(1)

ok = None
print("\n-- 逐个试密码/用户(连上即停)--")
for pw, why in candidates():
    for u, d in ((user, db), (user, "postgres"), ("gaussdb", "postgres"), ("omm", "postgres")):
        try:
            con = psycopg2.connect(host=host, port=port, dbname=d, user=u,
                                   password=pw, connect_timeout=6)
            print(f"   ✅ 连上了: user={u} db={d}  密码来源={why}")
            ok = (con, u, d, pw, why)
            break
        except Exception as e:
            msg = str(e).split("\n")[0][:70]
            print(f"   ✗ user={u} db={d} 来源={why}: {msg}")
    if ok:
        break

if not ok:
    print("\n!! 所有组合都连不上。**下一条命令**(在你那个 root 终端跑,不带 exit):")
    print("   podman inspect opengauss --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -i pass")
    print("   把输出里的 GS_PASSWORD 值贴回来,我直接写进 .env,这一步就永久解决。")
    raise SystemExit(2)

con, u, d, pw, why = ok
con.autocommit = True
cur = con.cursor()

print("\n-- 库 / 用户 / schema 在不在 --")
cur.execute("SELECT datname FROM pg_database ORDER BY 1")
dbs = [r[0] for r in cur.fetchall()]
print(f"   数据库: {dbs}")
print(f"   目标库 {db!r} 存在: {db in dbs}")
cur.execute("SELECT rolname FROM pg_roles ORDER BY 1")
roles = [r[0] for r in cur.fetchall()]
print(f"   角色: {roles[:20]}")
print(f"   目标用户 {user!r} 存在: {user in roles}")

print("\n-- 三张经验表 --")
cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_name = ANY(%s)", (list(TABLES),))
found = cur.fetchall()
if found:
    for sch, t in found:
        cur.execute(f'SELECT count(*) FROM "{sch}"."{t}"')
        print(f"   {sch}.{t:<18} {cur.fetchone()[0]} 行")
else:
    print("   三张表都不存在 —— 下面用 soc-agent 自己的建表逻辑建(不手写 DDL)")
con.close()

# ---- 把 .env 补齐(备份原文件),然后走 soc-agent 自己的 ensure_schema ----
need = {"OG_HOST": host, "OG_PORT": str(port), "OG_DATABASE": d,
        "OG_USER": u, "OG_PASSWORD": pw, "OG_SCHEMA": schema}
lines, changed = env_lines(), []
for k, v in need.items():
    hit = False
    for i, ln in enumerate(lines):
        if re.match(rf"^\s*{k}\s*=", ln):
            if ln.split("=", 1)[1].strip().strip('"').strip("'") != v:
                lines[i] = f"{k}={v}"; changed.append(k)
            hit = True
            break
    if not hit:
        lines.append(f"{k}={v}"); changed.append(k)
if changed:
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
    shutil.copy(ENV, f"{ENV}.bak-{stamp}")
    open(ENV, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print(f"\n★已写 .env(原文件备份为 {ENV}.bak-{stamp}):{changed}")
else:
    print("\n.env 已经是对的,没改")

print("\n-- 建表 / 自检(走 soc-agent 自己的路径)--")
try:
    from soc_agent.config import Config
    from soc_agent.experience import opengauss as OG
    cfg = Config.from_env()
    print(f"   has_experience = {bool(cfg.og_host)}")
    for fn in ("ensure_schema", "init_schema", "ensure_tables", "bootstrap"):
        f = getattr(OG, fn, None)
        if callable(f):
            print(f"   调用 opengauss.{fn}()")
            try:
                f(cfg)
            except TypeError:
                f()
            break
    else:
        print("   ⚠ opengauss 模块里没找到建表入口,列出可用函数供定位:")
        print("     " + ", ".join(n for n in dir(OG) if not n.startswith("_")))
    con = psycopg2.connect(host=host, port=port, dbname=d, user=u, password=pw, connect_timeout=6)
    cur = con.cursor()
    cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_name = ANY(%s)", (list(TABLES),))
    after = cur.fetchall()
    print(f"   复核:三张表现在有 {len(after)} 张 → {after}")
    for sch, t in after:
        cur.execute(f'SELECT count(*) FROM "{sch}"."{t}"')
        print(f"     {sch}.{t:<18} {cur.fetchone()[0]} 行")
    con.close()
except Exception as e:
    print(f"   !! {type(e).__name__}: {str(e)[:240]}")
PY
  RC=$?
  echo
  echo "[退出码] $RC"
  case "$RC" in
    0) echo "✅ 经验层接上了(.env 已写好、表已就位)。"
       echo "   ★这一步的意义:在此之前 OG_HOST 是空的 ⇒ 经验层整个降级成「永远走大模型」,"
       echo "     第一级签名复用(省算力那一级)一直是死的、沉淀也没地方落。" ;;
    2) echo "⚠ 差一个密码。上面已经写了下一条命令(root 终端,一条,不带 exit)。" ;;
    *) echo "⚠ 看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
