#!/usr/bin/env bash
# openGauss 为什么连不上(127.0.0.1:5432 Connection refused)—— ★纯只读诊断。
#
# 不启动、不重启、不改配置:数据库的启停是有状态动作,得看清原因、由人拍板再动。
# 修法在报告末尾**打印**出来,不执行。
#
# 「Connection refused」的含义很窄:**那个地址那个端口上没人在听**。
# 所以只有三类可能,本脚本就按这三类查:
#   ① 进程没起来(最常见:机器重启过而它不是开机自启;或崩了)
#   ② 起来了但听在别的地址/端口(listen_addresses / port 改过)
#   ③ 起不来(磁盘满 / 内存不够被 OOM 杀 / 数据目录锁残留 / 配置写坏)
#
# 用法(在 **server2 研判机** 上): cd ~/soc-agent && bash scripts/og-diag.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
mkdir -p feedback
FB="feedback/og-diag.out"
ferry_guard "$FB" "feedback: og-diag $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

# 每个外部调用都要有上限(本会话吃过"脚本挂一整晚"的亏)
r() { timeout -k 3 20 "$@" 2>&1; }

{
  echo "=== openGauss 诊断(只读) $(date '+%F %T' 2>/dev/null) ==="
  echo "主机: $(hostname 2>/dev/null)   $(uname -srm 2>/dev/null)"
  # ★开机时长是头号线索:机器刚重启过 + 数据库不是开机自启 = 直接就是答案
  echo "开机: $(uptime -p 2>/dev/null || uptime 2>/dev/null)"
  echo "     最后启动: $(who -b 2>/dev/null | tr -s ' ')"
  echo

  echo "--- ① 我们到底在连什么(.env 里的 OG_* )---"
  grep -E '^OG_' .env 2>/dev/null | sed 's/\(PASSWORD=\).*/\1***/' | sed 's/^/  /' || echo "  (.env 里没有 OG_*)"
  echo

  echo "--- ② 5432 上有没有人在听 ---"
  r ss -tlnp | grep -E ':5432|Local' | head -8 | sed 's/^/  /' || echo "  (ss 不可用)"
  if ! r ss -tln | grep -q ':5432'; then
    echo "  ★**没有任何进程在听 5432** —— 这与 Connection refused 完全吻合,问题在①或③,不在网络。"
  fi
  echo

  echo "--- ③ 进程在不在 ---"
  r ps -eo pid,etime,stat,user,cmd | grep -Ei 'gaussdb|gs_ctl|gs_om|postgres' | grep -v grep \
    | head -10 | sed 's/^/  /' || echo "  (没有任何 gaussdb/postgres 进程)"
  echo

  echo "--- ④ 装在哪、以谁的身份跑 ---"
  for c in gaussdb gs_ctl gs_om gsql; do
    printf '  %-8s %s\n' "$c" "$(command -v $c 2>/dev/null || echo '(不在当前 PATH)')"
  done
  echo "  GAUSSHOME=${GAUSSHOME:-（当前 shell 未设,通常在 omm 用户的 profile 里）}"
  echo "  GAUSSDATA=${GAUSSDATA:-（未设）}   PGDATA=${PGDATA:-（未设）}"
  echo "  omm 用户: $(getent passwd omm 2>/dev/null || echo '(没有 omm 用户)')"
  echo "  ★openGauss 一般以 **omm** 身份跑,当前用户 $(whoami) 的 PATH/env 里看不到很正常 ——"
  echo "    别据此判断'没装'。下面直接去找数据目录与日志。"
  echo

  echo "--- ⑤ systemd 里有没有它 ---"
  r systemctl list-unit-files | grep -Ei 'gauss|opengauss|postgres' | head -5 | sed 's/^/  /' \
    || echo "  (systemd 里没有相关 unit —— 那它多半是**手工起的**,重启就不会自己回来)"
  for u in opengauss gaussdb openGauss; do
    r systemctl is-enabled "$u" 2>/dev/null | sed "s/^/  is-enabled $u: /"
  done
  echo

  echo "--- ⑥ 数据目录与锁文件(★残留 postmaster.pid 会让它起不来)---"
  DD=""
  for d in "${GAUSSDATA:-}" "${PGDATA:-}" /gaussdb/data /var/lib/opengauss/data \
           /home/omm/data /opt/opengauss/data /gauss/data; do
    [ -n "$d" ] && [ -d "$d" ] && { DD="$d"; break; }
  done
  if [ -z "$DD" ]; then
    echo "  常见路径都没命中,全盘找一下(限时):"
    DD="$(r timeout 15 find / -maxdepth 5 -name postgresql.conf -path '*data*' 2>/dev/null | head -1 | xargs -r dirname)"
  fi
  echo "  数据目录 = ${DD:-（没找到）}"
  if [ -n "$DD" ]; then
    r ls -l "$DD/postmaster.pid" | sed 's/^/    /' || echo "    (无 postmaster.pid —— 说明它是**干净停的**,不是崩在半路)"
    echo "    监听配置:"
    r grep -E "^\s*(listen_addresses|port)\s*=" "$DD/postgresql.conf" | sed 's/^/      /' \
      || echo "      (读不到 postgresql.conf,可能需要 sudo/omm 身份)"
  fi
  echo

  echo "--- ⑦ ★日志:它到底是怎么停的 / 为什么起不来 ---"
  LOGD=""
  for d in "${GAUSSLOG:-}" /var/log/gaussdb /var/log/opengauss "$DD/pg_log" "$DD/log" /home/omm/log; do
    [ -n "$d" ] && [ -d "$d" ] && { LOGD="$d"; break; }
  done
  echo "  日志目录 = ${LOGD:-（没找到;可能在 omm 家目录下,需 sudo -u omm 看）}"
  if [ -n "$LOGD" ]; then
    LATEST="$(r find "$LOGD" -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
    echo "  最新日志 = ${LATEST:-（没有 .log）}"
    [ -n "$LATEST" ] && { echo "  最后 25 行:"; r tail -25 "$LATEST" | sed 's/^/    /'; }
    echo "  近期 FATAL/PANIC/shutdown(全目录搜,最多 12 条):"
    r grep -hriE "FATAL|PANIC|shutting down|database system is shut down|could not" "$LOGD" \
      | tail -12 | cut -c1-200 | sed 's/^/    /' || echo "    (搜不到)"
  fi
  echo

  echo "--- ⑧ 两个最常见的「起不来」根因 ---"
  echo "  磁盘:"
  r df -h | grep -vE '^tmpfs|^devtmpfs' | head -8 | sed 's/^/    /'
  echo "  ★任一分区 100%(尤其数据目录所在的)⇒ 数据库会拒绝启动或自行停下。"
  echo "  内存 / OOM:"
  r free -h | sed 's/^/    /'
  echo "  内核有没有杀过它:"
  (r dmesg -T 2>/dev/null || r journalctl -k --since '-7 days' 2>/dev/null) \
    | grep -iE 'out of memory|killed process|oom' | tail -6 | sed 's/^/    /' \
    || echo "    (没有 OOM 记录,或没权限读内核日志 —— 试 sudo dmesg)"
  echo

  echo "--- ⑨ 怎么读这份报告 ---"
  echo "  · ②没人听 + ③没进程 + ⑤ systemd 里没有它 + ①开机时间很新"
  echo "      ⇒ **机器重启过,而它是手工起的、没设开机自启**。这是最常见的一种,也最好修:"
  echo "        起回来之后把它做成开机自启,否则下次重启还会静悄悄地没。"
  echo "  · ⑦日志里有 PANIC / could not write / No space left"
  echo "      ⇒ 看⑧的磁盘,多半是写满了。腾空间再起。"
  echo "  · ⑧有 OOM killed"
  echo "      ⇒ 被内核杀的。这台是 2TiB 内存,真被杀说明有别的东西在吃内存(或它自己配置过大)。"
  echo "  · ⑥有残留 postmaster.pid 但③没进程"
  echo "      ⇒ 上次是**崩的**不是干净停的;起之前先确认没有僵尸进程,再按提示清理 pid 文件。"
  echo "  · ②有人听但不是 127.0.0.1:5432(比如只听 ::1 或别的端口)"
  echo "      ⇒ 不是「没起来」,是**听错地方**,改 .env 的 OG_HOST/OG_PORT 或改 listen_addresses。"
  echo
  echo "--- ⑩ 起它的命令(★先看完上面再执行,别照抄)---"
  echo "    sudo su - omm                     # openGauss 通常以 omm 身份管理"
  echo "    gs_ctl start -D \$GAUSSDATA        # 或 gs_om -t start(集群方式装的)"
  echo "    gs_ctl query -D \$GAUSSDATA        # 起完确认状态"
  echo "  验证连得上(回到普通用户):"
  echo "    ss -tln | grep 5432"
  echo "  ★起回来之后,别忘了确认经验表非空:"
  echo "    cd ~/soc-agent && bash scripts/replay-reuse.sh   # 空库它会当场停,不会再吐假基线"
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
