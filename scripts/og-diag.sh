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

# ★以 root 跑时 $HOME 是 /root —— 查 shell 历史/家目录会**搜错人**。
#   所以一律以「仓库属主」为准来定位应用用户的家目录,而不是当前用户的。
APP_USER="$(stat -c '%U' . 2>/dev/null || echo "$(whoami)")"
APP_HOME="$(getent passwd "$APP_USER" 2>/dev/null | cut -d: -f6)"
APP_HOME="${APP_HOME:-$HOME}"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
# ★root 在 soc 拥有的仓库里跑 git 会被 "detected dubious ownership" 全线拒绝
#   —— 实测导致「代码版本」为空、ferry 推送连 fetch 都失败。
#   用 GIT_CONFIG_* 环境变量临时放行(**不写 root 的全局 gitconfig**,不留痕)。
if [ "$IS_ROOT" = "1" ]; then
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$(pwd)"
fi

# ★root 跑完必须把属主还回去:否则 .git/feedback 变成 root 所有,
#   下次以 soc 身份跑会一路权限报错 —— 用 root 查问题,不该留下新问题。
_restore_owner() {
  [ "$IS_ROOT" = "1" ] || return 0
  chown -R "$APP_USER" .git feedback 2>/dev/null || true
  echo "[root] 已把 .git / feedback 的属主还给 $APP_USER"
}
# ★注意顺序:`ferry_guard` 已经装了 EXIT 陷阱(负责把结果推回去)。
#   这里直接 `trap ... EXIT` 会**覆盖**它,结果就推不回来了 —— 所以串起来,
#   并且**先推后还属主**(推的时候还在用 git,还早了又会变成 root 所有)。
trap '_ferry_guard_fire 结束; _restore_owner' EXIT

{
  echo "=== openGauss 诊断(只读) $(date '+%F %T' 2>/dev/null) ==="
  # ★这行是我自己定的规矩,却在这个脚本里漏了 —— 结果第二跑拿到一份看不出版本的报告,
  #   分不清是"没跑"还是"跑了旧脚本",只能靠 git log 反推。补回来。
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-50)"
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
    # ★别走 r():它 2>&1 会把 find 的 "Permission denied" 并进结果,
    #   于是 DD 变成一堆报错文本,后面 ls/grep 全部对着垃圾路径跑(首跑就是这样)。
    DD="$(timeout 20 find / -maxdepth 6 -name postgresql.conf -path '*data*' 2>/dev/null \
          | head -1 | xargs -r dirname)"
    [ -n "$DD" ] && echo "    找到 $DD" || echo "    ★全盘也没有 postgresql.conf —— 它多半**不是装在宿主机上的**(见下一节)"
  fi
  echo "  数据目录 = ${DD:-（没找到）}"
  if [ -n "$DD" ]; then
    r ls -l "$DD/postmaster.pid" | sed 's/^/    /' || echo "    (无 postmaster.pid —— 说明它是**干净停的**,不是崩在半路)"
    echo "    监听配置:"
    r grep -E "^\s*(listen_addresses|port)\s*=" "$DD/postgresql.conf" | sed 's/^/      /' \
      || echo "      (读不到 postgresql.conf —— 以 root 跑本脚本即可,别用 sudo:这台机器用不了)"
  fi
  echo

  echo "--- ⑦ ★日志:它到底是怎么停的 / 为什么起不来 ---"
  LOGD=""
  for d in "${GAUSSLOG:-}" /var/log/gaussdb /var/log/opengauss "$DD/pg_log" "$DD/log" /home/omm/log; do
    [ -n "$d" ] && [ -d "$d" ] && { LOGD="$d"; break; }
  done
  echo "  日志目录 = ${LOGD:-（没找到 —— 已确认这台机器没有 omm 用户,宿主机上也没装,见 ⑦b）}"
  if [ -n "$LOGD" ]; then
    LATEST="$(r find "$LOGD" -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
    echo "  最新日志 = ${LATEST:-（没有 .log）}"
    [ -n "$LATEST" ] && { echo "  最后 25 行:"; r tail -25 "$LATEST" | sed 's/^/    /'; }
    echo "  近期 FATAL/PANIC/shutdown(全目录搜,最多 12 条):"
    r grep -hriE "FATAL|PANIC|shutting down|database system is shut down|could not" "$LOGD" \
      | tail -12 | cut -c1-200 | sed 's/^/    /' || echo "    (搜不到)"
  fi
  echo

  echo "--- ⑦b ★它是不是跑在容器里 ---"
  echo "  (首跑证据指向这个方向:**没有 omm 用户**、宿主机上没有任何 gaussdb 二进制,"
  echo "   而 df 里出现了 /run/k3s/containerd/… —— 这台机器上有 k3s。"
  echo "   我此前记的是「原生 openGauss」,这条得以实际证据为准。)"
  echo "  k3s / containerd:"
  r systemctl is-active k3s | sed 's/^/    k3s is-active: /'
  r systemctl is-enabled k3s | sed 's/^/    k3s is-enabled: /'
  for kc in k3s kubectl crictl; do
    printf '    %-8s %s\n' "$kc" "$(command -v $kc 2>/dev/null || echo '(不在 PATH)')"
  done
  # ★上一跑 pod 全"列不出",**不是** k3s 没起(它 is-active: active),
  #   是 k3s 的 kubeconfig 只有 root 能读。我上一版让人用 sudo —— **错了**:
  #   这台机器的 soc 用户建号时就没设密码、登录也不要密码,sudo 根本用不了。
  #   现在改成:命令直接跑(以 root 身份跑本脚本时自然有权限),不是 root 就明说这节跳过。
  export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
  echo "  当前身份: $(whoami)  (仓库属主 $APP_USER,家目录 $APP_HOME)"
  if [ "$IS_ROOT" = "1" ] || [ -r "$KUBECONFIG" ]; then
    echo "  ★全部 pod(不只找 gauss —— 要看的是**整个应用层回来没有**):"
    r k3s kubectl get pods -A -o wide | head -25 | sed 's/^/    /'
    echo "  最近的事件(为什么没起来,答案通常直接写在这):"
    r k3s kubectl get events -A --sort-by=.lastTimestamp | tail -15 | cut -c1-190 | sed 's/^/    /'
    echo "  部署对象(pod 没了也能看出**本来该有什么**):"
    r k3s kubectl get deploy,sts,ds -A | head -20 | sed 's/^/    /'
    echo "  containerd 容器(含已退出的 —— 退出码/原因在这):"
    r crictl ps -a | head -15 | sed 's/^/    /'
  else
    echo "  ⚠ 非 root 且读不到 kubeconfig ⇒ **这一节查不了**。"
    echo "    以 root 身份重跑本脚本即可(sudo 在这台机器上用不了,别试):"
    echo "      cd $(pwd) && bash scripts/og-diag.sh"
  fi
  echo "  podman:"
  r podman ps -a --format '    {{.Names}}	{{.Status}}	{{.Image}}' | head -8 || echo "    (podman 不可用)"
  echo

  echo "  ★现在到底有什么在跑(容器里的进程宿主机也看得见 —— 这条不需要任何权限):"
  r ps -eo pid,etime,user,cmd --sort=-etime     | grep -iE 'containerd-shim|vllm|gauss|k3s server|python.*serve' | grep -v grep     | head -15 | cut -c1-170 | sed 's/^/    /' || echo "    (没有相关进程)"
  echo

  echo "  ★★它们当初是怎么起的 —— 这才是能把服务拉回来的线索(全部无需 root):"
  echo "  (a) shell 历史里的启动命令($APP_HOME):"
  r grep -hiE 'vllm|gauss|gsql|kubectl apply|helm |podman run|nerdctl|k3s ctr'       "$APP_HOME/.bash_history" "$APP_HOME/.zsh_history" 2>/dev/null     | tail -15 | cut -c1-160 | sed 's/^/      /' || echo "      (历史里没有相关命令)"
  echo "  (b) 家目录里的部署文件(yaml/compose/启动脚本):"
  r find "$APP_HOME" -maxdepth 4 \( -name '*.yaml' -o -name '*.yml' -o -name '*.sh' \) 2>/dev/null     | head -400 | xargs -r grep -liE 'gauss|vllm|:5432|:8000' 2>/dev/null | head -12 | sed 's/^/      /'     || echo "      (没找到)"
  echo "  (c) crontab:"
  r crontab -u "$APP_USER" -l 2>/dev/null | grep -vE '^\s*#' | head -8 | sed 's/^/      /'     || echo "      (没有 crontab)"
  echo "  (d) 用户级 systemd 服务 + linger(没开 linger 的用户服务,重启后**不会**自动起):"
  r systemctl --user list-units --type=service --no-pager | head -8 | sed 's/^/      /'     || echo "      (取不到用户级服务)"
  r loginctl show-user "$APP_USER" -p Linger 2>/dev/null | sed 's/^/      /' || echo "      (查不到 linger)"
  echo "  (e) tmux/screen 会话(手工起在会话里的,一重启就全没):"
  r tmux ls | head -5 | sed 's/^/      /' || echo "      (没有 tmux 会话)"
  r screen -ls | head -5 | sed 's/^/      /' || echo "      (没有 screen 会话)"
  echo

  echo "  ★对照组(★订正:我先前据此断言「vLLM 也没起来、整个应用层没回来」——**错了**)"
  echo "    宿主机 ss 只看得见**宿主网络命名空间**的监听;vLLM 跑在 pod 网络里(10.42.0.x),"
  echo "    经 k3s svclb 以 lb-tcp-8001/8005 暴露 ⇒ **宿主机上本来就不会有 :8000**。"
  echo "    以上面的 pod 列表为准,不以这一行为准。"
  r ss -tln | awk 'NR==1 || /:8000|:5432|:6443|:11434|:7687/' | head -10 | sed 's/^/    /'
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
    || echo "    (没有 OOM 记录,或非 root 读不到内核日志 —— 以 root 跑本脚本即可)"
  echo

  echo "--- ⑨ 怎么读这份报告 ---"
  echo "  ★已经确定的(前两跑):磁盘 28% 不满、2TiB 内存无 OOM、无残留 postmaster.pid、"
  echo "    5432 无人监听、宿主机上没有任何 gaussdb 二进制、没有 omm 用户。"
  echo "  ★★已查明(2026-08-13,root 跑通 ⑦b):openGauss 是个 **podman 容器**"
  echo "    (localhost/opengauss:7.0.0-RC3),状态 **Exited (0) 23 小时前** —— 干净退出,"
  echo "    时间正是那次重启。同机另外三个 podman 容器(soc-eval / one-api-gateway /"
  echo "    proxy-nginx)都 Up 22 小时回来了,**只有它没有重启策略**。"
  echo "    ⇒ 立刻修:podman start opengauss;根治:给它加 --restart=always 或 systemd unit。"
  echo "  ★订正:我一度据宿主机 ss 断言「vLLM 也没起来」—— 错的。vLLM pod 一直 Running,"
  echo "    只是听在 pod 网络里,宿主机看不见。**应用层是好的,只有 opengauss 这一个没回来**。"
  echo "  · ⑦b 的 pod 列表里有 gauss/vllm 但状态不是 Running(CrashLoopBackOff/Pending/Error)"
  echo "      ⇒ 它们**试过起但起不来**,看同一节的 events,原因通常直接写在那儿。"
  echo "  · pod 列表里**压根没有**它们"
  echo "      ⇒ 从来没被部署进 k3s,是手工起的(看 tmux/screen/shell 历史那几行)。"
  echo "        修法不是「再手工起一次」,而是做成开机自启,否则下次重启还会静悄悄地全没。"
  echo "  · ⑦日志里有 PANIC / could not write / No space left"
  echo "      ⇒ 看⑧的磁盘,多半是写满了。腾空间再起。"
  echo "  · ⑧有 OOM killed"
  echo "      ⇒ 被内核杀的。这台是 2TiB 内存,真被杀说明有别的东西在吃内存(或它自己配置过大)。"
  echo "  · ⑥有残留 postmaster.pid 但③没进程"
  echo "      ⇒ 上次是**崩的**不是干净停的;起之前先确认没有僵尸进程,再按提示清理 pid 文件。"
  echo "  · ②有人听但不是 127.0.0.1:5432(比如只听 ::1 或别的端口)"
  echo "      ⇒ 不是「没起来」,是**听错地方**,改 .env 的 OG_HOST/OG_PORT 或改 listen_addresses。"
  echo
  echo "--- ⑩ 下一步(★先看完上面再动手)---"
  # ★★这一行原本是 `` `sudo su - omm` `` —— 双引号里的**反引号是命令替换**,
  #   于是一个自称"只读"的诊断脚本**真的执行了** sudo su - omm(输出里那句
  #   "su: user omm does not exist" 就是它)。展示命令一律不用反引号。
  echo "  ⚠ 原来这一节写的是「sudo su - omm + gs_ctl」—— **在这台机器上是错的**:"
  echo "    既没有 omm 用户、宿主机也没装 openGauss,而且 sudo 用不了(soc 无密码)。"
  echo "    正确姿势是**以 root 身份跑本脚本**,把 ⑦b 那几节的答案拿到手。"
  echo
  echo "  拿到答案后按情况:"
  echo "  · ⑦b 的 deploy/sts 里有 gauss/vllm,但 pod 不是 Running"
  echo "      ⇒ k3s 里本来就部署着,只是起不来。看同一节的 events,原因通常直接写在那儿。"
  echo "  · deploy/sts 里**压根没有**它们,而 (a)(b) 里能看到手工启动命令"
  echo "      ⇒ 它们从来不是 k3s 负载,是手工起的 —— 重启就全没了。"
  echo "        这时**别只是再手工起一次**:同样的事下次重启还会再发生一遍。"
  echo "        照 (a)(b) 找到的命令做成 systemd unit(或 k3s manifest)并 enable,才算修完。"
  echo
  echo "  ★两件事的优先级:**vLLM :8000 比 openGauss 更急** ——"
  echo "    没有 vLLM,soc-agent 一条告警都研判不了(poller 若在跑,每条都在失败);"
  echo "    没有 openGauss,只是经验不落库、退化成每条都走 LLM。"
  echo "=== done(本次跑到了 ⑦b 容器排查;报告里没有 ⑦b = 跑的是旧脚本)==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
