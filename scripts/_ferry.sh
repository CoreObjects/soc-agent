# shellcheck shell=bash
# ferry 公共函数:把结果推回去,**带延时重试**,**核实落地后才敢说成功**,而且**永远有时间上限**。
#
# 三条血泪(每条都真吃过亏,别删):
#   1. 这台机器出网是**间歇性抖**的(不是断)—— push/fetch 偶尔失败,重试就好。
#      一次性失败就放弃会让结果留在本机,而人以为推成功了,下一轮拿到的是旧文件。
#   2. 早先的写法是结尾无条件 `echo "已推"`:推失败照样显示成功。
#      **会撒谎的验证比没有验证更糟**,所以一律以「fetch 回来比对 HEAD == origin/main」为准。
#   3. ★git 有两种「无限等」的姿势,漏一个脚本就能挂一整晚(2026-08 实测挂了一晚上):
#        · **要账号密码时弹交互提示** —— 无人值守的终端上永远等下去,而正文早已跑完;
#        · **TCP 连上了但对端不说话**(代理 CONNECT 成功后卡死)—— git 默认**不设传输超时**。
#      注意重试逻辑对这两种情况**完全无效**:命令根本不返回,谈不上"失败后重试"。
#      对策三层:关交互 + 让 git 自己对慢传输放弃 + ★`timeout` 兜底(不管卡在哪一层都有硬上限),
#      外加 ferry_push 的整体墙钟 deadline,保证这个函数**一定会返回**。
#
# 用法:
#   source "$(dirname "$0")/_ferry.sh"
#   ferry_retry git fetch origin            # 需要重试的任何**外部命令**
#   ferry_push "$FB" "feedback: xxx"        # 提交 + 推 + 核实

FERRY_TRIES="${FERRY_TRIES:-5}"
FERRY_BACKOFF="${FERRY_BACKOFF:-3 8 15 30}"      # 秒;最后一次沿用末位
FERRY_TIMEOUT="${FERRY_TIMEOUT:-90}"             # ★单次操作硬上限(秒)
FERRY_DEADLINE="${FERRY_DEADLINE:-600}"          # ★ferry_push 整体墙钟上限(秒)

# 永不交互:没有这一行,push 会停在 "Username for 'https://github.com':" 上等到天亮。
export GIT_TERMINAL_PROMPT=0
unset GIT_ASKPASS SSH_ASKPASS 2>/dev/null || true
# 传输卡死时让 git 自己放弃:持续 20s 低于 1KB/s 即报错(git 默认是**无限等**)。
export GIT_HTTP_LOW_SPEED_LIMIT="${GIT_HTTP_LOW_SPEED_LIMIT:-1000}"
export GIT_HTTP_LOW_SPEED_TIME="${GIT_HTTP_LOW_SPEED_TIME:-20}"
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o ConnectTimeout=15}"
# ★注意:credential.helper **不能**关 —— 这台机器的 GitHub 凭据就存在里面,关了就真推不动了。
#   我们只禁「交互提示」,不禁「已存好的凭据」。

_FERRY_T0=0
_ferry_now() { date +%s 2>/dev/null || echo 0; }

# ★不该重试的失败(确定性的,重试多少次都是同一个结果)。
#   实测踩过两次:①落后于远端 → `! [rejected] (fetch first)`;
#   ②root 在别人拥有的仓库里跑 git → `detected dubious ownership`。
#   两次都是傻等 3/8/15/30 秒重试 5 遍,每遍同样失败,还让人误以为是网断了。
#   **把确定性失败当成瞬时失败去重试,是纯浪费,而且会把人引向错误的方向。**
_FERRY_FATAL='dubious ownership|not a git repository|not in a git directory|Permission denied \(publickey|could not read Username|Authentication failed|repository .* not found'

ferry_retry() {
  # 跑一条**外部命令**(不能是 shell 函数 —— 要经 timeout 启动),失败就按退避重试。
  # ★退避不是装饰:代理抖动通常几秒到几十秒就恢复,立刻重试往往连撞几次,
  #   反而看起来像「彻底断了」。
  # ★但只对**可能自愈**的失败重试;命中 _FERRY_FATAL 的当场停,并把修法打出来。
  local i=1 delays=($FERRY_BACKOFF) d rc now out
  [ "$_FERRY_T0" = 0 ] && _FERRY_T0="$(_ferry_now)"
  while :; do
    if command -v timeout >/dev/null 2>&1; then
      out="$(timeout -k 5 "$FERRY_TIMEOUT" "$@" 2>&1)"; rc=$?
    else
      out="$("$@" 2>&1)"; rc=$?                  # 没有 timeout 的系统:退化成老行为
    fi
    [ -n "$out" ] && printf '%s
' "$out" >&2
    [ "$rc" -eq 0 ] && return 0
    if printf '%s' "$out" | grep -qE "$_FERRY_FATAL"; then
      echo "   ↳ ★这是**确定性失败**,重试没有意义,当场停:$*" >&2
      case "$out" in
        *"dubious ownership"*|*"not in a git directory"*)
          echo "     以 root 在 $(whoami) 之外的用户拥有的仓库里跑 git 会被拒。修法(任选):" >&2
          echo "       · 用仓库属主的身份跑本脚本;或" >&2
          echo "       · 跑之前 export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \\" >&2
          echo "                        GIT_CONFIG_VALUE_0=\"\$(pwd)\"" >&2 ;;
      esac
      return 1
    fi
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
      echo "   ↳ ★卡住不返回,已按 ${FERRY_TIMEOUT}s 上限掐断:$*" >&2
    fi
    now="$(_ferry_now)"
    if [ "$now" != 0 ] && [ $((now - _FERRY_T0)) -ge "$FERRY_DEADLINE" ]; then
      echo "   ↳ 已用满整体上限 ${FERRY_DEADLINE}s,停止重试:$*" >&2
      return 1
    fi
    if [ "$i" -ge "$FERRY_TRIES" ]; then
      echo "   ↳ 重试 $FERRY_TRIES 次仍失败:$*" >&2
      return 1
    fi
    d="${delays[$((i-1))]:-${delays[${#delays[@]}-1]}}"
    echo "   ↳ 第 $i 次失败(rc=$rc),${d}s 后重试:$*" >&2
    sleep "$d"
    i=$((i+1))
  done
}

_FERRY_GUARD_FB=""
_FERRY_GUARD_MSG=""

_ferry_guard_fire() {
  local how="$1" rc="${2:-0}"
  trap - EXIT INT TERM                       # 只放一次,免得递归
  if [ -s "${_FERRY_GUARD_FB:-}" ]; then
    echo
    echo "[ferry] 脚本${how} —— 把**已经产出的部分**推回去($_FERRY_GUARD_FB)"
    ferry_push "$_FERRY_GUARD_FB" "$_FERRY_GUARD_MSG"
  fi
  if [ "$rc" != 0 ]; then exit "$rc"; fi
  return 0
}

ferry_guard() {
  # $1=要推的文件  $2=提交信息
  # 给整个脚本装一个「无论怎么结束都把已产出的结果推回去」的兜底,**在正文之前**调用。
  #
  # ★为什么需要(2026-08-13 真丢过一次):tee 是边跑边写的,但脚本中途被 Ctrl-C / kill 掉时,
  #   结尾的 ferry_push 根本没机会跑,结果只留在本机;而 feedback/*.out 是**被 git 跟踪**的,
  #   下一条 `git reset --hard` 一来就用已提交的旧版本把它覆盖掉 —— 一晚上白跑,证据归零。
  #   装上它以后,Ctrl-C 也会先把跑到的部分推回去再退出。
  _FERRY_GUARD_FB="$1"; _FERRY_GUARD_MSG="$2"
  trap '_ferry_guard_fire 被中断 130' INT
  trap '_ferry_guard_fire 被终止 143' TERM
  trap '_ferry_guard_fire 结束' EXIT
}

ferry_push() {
  # $1=要推的文件  $2=提交信息
  # 保证:**最多 FERRY_DEADLINE 秒就返回**,绝不无限等。
  local fb="$1" msg="$2" local_head remote_head elapsed
  _FERRY_T0="$(_ferry_now)"                      # ★每次推送重新计时,别沿用上一次的
  git config user.email >/dev/null 2>&1 || git config user.email "ferry@range"
  git config user.name  >/dev/null 2>&1 || git config user.name  "ferry"
  git add -f "$fb" >/dev/null 2>&1 || true
  # 需要连同结果一起推的附件(空格分隔),由调用方设置 FERRY_EXTRA。
  # shellcheck disable=SC2086
  [ -n "${FERRY_EXTRA:-}" ] && git add -f ${FERRY_EXTRA} >/dev/null 2>&1
  true
  git commit -q -m "$msg" 2>&1 | tail -1 || true

  # ★★先同步再推,不要"推失败了再说"。
  #
  # 2026-08-13 实测踩到:本机落后于远端时 push 报
  #   `! [rejected] (fetch first)` —— 这是**必然失败**,不是网络抖动,
  # 而 ferry_retry 把所有失败一视同仁,傻等 3/8/15/30 秒重试 5 遍,每遍都以同样的理由失败,
  # 真正的修法(rebase)被推到半分钟之后才轮到。**把确定性失败当成瞬时失败去重试,是纯浪费**,
  # 更糟的是它会让人以为"网又断了"。
  #
  # 所以顺序反过来:fetch → rebase → push。落后是常态(我在另一头推代码),不是异常。
  ferry_retry git fetch -q origin || true
  if ! git rebase -q --autostash origin/main >/dev/null 2>&1; then
    git rebase --abort >/dev/null 2>&1 || true
    echo "   ↳ rebase 到 origin/main 失败(多半是同一个 feedback 文件两头都改过)。" >&2
    echo "     结果**已在本机** $fb;手动处理:git fetch origin && git rebase origin/main" >&2
  fi
  ferry_retry git push -q origin HEAD || true

  # ★核实:以「远端真的有这个提交」为准,不以 push 的退出码为准。
  ferry_retry git fetch -q origin || true
  local_head="$(git rev-parse HEAD 2>/dev/null)"
  remote_head="$(git rev-parse origin/main 2>/dev/null)"
  elapsed=$(( $(_ferry_now) - _FERRY_T0 ))
  if [ -n "$local_head" ] && [ "$local_head" = "$remote_head" ]; then
    echo "✅ 已推并核实落地:$fb  (origin/main = $(echo "$local_head" | cut -c1-8),用时 ${elapsed}s)"
    return 0
  fi
  echo "❌ **没推上去**(已重试 $FERRY_TRIES 次 / 用时 ${elapsed}s):本地 HEAD=$(echo "$local_head" | cut -c1-8)"
  echo "   远端 origin/main=$(echo "$remote_head" | cut -c1-8)"
  echo "   结果只在本机 $fb —— **别当成跑完了**,但也**别重跑**:内容已经落盘了。"
  echo "   网抖的话过一会儿 git push origin HEAD 即可;要快的话直接把 $fb 贴出来。"
  return 3
}
