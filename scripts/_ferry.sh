# shellcheck shell=bash
# ferry 公共函数:把结果推回去,**带延时重试**,并且**核实落地后才敢说成功**。
#
# 为什么要这一份共用的(而不是每个脚本各写一遍尾巴):
#   · 这台机器出网是**间歇性抖**的(不是断)—— push/fetch 偶尔失败,重试就好。
#     一次性 push 失败会让结果留在本机,而人以为推成功了,下一轮拿到的是旧文件
#     ——实测被这个卡了两轮,查了半天才发现问题在脚本不在被测代码。
#   · 早先的写法是结尾无条件 `echo "✅ 已推"`:推失败照样显示成功。
#     **会撒谎的验证比没有验证更糟**,所以这里一律以"fetch 回来比对 HEAD == origin/main"为准。
#   · 收成一个入口,免得以后每加一个脚本就重新犯一遍同样的错。
#
# 用法:
#   source "$(dirname "$0")/_ferry.sh"
#   ferry_retry git fetch origin            # 需要重试的任何 git 操作
#   ferry_push "$FB" "feedback: xxx"        # 提交 + 推 + 核实

FERRY_TRIES="${FERRY_TRIES:-5}"
FERRY_BACKOFF="${FERRY_BACKOFF:-3 8 15 30}"      # 秒;最后一次沿用末位

ferry_retry() {
  # 跑一条命令,失败就按退避重试。★退避不是装饰:代理抖动通常几秒到几十秒就恢复,
  #   立刻重试往往连撞几次,反而看起来像"彻底断了"。
  local i=1 delays=($FERRY_BACKOFF) d
  while :; do
    if "$@"; then return 0; fi
    if [ "$i" -ge "$FERRY_TRIES" ]; then
      echo "   ↳ 重试 $FERRY_TRIES 次仍失败:$*" >&2
      return 1
    fi
    d="${delays[$((i-1))]:-${delays[${#delays[@]}-1]}}"
    echo "   ↳ 第 $i 次失败,${d}s 后重试:$*" >&2
    sleep "$d"
    i=$((i+1))
  done
}

ferry_push() {
  # $1=要推的文件  $2=提交信息
  local fb="$1" msg="$2" local_head remote_head
  git config user.email >/dev/null 2>&1 || git config user.email "ferry@range"
  git config user.name  >/dev/null 2>&1 || git config user.name  "ferry"
  git add -f "$fb" >/dev/null 2>&1 || true
  git commit -q -m "$msg" 2>&1 | tail -1 || true

  ferry_retry git push -q origin HEAD || {
    # 推不动可能是落后于远端(别人先推了)—— 先 rebase 再重试,而不是直接放弃
    ferry_retry git pull --rebase -q --autostash origin main || true
    ferry_retry git push -q origin HEAD || true
  }

  # ★核实:以"远端真的有这个提交"为准,不以 push 的退出码为准。
  ferry_retry git fetch -q origin || true
  local_head="$(git rev-parse HEAD 2>/dev/null)"
  remote_head="$(git rev-parse origin/main 2>/dev/null)"
  if [ -n "$local_head" ] && [ "$local_head" = "$remote_head" ]; then
    echo "✅ 已推并核实落地:$fb  (origin/main = $(echo "$local_head" | cut -c1-8))"
    return 0
  fi
  echo "❌ **没推上去**(已重试 $FERRY_TRIES 次):本地 HEAD=$(echo "$local_head" | cut -c1-8)"
  echo "   远端 origin/main=$(echo "$remote_head" | cut -c1-8)"
  echo "   结果只在本机 $fb —— **别当成跑完了**。网抖的话过一会儿手动 git push 即可。"
  return 3
}
