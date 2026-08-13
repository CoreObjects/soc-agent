#!/usr/bin/env bash
# 「脚本跑了一晚上还没完」的取证脚本。★纯只读:不 kill 任何进程、不改仓库、不动配置。
#
# 为什么不顺手 kill:卡住的那个进程可能正握着 .git 的锁,或者正处在一次能自愈的重试里。
#   先看清卡在**哪一段**,再决定 —— 而且几乎所有情况下,**结果都没丢**(tee 是边跑边写的)。
#
# 用法(★另开一个终端,别关掉卡住的那个):
#   cd ~/soc-graph-ingest && bash scripts/whats-stuck.sh
set -uo pipefail
cd "$(dirname "$0")/.." 2>/dev/null || true
mkdir -p feedback
FB="feedback/whats-stuck.out"

{
  echo "=== 卡在哪儿(只读取证) $(date '+%F %T' 2>/dev/null) ==="
  echo "主机 $(hostname 2>/dev/null)   仓库 $(pwd)   代码版本 $(git rev-parse --short HEAD 2>/dev/null)"
  echo

  echo "--- ① 还在跑的相关进程(ELAPSED = 已经卡了多久)---"
  ps -eo etime,pid,ppid,stat,cmd 2>/dev/null \
    | grep -E 'ELAPSED|git |curl |docker |python|bash scripts/|filebeat' \
    | grep -vE 'grep -E|whats-stuck' | head -25 | cut -c1-190 | sed 's/^/  /'
  echo
  echo "  ★怎么读 STAT:S=在等(网络/IO 都是这个) D=不可中断IO R=在算 Z=僵尸 T=被暂停"
  echo "    一个 git 进程 ELAPSED 好几个小时 ⇒ 它在**干等**,不是在传数据。"
  echo

  echo "--- ② 每个 feedback 写到哪一步了(tee 边跑边写,所以最后一行 = 卡住的位置)---"
  ls -lt --time-style=+'%m-%d %H:%M' feedback/*.out 2>/dev/null | head -8 | sed 's/^/  /'
  newest="$(ls -t feedback/*.out 2>/dev/null | grep -v whats-stuck | head -1)"
  if [ -n "${newest:-}" ]; then
    echo
    echo "  最新的是 $newest —— 最后 15 行:"
    tail -15 "$newest" 2>/dev/null | sed 's/^/    /'
    echo
    echo "  ★判读:"
    echo "    · 末行已是 '=== done ===' ⇒ 正文**早跑完了**,卡在最后的**推送**(git),见①"
    echo "    · 末行停在某个小节标题   ⇒ 卡在那一节的命令上(多半是 docker exec)"
  else
    echo "  (feedback 下没有 .out —— 那就是卡在很靠前的地方,看①的进程)"
  fi
  echo

  echo "--- ③ git:是不是在等交互 / 有没有留下锁 ---"
  found_lock=0
  for f in .git/index.lock .git/shallow.lock .git/HEAD.lock .git/refs/remotes/origin/main.lock; do
    if [ -e "$f" ]; then
      echo "  ★锁文件 $f (mtime $(date -r "$f" '+%F %T' 2>/dev/null))"
      found_lock=1
    fi
  done
  [ "$found_lock" = 0 ] && echo "  (没有锁文件)"
  pgrep -a git 2>/dev/null | head -5 | sed 's/^/  git进程: /' || echo "  (没有 git 进程在跑)"
  echo
  echo "  这些连接的去向(有 ESTAB = 连上了在干等;什么都没有 = 连都没连上):"
  { ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null; } \
    | grep -E 'git|:443|:8080|:3128|ESTAB' | head -8 | sed 's/^/    /' \
    || echo "    (看不到,可能要 sudo)"
  echo

  echo "--- ④ 怎么办(★先看②再选,别一上来就重跑)---"
  echo "  A) ②的末行是 '=== done ===' ⇒ 卡在 git 推送。**结果没丢**,就在 ${newest:-feedback/*.out} 里。"
  echo "       pkill -f 'git-remote-http'; pkill -f 'git push'    # 只掐 git,不动别的"
  echo "     然后二选一:把那个文件贴给我,或者 git push origin HEAD 重推一次。"
  echo "  B) ②的末行停在小节标题 ⇒ 卡在 docker exec:"
  echo "       pkill -f 'docker exec'"
  echo "  C) 不想要了:在卡住的那个终端按 Ctrl-C —— 跑到的部分已经落盘,不会白跑。"
  echo
  echo "  ★根因已修(本次提交):_ferry.sh 现在给每个 git 操作加了 ${FERRY_TIMEOUT:-90}s 硬超时、"
  echo "    关掉了交互式凭据提示、并给整个推送设了 10 分钟墙钟上限 —— 以后不会再挂一整晚。"
  echo "=== done ==="
} 2>&1 | tee "$FB"

echo
# ★有 git 在跑就**不敢动仓库**:再起一个 git 会抢锁,把「能自愈」变成「真卡死」。
if pgrep -x git >/dev/null 2>&1 || pgrep -x git-remote-http >/dev/null 2>&1 \
   || pgrep -x git-remote-https >/dev/null 2>&1; then
  echo "⚠ 还有 git 进程在跑 —— **本脚本不动仓库**(抢锁只会更糟)。"
  echo "  请直接把上面整段输出贴过来,或按 ④A 处理完再重跑本脚本。"
else
  # shellcheck source=scripts/_ferry.sh
  source "$(dirname "$0")/_ferry.sh"
  ferry_push "$FB" "feedback: whats-stuck $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" \
    || echo "   ↑ 推不上去也无所谓,直接贴上面的输出即可。"
fi
