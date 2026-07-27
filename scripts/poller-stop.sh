#!/usr/bin/env bash
# server2:停 poller + 把并发调慢(写进 .env,下次起生效)。★停是幂等的 —— 下次从 CONCLUDED 水位续,不重判。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-stop.sh [并发数,默认8]
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
N="${1:-8}"

mkdir -p feedback
FB="feedback/poller-stop.out"
{
  echo "=== poller-stop  $(date -u '+%F %H:%MZ' 2>/dev/null || true)   并发→${N} ==="
  if pgrep -f "soc_agent.runtime" >/dev/null 2>&1; then
    pkill -f "soc_agent.runtime" && echo "  已发 SIGTERM(优雅退出:停取新、在跑的收尾写完台账)…"
    sleep 4
    if pgrep -f "soc_agent.runtime" >/dev/null 2>&1; then
      echo "  仍在收尾,再等…"; sleep 6
      pgrep -f "soc_agent.runtime" >/dev/null 2>&1 && { echo "  强制 kill -9"; pkill -9 -f "soc_agent.runtime" || true; }
    fi
    echo "  ✅ poller 已停"
  else
    echo "  poller 本就没在跑"
  fi
  # 并发写 .env(有则替换、无则追加)
  if grep -q '^POLLER_CONCURRENCY=' .env; then
    sed -i "s/^POLLER_CONCURRENCY=.*/POLLER_CONCURRENCY=${N}/" .env
  else
    echo "POLLER_CONCURRENCY=${N}" >> .env
  fi
  echo "  ✅ 并发已设 POLLER_CONCURRENCY=${N}(.env;下次 poller-full.sh/resume.sh 生效)"
  echo "  重新起(慢速常驻):bash scripts/poller-full.sh"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-stop 并发→${N}" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
