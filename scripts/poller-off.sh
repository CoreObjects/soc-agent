#!/usr/bin/env bash
# server2:只关 poller —— 不重启、不改并发/超时/模型。幂等(下次从 CONCLUDED 水位续,不重判)。ferry 一行确认。
# 用法: cd ~/soc-agent && bash scripts/poller-off.sh
set -uo pipefail
cd "$(dirname "$0")/.."

mkdir -p feedback
FB="feedback/poller-off.out"
{
  echo "=== poller-off  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  if pgrep -af "soc_agent.runtime" >/dev/null 2>&1; then
    echo "  在跑的进程:"; pgrep -af "soc_agent.runtime"
    pkill -9 -f "soc_agent.runtime" 2>/dev/null || true
    sleep 2
    if pgrep -af "soc_agent.runtime" >/dev/null 2>&1; then
      echo "  仍在?再杀一次"; pkill -9 -f "soc_agent.runtime" 2>/dev/null || true; sleep 1
    fi
    if pgrep -af "soc_agent.runtime" >/dev/null 2>&1; then
      echo "  ⚠ 仍未退,手动:pkill -9 -f soc_agent.runtime"
    else
      echo "  ✅ 已关。台账/经验都在;想再开:bash scripts/poller-full.sh 或 poller-fix-restart.sh"
    fi
  else
    echo "  poller 本没在跑"
  fi
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-off" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
