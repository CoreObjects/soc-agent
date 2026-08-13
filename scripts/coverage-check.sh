#!/usr/bin/env bash
# WP9 读侧真机闸门(★只读):拿真图里的 `:Coverage` 事实跑一遍所有 skill,
# 看有没有 skill **误报**覆盖盲区。
#
# 为什么这是误报侧闸门:GOAD 遥测齐全,只缺 log.clear / group.member_add / module.load,
# 而没有任何 skill 声明需要这三类 ⇒ 期望是**一条都不报**。
# 报了就危险:每条告警都会被加一句"我看不到",研判整体偏向"证据不足",
# 这句话还会被喂进 LLM 提示词里带偏结论。
#
# 前置:入图仓先跑过 `bash scripts/coverage.sh --execute`(否则读侧 known=False,
#       正确行为是什么都不报 —— 脚本会明确区分这两种"没报")。
#
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/coverage-check.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/coverage-check.out"
ferry_guard "$FB" "feedback: coverage-check $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== WP9 读侧覆盖度闸门(只读) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  # ★打主机名:soc-agent 跑在 **server2 研判机**,而本项目大多数脚本跑在靶场机 ——
  #   两台机器的 feedback 混在一个仓里,不写主机名就分不清哪份是哪台跑的。
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo "图      : $(grep -E '^NEO4J_URI=' .env 2>/dev/null | cut -d= -f2- | tr -d '\"')"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/coverage_check.py
  echo "[退出码] $?"
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
