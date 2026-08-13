#!/usr/bin/env bash
# WP10 前置(★只读):用 PROFILE 证明「event_code 放宽成 OR activity」没有打掉索引命中。
#
# 计划点名的风险:两个属性各有各的索引,OR 可能**两个索引都不走**、退化成 :Event 全标签扫。
# 在 90 万事件上那是灾难,而且**不会报错**,只会让研判默默变慢。
# 所以三条谓词动手之前先把这件事证掉,而不是改完再看。
#
# 用法(soc 身份,server2): cd ~/soc-agent && bash scripts/profile-predicate.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/profile-predicate.out"
ferry_guard "$FB" "feedback: profile-predicate $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== 谓词放宽的执行计划体检(只读) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/profile_predicate.py
  RC=$?
  echo "[退出码] $RC"
  echo
  case "$RC" in
    0) echo "✅ 可以直接 OR 放宽,三条谓词按计划走。" ;;
    1) echo "❌ 至少一条不能直接 OR —— 需要换写法(拆 UNION 两支之类),别硬改。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
