#!/usr/bin/env bash
# 【Phase 2】路由记忆观测:省了多少 / 学得稳不稳 / 哪些键学不动。★只读。
#
# 最要紧的一个数是 **零 LLM 命中总数** —— 记忆层的全部意义就在它上面。
# 第二要紧的是 **ambiguous / unstable 的键逐条清单**:
#   · ambiguous = 键太粗、少一个区分字段 → 去改 route_key()
#   · unstable  = 环境在漂(模型/skill registry/recipe/数据源)→ 去查什么变了
# 只报计数没有用:一个覆盖 30% 告警的歧义键,和一个覆盖 3 条的,优先级差着量级。
#
# 用法(server2 研判机,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/route-memo-stats.sh
#
#   bash scripts/route-memo-stats.sh --no-graph      # 图不通时只看记忆表
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"

mkdir -p feedback
FB="feedback/route-memo-stats.out"
ferry_guard "$FB" "feedback: route-memo-stats $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== route-memo-stats  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/route_memo_stats.py "$@"
  echo
  echo "[退出码] $?   (2=OG_HOST 没配,记忆层在内存里、没什么可统计)"
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
