#!/usr/bin/env bash
# 深度通道的学习产出 + sediment 收敛率。★只读 —— 不调 LLM、不写图、不写经验库。
#
# 三段:
#   [1] 谁会走到 sediment 的 LLM —— distill.py 在调模型**之前**有两道免费退出
#       (verdict 不是 TP/FP/benign 就 return;没有非元 finding 也 return),
#       先把真正的分母量出来,别拿猜的数去做优化决策。
#   [2] 收敛率:在那个分母里,有多少条**已有经验能覆盖** ⇒ 把收敛检查提到 distill 之前能省下的量。
#       ★是**前瞻**口径(比对当前经验库),回答"以后能省多少",不是"过去白烧了多少"。
#   [3] ★重点:最贵的深度通道 99% 以上结论是 suspicious,而 suspicious **不沉淀** ——
#       钱花完了经验库一条没长。missing_evidence 频次表 = "要能结案还缺什么"的清单。
#
# 用法(server2 研判机,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/sediment-yield.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"

mkdir -p feedback
FB="feedback/sediment-yield.out"
ferry_guard "$FB" "feedback: sediment-yield $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== sediment-yield  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/sediment_yield.py "$@"
  echo
  echo "[退出码] $?"
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
