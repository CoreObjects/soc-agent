#!/usr/bin/env bash
# 安全代理名单声明式化的真机等价闸门(★只读,不写图不写库)。
#
# 为什么要上真机:单测语料是我自己想出来的字符串;真正会翻结论的是图里**实际存在**的
# image 值(带盘符/版本目录/短名/大小写混杂/Linux 路径)。拿自造语料证等价,
# 证的是"我想到的情况没问题",不是"现网没问题"。
#
# 判据不只是"等价",还要**这份语料有区分力**:一条代理都没命中时,把名单删空也会
# 「等价」—— 那种绿灯是空的,脚本会判证据不足(退出码 3)。
#
# 用法(soc 身份,server2): cd ~/soc-agent && bash scripts/sec-agents-parity.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/sec-agents-parity.out"
ferry_guard "$FB" "feedback: sec-agents-parity $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== 安全代理名单:真机逐条等价(只读) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo "租户声明: ${SOC_SECURITY_AGENTS_FILE:-config/security_agents.yaml(默认路径)}"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/sec_agents_parity.py
  RC=$?
  echo "[退出码] $RC"
  echo
  case "$RC" in
    0) echo "✅ 通过:真实 image 上新旧返回的名字串逐条一致,且语料里确实有代理进程。" ;;
    1) echo "❌ 不等价 —— 这会直接改研判结论(white 极性)和处置护栏(NEVER-TOUCH)。别放行。" ;;
    3) echo "⚠ 证据不足:语料为空或一条代理都没命中,这种「等价」是空跑,不算通过。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
