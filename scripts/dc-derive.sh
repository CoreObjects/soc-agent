#!/usr/bin/env bash
# 能不能从遥测推导出"哪台主机是 DC"?★只读 —— 不写图、不调 LLM、不碰经验库。
#
# 背景:`dcsync.actor_is_dc` 零点火 ⇒ 4180 条 dcsync 卡在 suspicious(积压里还有约 3.4 万条)。
# 断点已定位:`Domain.netbios` / `Domain.dc` / `Host.is_dc` **全空**,从来没有东西往里写过。
# 图模型自己给了另一条路(graph_model.json:118):`4769(TGS) 的 secondary: ON_HOST→DC`
# —— **签发 Kerberos 票据的主机就是 DC**,行为推导、厂商中立、不硬编码实例。
#
# 这个脚本只做一件事:把这条推导的前提**量出来**,而不是再猜一次。
#   [1] KDC 事件在不在、挂没挂 ON_HOST      [2] 落在哪几台(只有 DC?还是满图都是)
#   [3] 4662 交叉验证(两组主机该重合)       [4] ★推出的 DC 和卡死的 actor 对不对得上
#   [5] Host.role / Host.is_dc 现状(NEVER-TOUCH 护栏也查它们)
#
# 用法(server2 研判机,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/dc-derive.sh
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"

mkdir -p feedback
FB="feedback/dc-derive.out"
ferry_guard "$FB" "feedback: dc-derive $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== dc-derive  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/dc_derive.py "$@"
  echo
  echo "[退出码] $?   (1=推导路走不通:没有 KDC 事件、或全都没挂 ON_HOST)"
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
