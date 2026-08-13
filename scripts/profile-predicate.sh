#!/usr/bin/env bash
# WP10(★只读):用 PROFILE 证明谓词放宽没有打掉索引命中、且行为不变。
#
# 计划点名的风险:两个属性各有各的索引,OR 可能**两个索引都不走**、退化成 :Event 全标签扫。
# 在 90 万事件上那是灾难,而且**不会报错**,只会让研判默默变慢。
# 首跑就抓到一条真问题(kerberoast 扇出 2→6),按结论补了 ticket_kind 判别位。
#
# ★这个脚本自己被修过两次,两次都是「闸门没生效」而不是「闸门报错」——
#   后者会喊,前者长得像通过:
#   ① 首跑之后 recipe 改了两处(kerberoast 补 ticket_kind、lateral 补 outcome),
#      探针把新形式写死在自己里、没跟着改 ⇒ 一直在测一个代码里已不存在的写法。
#      现在开跑先做防漂移自检:新形式的 WHERE 必须与 recipe 源码逐字一致,对不上退 2。
#   ② 全标签扫判据写成 op == NodeByLabelScan,而驱动回的算子名带 @neo4j 后缀
#      ⇒ 恒 False,从首跑起一次都没生效。报告里能直接看到自相矛盾:算子链印着
#      NodeByLabelScan@neo4j,同一行却写 全标签扫=False。
#      现已按前缀判,并区分扫的是 :Event(90 万,灾难)还是 :Account 之类小标签。
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
    0) echo "✅ 四条谓词放宽均无代价:索引命中未变、dbHits 无显著上涨、结果一致。" ;;
    1) echo "❌ 至少一条不能直接 OR —— 需要换写法(拆 UNION 两支之类),别硬改。" ;;
    2) echo "⚠ 前置不满足:探针与 recipe 漂移了,或连不上图。看上面第一段。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
