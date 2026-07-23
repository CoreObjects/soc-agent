#!/usr/bin/env bash
# server2: openJiuwen 安装/导入 + cascade 单测 的 go/no-go 探针(浅度研判 scope A 的 gate)。
# openjiuwen 要求 Python 3.11-3.13(soc-agent 原 .venv 是 3.10)→ 本脚本单独建 .venv312。
# 自包含:不碰 Neo4j/LLM,只验"openjiuwen 在昇腾 ARM 装得上+导得进 + cascade 图跑得通"。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/cascade-gate.sh
set -uo pipefail
cd "$(dirname "$0")/.."

pick_py() {   # 找一个 3.11-3.13 的解释器
  for c in python3.12 python3.11 python3.13 python3; do
    command -v "$c" >/dev/null 2>&1 || continue
    v=$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)
    case "$v" in 3.11|3.12|3.13) echo "$c"; return 0 ;; esac
  done
  return 1
}

mkdir -p feedback
FB="feedback/cascade-gate.out"
{
  echo "=== cascade-gate  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PY312=".venv312/bin/python"
  if [ ! -x "$PY312" ]; then
    BASE=$(pick_py) || { echo "  [FAIL] 找不到 Python 3.11-3.13 —— openjiuwen 要 3.11+。server2 先装一个(conda/pyenv/apt),再重跑。"; exit 1; }
    echo "  用 $BASE ($("$BASE" --version 2>&1)) 建 .venv312"
    "$BASE" -m venv .venv312 || { echo "  [FAIL] 建 .venv312 失败"; exit 1; }
  fi
  echo "== 装 soc-agent[dev,og] + openjiuwen(★ARM 轮子风险:pyoxigraph[Rust]/grpcio[C++]/psycopg2)=="
  # og extra = psycopg2(深度层经由 cascade 在 .venv312 里跑时,经验层要连 openGauss)
  if "$PY312" -c "import openjiuwen, soc_agent, psycopg2" >/dev/null 2>&1; then
    echo "  openjiuwen + soc_agent + psycopg2 已在 .venv312 → 跳过安装(重跑只验测试)"
  else
    "$PY312" -m pip install -q -U pip 2>&1 | tail -2
    "$PY312" -m pip install -e ".[dev,og]" openjiuwen 2>&1 | tail -25
  fi
  echo "== 导入检查 =="
  "$PY312" -c "import openjiuwen; from openjiuwen.core.workflow import Workflow, LLMComponent, BranchRouter, WorkflowComponent; from openjiuwen.core.runner.runner import Runner; print('  [OK] openjiuwen', getattr(openjiuwen,'__version__','?'), '导入通过')" \
    || { echo "  [FAIL] openjiuwen 导入失败 —— 见上安装日志(多半 ARM 无轮子)"; exit 1; }
  echo "== cascade 单测(验 floor/浅层图/分叉 在昇腾跑得通;不需 .env)=="
  # 捕获到变量 → 拿真 rc + 保住"N passed"汇总行(旧版 tail 把它切没了);-W 压掉 openjiuwen 弃用告警噪声
  CG_OUT=$(PYTHONUTF8=1 "$PY312" -m pytest tests/test_cascade_floor.py tests/test_cascade_components.py \
      tests/test_cascade_build.py tests/test_cascade_dispatch.py -p no:cacheprovider -q \
      -W ignore::DeprecationWarning 2>&1); CG_RC=$?
  echo "$CG_OUT" | grep -viE "\| INFO \||Registered parser|event_id|^\s*$" | tail -8
  echo "  [pytest rc=$CG_RC]  (0=全绿;非0见上)"
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: cascade-gate $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
