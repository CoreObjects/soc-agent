#!/usr/bin/env bash
# server2:一次性采集 openJiuwen 运行环境 —— 填 GitCode issue 的"详细环境信息"字段。只读、不改任何东西。
# 覆盖:OS/内核/架构 + CPU/内存 + 昇腾 NPU 驱动/CANN + Python 与 openjiuwen 及关键依赖版本 + LLM 后端。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/env-info.sh
set -u
cd "$(dirname "$0")/.."
mkdir -p feedback
FB="feedback/env-info.out"

{
  echo "=== openJiuwen 运行环境采集(server2)  $(date -u '+%F %H:%MZ' 2>/dev/null) ==="

  echo; echo "== OS / 内核 / 架构 =="
  if [ -f /etc/os-release ]; then . /etc/os-release 2>/dev/null; echo "  OS: ${PRETTY_NAME:-?}"; else echo "  OS: (无 /etc/os-release)"; fi
  echo "  内核: $(uname -r 2>/dev/null)   架构: $(uname -m 2>/dev/null)   主机: $(uname -n 2>/dev/null)"

  echo; echo "== CPU =="
  lscpu 2>/dev/null | grep -iE 'Architecture|Model name|Vendor ID|^CPU\(s\)|BIOS Model name|Byte Order' | sed 's/^/  /' \
    || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/^/  /' || echo "  (取不到 CPU 信息)"

  echo; echo "== 内存 =="
  free -h 2>/dev/null | sed 's/^/  /' || echo "  (无 free)"

  echo; echo "== 昇腾 NPU / 驱动 / CANN(LLM 后端所在;openjiuwen 仅经 HTTP 连它,非直接用 NPU) =="
  if command -v npu-smi >/dev/null 2>&1; then
    npu-smi info 2>&1 | head -22 | sed 's/^/  /'
  else
    echo "  (无 npu-smi —— 本机非昇腾节点/未装驱动,或 NPU 在别的机器)"
  fi
  for v in /usr/local/Ascend/driver/version.info \
           /usr/local/Ascend/ascend-toolkit/latest/version.cfg \
           /usr/local/Ascend/ascend-toolkit/latest/*/ascend_toolkit_install.info; do
    [ -f "$v" ] && { echo "  -- $v --"; head -6 "$v" 2>/dev/null | sed 's/^/    /'; }
  done

  echo; echo "== Python 解释器 + openjiuwen 及关键依赖版本(探多个候选) =="
  CANDS=(".venv312/bin/python" ".venv/bin/python" ".venv311/bin/python" \
         "python3.13" "python3.12" "python3.11" "python3")
  # 追加发现的 *venv*/bin/python(cascade-gate 建的等)
  for extra in $(ls -d ./*venv*/bin/python ~/*venv*/bin/python 2>/dev/null); do CANDS+=("$extra"); done
  seen=""
  for PY in "${CANDS[@]}"; do
    RP="$(command -v "$PY" 2>/dev/null || { [ -x "$PY" ] && echo "$PY"; })"; [ -n "$RP" ] || continue
    key="$("$RP" -c 'import sys;print(sys.executable)' 2>/dev/null)" || continue
    case " $seen " in *" $key "*) continue;; esac; seen="$seen $key"
    ver="$("$RP" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null)"
    echo "  -- $key  (Python $ver) --"
    "$RP" - <<'PYEOF' 2>&1 | sed 's/^/      /'
import importlib.metadata as m
def v(p):
    try: return m.version(p)
    except Exception: return "—(未装)"
oj = v("openjiuwen")
print(f"openjiuwen = {oj}")
if oj != "—(未装)":
    for p in ["openai","httpx","httpcore","anyio","pydantic","aiohttp","grpcio"]:
        print(f"{p} = {v(p)}")
PYEOF
  done

  echo; echo "== LLM 后端(openjiuwen 经 OpenAI 兼容端点连它) =="
  BASE="$(sed -n 's/^LLM_API_BASE=//p' .env 2>/dev/null)"; BASE="${BASE:-http://100.102.211.138:8080/v1}"
  echo "  端点: $BASE"
  curl -s --noproxy '*' -m 10 "${BASE%/}/models" 2>/dev/null | head -c 800 | sed 's/^/  /models: /' || echo "  (探 /models 失败)"
  echo

  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: env-info" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
