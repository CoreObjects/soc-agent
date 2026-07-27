#!/usr/bin/env bash
# server2:后台起控制台(uvicorn :8000)+ 打印能访问的 IP + 本机自测。ferry。★uvicorn 后台常驻,脚本退了它还在。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/web-serve.sh
#   停: pkill -f 'uvicorn soc_agent.web.app'
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || { echo "!! 缺 venv"; exit 1; }

mkdir -p logs feedback
FB="feedback/web-serve.out"
{
  echo "=== web-serve  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- 装 web 依赖(幂等)--"
  "$PY" -m pip install -q -e '.[web]' 2>&1 | tail -2 || echo "  (pip install 有告警,见上)"

  # ★每次都重启:静态 dist 实时读盘,但后端 Python 代码在运行进程里不会随 git pull 重载 → 必须重起才拾取最新
  if pgrep -f "uvicorn soc_agent.web.app" >/dev/null 2>&1; then
    echo "-- 已有 uvicorn 在跑 → 先停(拾取最新后端代码)--"
    pkill -f "uvicorn soc_agent.web.app" 2>/dev/null || true
    sleep 2
  fi
  echo "-- 后台启动 uvicorn :8000 --"
  nohup env PYTHONUTF8=1 "$PY" -m uvicorn soc_agent.web.app:app --host 0.0.0.0 --port 8000 \
    > logs/web.log 2>&1 &
  sleep 5
  echo "  PID=$!  日志 logs/web.log"

  echo "-- 8000 端口监听检查 --"
  (ss -ltn 2>/dev/null | grep ':8000' || netstat -ltn 2>/dev/null | grep ':8000' \
    || echo "  ⚠ 没抓到 8000 监听 —— 看下面日志") | head -3

  echo "-- 本机自测(curl 绕代理)--"
  if curl -s --noproxy '*' -m 8 http://127.0.0.1:8000/api/healthz 2>/dev/null | grep -q '"ok"'; then
    echo "  ✅ 本机 healthz 通 → 服务本身没问题;剩下就是从你电脑能不能连到下面某个 IP"
  else
    echo "  ⚠ 本机自测没通 —— 服务没起好,看日志:"; tail -8 logs/web.log 2>/dev/null
  fi

  echo "-- server2 的 IP(浏览器挨个试 http://<IP>:8000,优先 100.x)--"
  ip -4 addr 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | grep -v '^127\.' \
    | sed 's#^#   http://#; s#$#:8000#' || hostname -I 2>/dev/null || echo "  (取 IP 失败,用 ip addr 手看)"

  echo
  echo "★ 若上面 IP 浏览器仍连不上(但本机 healthz 通)= 防火墙挡了 8000。用 root 开:"
  echo "    sudo firewall-cmd --add-port=8000/tcp        # 临时(重启失效)"
  echo "    sudo firewall-cmd --add-port=8000/tcp --permanent && sudo firewall-cmd --reload   # 永久"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: web-serve" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
