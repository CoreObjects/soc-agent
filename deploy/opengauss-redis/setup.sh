#!/usr/bin/env bash
# =============================================================================
# 起 openGauss(权威规则库)+ Redis(热读)容器 + 冒烟验证 + 自 ferry(★不打印/不提交密码)。
# 密码从 soc-agent/.env 读(不进仓库):OG_PASSWORD / REDIS_PASSWORD 必填。
#   openGauss GS_PASSWORD 复杂度:≥8 位,含 大写+小写+数字+特殊字符(如 Soc@Pattern2026)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main
#        # 先在 ~/soc-agent/.env 写 OG_PASSWORD=... 和 REDIS_PASSWORD=...
#        bash deploy/opengauss-redis/setup.sh
# 镜像拉不动(代理拦)→ 见文末"手动摆渡"。
# =============================================================================
set -u
cd "$(cd "$(dirname "$0")/../.." && pwd)" || exit 1
[ -f .env ] && set -a && . ./.env && set +a
OUT="feedback/opengauss-redis.out"; mkdir -p feedback
OG_IMG="${OG_IMG:-opengauss/opengauss:5.0.0}"    # 用你们信创的 openGauss 系镜像也行:export OG_IMG=...
RD_IMG="${RD_IMG:-redis:7}"
OG_PORT="${OG_PORT:-15432}"; RD_PORT="${RD_PORT:-16379}"
D="sudo docker"

if [ -z "${OG_PASSWORD:-}" ] || [ -z "${REDIS_PASSWORD:-}" ]; then
  echo "!! 请先在 ~/soc-agent/.env 里写:"
  echo "   OG_PASSWORD=Soc@Pattern2026      # openGauss(≥8位,大写+小写+数字+特殊字符)"
  echo "   REDIS_PASSWORD=Soc_Redis_2026    # Redis"
  echo "   (可选)OG_IMG=你们的openGauss镜像  OG_PORT=15432  RD_PORT=16379"
  exit 1
fi

{
  echo "=== openGauss+Redis provision $(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  echo "[1] 镜像(优先服务器网直拉)"
  for img in "$OG_IMG" "$RD_IMG"; do
    if $D image inspect "$img" >/dev/null 2>&1; then echo "  已在本地: $img";
    else echo "  pull $img …"; $D pull "$img" 2>&1 | tail -2 | sed 's/^/    /'; fi
  done
  echo "[2] 起 openGauss(host :$OG_PORT → 容器 5432)"
  $D rm -f soc-opengauss >/dev/null 2>&1 || true
  $D run -d --name soc-opengauss -e GS_PASSWORD="$OG_PASSWORD" -p "$OG_PORT":5432 \
     --restart unless-stopped "$OG_IMG" 2>&1 | tail -1 | sed 's/^/  cid /'
  echo "[3] 起 Redis(host :$RD_PORT → 容器 6379)"
  $D rm -f soc-redis >/dev/null 2>&1 || true
  $D run -d --name soc-redis -p "$RD_PORT":6379 --restart unless-stopped "$RD_IMG" \
     redis-server --requirepass "$REDIS_PASSWORD" 2>&1 | tail -1 | sed 's/^/  cid /'
  echo "[4] 等就绪 ~35s"; sleep 35
  echo "[5] 冒烟(不打印密码)"
  echo "  容器状态:"; $D ps --filter name=soc-opengauss --filter name=soc-redis \
     --format '    {{.Names}}  {{.Status}}  {{.Ports}}' 2>&1
  echo "  redis ping : $($D exec soc-redis redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null)"
  echo "  openGauss 就绪日志(找 ready/normal/listen):"
  $D logs soc-opengauss 2>&1 | grep -iE "ready to accept|state:normal|database system is ready|listen|gaussdb" | tail -6 | sed 's/^/    /'
  echo "  openGauss gsql 版本(容器内,权威连通性):"
  $D exec soc-opengauss bash -lc "gsql -d postgres -U gaussdb -c 'select version();' 2>&1 || su - omm -c \"gsql -d postgres -c 'select version();'\" 2>&1" 2>&1 | grep -iE "openGauss|gsql|error|failed|role|password" | head -4 | sed 's/^/    /'
  echo "=== done ==="
} 2>&1 | tee "$OUT"

git add "$OUT" >/dev/null 2>&1 || true
git commit -q -m "feedback: opengauss+redis provision $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/opengauss-redis.out(无密码)"
