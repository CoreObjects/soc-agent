#!/usr/bin/env bash
# 重建 openGauss 容器 —— 去掉它身上那套已经失效的 SELinux 标签,并顺手加上重启策略。
#
# 为什么要重建(2026-08-13 查实):
#   容器创建时 SELinux 还开着,身上焊了 MountLabel/ProcessLabel;而现在内核里
#   `getenforce = Disabled`。podman 启动时把 `context=...` 传给 shm 的 tmpfs 挂载,
#   内核不认这个参数 → EINVAL → 就是那句 `failed to mount shm tmpfs: invalid argument`。
#   同机另外三个容器没事,是因为它们在 SELinux 关掉**之后**才创建的、身上没标签。
#   ⇒ SELinux 其实早就关了,opengauss 只因一直没重启才活着;这次重启把它暴露出来。
#
#   podman 4.9 无法给**已存在**的容器改标签或重启策略(`podman update --restart` 是 5.x 才有),
#   所以只能重建。**数据安全**:数据在具名卷 opengauss-data 里,与容器生命周期无关。
#
# ★为什么做成脚本而不是让人粘命令:上一轮那段多行长命令在粘贴过程中被吃掉了字符
#   (引号没闭合、shell 卡在续行符),白折腾一轮。仓库脚本对粘贴免疫。
#
# 用法(★以 **root** 跑,podman 是 rootful 的):
#   bash /home/soc/soc-agent/scripts/og-recreate.sh              # 只读:打印将要执行什么
#   bash /home/soc/soc-agent/scripts/og-recreate.sh --execute    # 真做
#
# ★本脚本不碰 git、不 ferry:root 在 soc 的仓库里跑 git 会撞 dubious ownership,
#   还会把 .git 弄成 root 所有。结果直接打屏幕,短得可以直接贴回来。
set -uo pipefail

C=opengauss
OLD=opengauss-old
VOL=opengauss-data
EXEC=0
[ "${1:-}" = "--execute" ] && EXEC=1

die() { echo "❌ $*"; exit 1; }

[ "$(id -u)" = "0" ] || die "要以 root 跑(podman 是 rootful 的,soc 用户看不到这些容器)。"
command -v podman >/dev/null || die "没有 podman。"

echo "=== 重建 openGauss 容器 $( [ "$EXEC" = 1 ] && echo '(真做)' || echo '(★只读,不动任何东西)' ) ==="
echo

# ---------------------------------------------------------------- 前置检查
podman container exists "$C" || die "容器 $C 不存在(是不是已经重建过、或改过名?先 podman ps -a 看看)。"
STATE="$(podman inspect "$C" --format '{{.State.Status}}')"
IMG="$(podman inspect "$C" --format '{{.ImageName}}')"
MTYPE="$(podman inspect "$C" --format '{{range .Mounts}}{{.Type}}{{end}}')"
MNAME="$(podman inspect "$C" --format '{{range .Mounts}}{{.Name}}{{end}}')"
MDEST="$(podman inspect "$C" --format '{{range .Mounts}}{{.Destination}}{{end}}')"
PORTS="$(podman inspect "$C" --format '{{json .HostConfig.PortBindings}}')"
MLABEL="$(podman inspect "$C" --format '{{.MountLabel}}')"

echo "--- 现状 ---"
echo "  容器状态 : $STATE"
echo "  镜像     : $IMG"
echo "  数据卷   : type=$MTYPE name=$MNAME → $MDEST"
echo "  端口     : $PORTS"
echo "  SELinux  : 内核 $(getenforce 2>/dev/null || echo '?') / 容器标签 ${MLABEL:-（无）}"
echo

# 这三条任一不满足就别往下走 —— 重建的安全性全靠它们
[ "$MTYPE" = "volume" ] || die "数据不在**具名卷**里(type=$MTYPE),重建会丢数据。停手,先人工确认。"
[ "$MNAME" = "$VOL" ]   || die "卷名不是 $VOL(而是 '$MNAME'),与预期不符。停手。"
podman volume exists "$VOL" || die "卷 $VOL 不存在。停手。"
if [ "$STATE" = "running" ]; then
  echo "★容器已经在跑了 —— 那就不用重建。"
  echo "  (若只是想加重启策略,podman 4.9 改不了已存在的容器,仍需重建;那就先 podman stop $C 再跑本脚本。)"
  exit 0
fi
podman container exists "$OLD" && die "已存在 $OLD —— 上一次重建的退路还在。先确认它可以丢弃再 podman rm $OLD。"

# ---------------------------------------------------------------- 还原运行时参数
# ★不猜:运行时 env = 容器 env **减去** 镜像自带 env。GS_PASSWORD 原样带过去、不经屏幕。
IMGENV="$(mktemp)"; CTRENV="$(mktemp)"
trap 'rm -f "$IMGENV" "$CTRENV"' EXIT
podman image inspect "$IMG" --format '{{range .Config.Env}}{{println .}}{{end}}' > "$IMGENV" 2>/dev/null || true
podman inspect "$C"        --format '{{range .Config.Env}}{{println .}}{{end}}' > "$CTRENV"

ENVARGS=()
while IFS= read -r line; do
  [ -n "$line" ] || continue
  ENVARGS+=(-e "$line")
done < <(grep -vxF -f "$IMGENV" "$CTRENV" || true)

echo "--- 将要执行 ---"
echo "  podman rename $C $OLD          # ★留退路,不删"
echo "  podman run -d --name $C \\"
echo "      --security-opt label=disable \\      # 不再打 SELinux 标签(内核里已关)"
echo "      --restart=always \\                  # 配合已 enable 的 podman-restart.service"
for a in "${ENVARGS[@]}"; do
  [ "$a" = "-e" ] && continue
  echo "      -e ${a%%=*}=*** \\"
done
echo "      -p 127.0.0.1:5432:5432 \\"
echo "      -v $VOL:$MDEST \\"
echo "      $IMG"
echo "  systemctl disable --now container-opengauss.service   # 那个 unit 正在失败循环里,不再需要"
echo "  (运行时环境变量共 $(( ${#ENVARGS[@]} / 2 )) 个,值不打屏)"
echo

if [ "$EXEC" != "1" ]; then
  echo "★只读结束。确认无误后加 --execute 真做。"
  exit 0
fi

# ---------------------------------------------------------------- 真做
echo "--- 执行 ---"
podman rename "$C" "$OLD" || die "rename 失败,什么都没动。"
echo "  已改名 $C → $OLD(退路)"

if ! podman run -d --name "$C" \
      --security-opt label=disable \
      --restart=always \
      "${ENVARGS[@]}" \
      -p 127.0.0.1:5432:5432 \
      -v "$VOL:$MDEST" \
      "$IMG"; then
  echo
  echo "❌ 新容器起不来。**回滚**(数据一直在卷里,没动过):"
  echo "     podman rm $C 2>/dev/null; podman rename $OLD $C"
  exit 1
fi

echo "  新容器已创建,等它初始化(20s)…"
sleep 20
echo
echo "--- 验证 ---"
podman ps --format '  {{.Names}}  {{.Status}}  {{.Image}}' | grep -E "$C|NAMES" || true
echo "  5432 在听吗:"
ss -tln 2>/dev/null | grep 5432 | sed 's/^/    /' || echo "    ★没在听 —— 看日志:podman logs --tail 30 $C"
echo "  重启策略:$(podman inspect "$C" --format '{{.HostConfig.RestartPolicy.Name}}')"
systemctl disable --now container-opengauss.service >/dev/null 2>&1 \
  && echo "  已停用 container-opengauss.service(它在失败循环里;重启自启改由 --restart=always + podman-restart.service 负责)"
echo
echo "--- 收尾 ---"
echo "  · 一切正常后回收退路:  podman rm $OLD"
echo "  · 要回滚:              podman rm $C && podman rename $OLD $C"
echo "  · 然后切回 soc 用户跑重放基线:"
echo "      su - soc"
echo "      cd ~/soc-agent && git fetch origin && git reset --hard origin/main && LIMIT=200 bash scripts/replay-reuse.sh"
echo "=== done ==="
