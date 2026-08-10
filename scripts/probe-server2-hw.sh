#!/usr/bin/env bash
# server2 硬件/资源画像(只读)—— 回答:若未来把知识图谱(Neo4j 写入)放在 server2 这种机器上,
#   写吞吐天花板 + 与 vLLM/openGauss 共存的 RAM 余量 够不够。★纯 shell、不装任何东西、不改任何东西。
# 关注点(相对通用 env-info):① 盘是不是 SSD(ROTA)→ 决定小事务提交速率 ② vLLM/openGauss 吃掉后**剩多少 RAM 给图 page cache**
#   ③ 有没有 JVM(Neo4j 需要) ④ 容器运行时(docker/rootless podman) ⑤ 已驻留服务端口(5432/8000/7687...)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/probe-server2-hw.sh
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p feedback
FB="feedback/probe-server2-hw.out"

{
  echo "=== server2 硬件/资源画像(只读)  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="

  echo; echo "== [1] 主机 / OS / 内核 / 架构 =="
  if [ -f /etc/os-release ]; then . /etc/os-release 2>/dev/null; echo "  OS: ${PRETTY_NAME:-?}"; else echo "  OS: (无 /etc/os-release)"; fi
  echo "  内核: $(uname -r 2>/dev/null)   架构: $(uname -m 2>/dev/null)   主机: $(uname -n 2>/dev/null)"

  echo; echo "== [2] CPU(核数=并发事务处理能力;但 70eps 单写者用不满)=="
  lscpu 2>/dev/null | grep -iE 'Architecture|Model name|Vendor ID|^CPU\(s\)|Core|Socket|BIOS Model name' | sed 's/^/  /' \
    || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/^/  /' || echo "  (取不到 CPU)"
  echo "  逻辑核: $(nproc 2>/dev/null || echo '?')   负载(1/5/15m):$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')"

  echo; echo "== [3] 内存 —— ★共存关键:vLLM/openGauss 吃掉后剩多少给图 page cache =="
  free -h 2>/dev/null | sed 's/^/  /' || echo "  (无 free)"
  echo "  -- 当前 RSS TOP10 进程(看 vLLM/python/gaussdb 已占多少)--"
  ps -eo rss,pid,comm --sort=-rss 2>/dev/null | head -11 | \
    awk 'NR==1{printf "     %10s %8s  %s\n","RSS(KB)","PID","COMM";next}{printf "     %10s %8s  %s\n",$1,$2,$3}' \
    || echo "     (无 ps)"

  echo; echo "== [4] 磁盘 —— ★ROTA=0 是 SSD/NVMe(小事务提交上千/秒);=1 是 HDD(fsync 受限,不适合图) =="
  if command -v lsblk >/dev/null 2>&1; then
    lsblk -d -o NAME,SIZE,ROTA,TYPE,MODEL 2>/dev/null | sed 's/^/  /' || echo "  (lsblk 出错)"
  else echo "  (无 lsblk)"; fi
  echo "  -- 挂载点可用空间(图 store 落哪就看哪个)--"
  df -h 2>/dev/null | grep -vE '^(tmpfs|devtmpfs|overlay|shm)' | sed 's/^/  /' || echo "  (无 df)"

  echo; echo "== [5] JVM(Neo4j 是 JVM 应用,ARM 上需 arm64 JDK 才能跑)=="
  if command -v java >/dev/null 2>&1; then java -version 2>&1 | sed 's/^/  /'
  else
    echo "  (PATH 无 java)"; for j in /usr/lib/jvm/*/bin/java /opt/*/bin/java; do [ -x "$j" ] && { echo "  发现: $j"; "$j" -version 2>&1 | head -1 | sed 's/^/    /'; }; done
  fi

  echo; echo "== [6] 容器运行时(决定图是容器化还是原生装;记忆:server2 只有未配的 rootless podman)=="
  for rt in docker podman; do
    if command -v "$rt" >/dev/null 2>&1; then
      echo "  $rt: $($rt --version 2>/dev/null | head -1)"
      "$rt" info --format '    storage-driver={{.Driver}} rootless={{.Host.Security.Rootless}}' 2>/dev/null || echo "    (info 取不到——可能未起服务/未配 rootless)"
    else echo "  $rt: (无)"; fi
  done

  echo; echo "== [7] 已驻留服务端口(5432=openGauss 8000=vLLM 7687/7474=Neo4j 9200=ES 9092=Kafka)=="
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -E ':(5432|8000|7687|7474|9200|9092)\b' | sed 's/^/  /' || echo "  (以上端口均未监听)"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | grep -E ':(5432|8000|7687|7474|9200|9092)\b' | sed 's/^/  /' || echo "  (以上端口均未监听)"
  else echo "  (无 ss/netstat)"; fi

  echo; echo "== [8] 昇腾 NPU(确认机器身份;NPU 与图要用的 CPU/RAM 是分开的资源)=="
  if command -v npu-smi >/dev/null 2>&1; then npu-smi info 2>&1 | head -16 | sed 's/^/  /'
  else echo "  (无 npu-smi —— 非昇腾节点或 NPU 在别处)"; fi

  echo; echo "== 判读(接回 IO 天花板问题)=="
  echo "  · [4] 若 ROTA=0(SSD/NVMe)+ [2] 多核 → 单写者 Neo4j 仍做上千小事务/秒 → 70eps(100x)照样是零头,"
  echo "        写 TPS 在 server2 这种机器上也不是墙。若 ROTA=1(HDD)才需担心 fsync 提交速率。"
  echo "  · [3] 真正约束 = RAM 余量:vLLM(通常吃大块)+ openGauss 占用后 free/available 还剩多少,"
  echo "        决定图 page cache 能不能装下'有界骨架(身份+告警+近期事件)'的热工作集。这才是共存的风险点,不是写 TPS。"
  echo "  · [6]/[7] 若无 docker、且 8000/5432 已被 vLLM/openGauss 占 → 图放这台得原生装 Neo4j(+arm64 JDK[5]),与它们抢 RAM;"
  echo "        更稳的架构=图仍独占一台(像现在 server1),server2 只跑研判只读查 bolt。拿到数再定。"
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry(与 og_probe 同约定:server2 跑完自动 push 回 feedback/)
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: probe-server2-hw $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
