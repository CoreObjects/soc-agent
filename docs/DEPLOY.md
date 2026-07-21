# soc-agent 部署 / 迁移运维手册

把 soc-agent 在一台**研判机**上立起来(首次部署或换机迁移通用)。soc-agent = invoke-per-alert 的
研判+处置编排器,没有常驻 daemon;靠 git-ferry(脚本 tee 日志到 `feedback/` + 自动 push)远程操作。

## 拓扑：哪些在本机、哪些在远端

| 组件 | 位置 | 说明 |
|---|---|---|
| **soc-agent 代码 + venv + `.env`** | **研判机本地** | 本仓 clone;venv 脚本自建;`.env` 手工填(gitignored) |
| **qwen vLLM 推理** | **研判机本地** `localhost:8000` | ★不在本仓,是外部基建(模型权重+serving+卡驱动),你自己起 |
| **openGauss 第二类经验库** | **研判机本地** `127.0.0.1:5432` | 原生装(非 docker);app 首连自动建 `soc.experience`/`soc.cases` 表 |
| **Neo4j 图库(图台账 + 响应台账)** | **远端**(靶场那台) `bolt://<range>:7687` | soc-agent 读+写台账;ingest 也在那侧写。**不随研判机迁移** |
| **处置面 appliance** | **远端**(靶场那台) `http://<range>:8765` | 处置真执行/回退在这;空 `RESPONSE_URL` 则退图台账队列通道 |

★研判机 ↔ 靶场(range)内网直连**必须绕企业代理**:代码已内置(qwen `trust_env=False`、appliance 空 `ProxyHandler`);
shell 里的 curl 记得 `--noproxy '*'`。

## Step 0 — 前置基建(soc-agent 之外，你先备好)
> ★**运维分工**:容器/podman(qwen、openGauss)= **root** 跑;soc-agent 研判/脚本 = **soc 用户**跑
> (镜像常在 root 的 rootful podman 里，soc 看不到)。具体 podman 命令见文末【附:openEuler ARM + podman 实况】。

- OS + **Python ≥3.10** + git;git remote 配好 + push 权限(ferry 要用,见 Step 5)。
- **qwen vLLM** 起在本机某端口。★soc-agent 靠强制工具调用 → **必须指向开了 tool-calling 的端口**
  (vLLM 带 `--enable-auto-tool-choice --tool-call-parser ...`);`LLM_MODEL` = 该服务的 `--served-model-name`。
  验:`curl --noproxy '*' -s http://localhost:<port>/v1/models`。qwen3 思维链由 **代码默认关**(不用管)。
  ★大模型(如 122b)若用 `--enforce-eager` 起,解码极慢、单次调用可能 >10min → 不实用,换更快的端口/模型或让部署方去掉 enforce-eager。
- **openGauss** 装好(**原生 或 podman 容器均可**)、**预先**建 database `soc` + role `soc_agent` + `soc` schema 授权
  (app 只连、不建库建角色);`.env` 的 `OG_*` 与之对齐。podman 起法 + 建库 SQL 见文末附录。
- 确认本机**直连** `<range>:7687` 与 `<range>:8765`。

## Step 1 — clone + venv + .env
```bash
git clone <repo-url> ~/soc-agent        # ★路径就用 ~/soc-agent,脚本按此 cd
cd ~/soc-agent
python3 -m venv .venv && ./.venv/bin/pip install -e ".[og,dev]"   # 或首跑脚本自建
# psycopg2:x86 有 binary 轮子直接装;若研判机是 ARM 昇腾,可能要 `apt install libpq-dev` 后源码装 psycopg2
cp .env.example .env                    # 然后手工填真值(见下)
```
`.env` 关键项(真值只在本机,绝不入公库):
```
NEO4J_URI=bolt://<range>:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<...>
LLM_API_BASE=http://localhost:8000/v1
LLM_MODEL=qwen32b-ft
OG_HOST=127.0.0.1
OG_PORT=5432
OG_DATABASE=soc
OG_USER=soc_agent
OG_PASSWORD=<...>
OG_SCHEMA=soc
RESPONSE_URL=http://<range>:8765
RESPONSE_TOKEN=<靶场 62-appliance-serve.sh 生成>
DISPOSITION_PROTECTED_HOSTS=<DC/网关名单,逗号分隔>
```

## Step 2 — 自底向上验栈(git-ferry，按序)
```bash
python scripts/preflight.py       # Neo4j + qwen 连通 + 列可研判 alert(掩码)
bash scripts/og_probe.sh          # openGauss 驱动/建表/读写往返(自动建 soc.experience/soc.cases)
bash scripts/verify_all.sh        # 全量:单测 + import + neo4j/qwen + respond_cli + 处置面 + e2e
```
每个服务缺了会**优雅降级不崩**:空 `OG_HOST`→内存经验;空 `RESPONSE_URL`→图台账队列通道;
qwen/neo4j 连不上 preflight 直接报。可分步定位。

## Step 3 — 对称清(换机迁移必做)
换机后:持久的靶场 Neo4j 里**留着旧研判机时代的 CONCLUDED 台账**,而新机 openGauss 是空的 → **不对称**
(agent 靠"无 CONCLUDED 边"判未研判,会跳过旧台账 → 那批经验补不回)。收尾对称清:
```bash
bash scripts/reset_pristine.sh    # 清靶场 Neo4j 全部台账 + 复原 appliance 态(/reset) + 清 openGauss
```
⚠️ **会抹掉靶场 Neo4j 上全部历史研判审计台账**。"起空库重学"策略下可接受(经验可重建)。
若要保留历史台账 → 别跑这步(留着可接受的不对称);要既留台账又留经验 → 迁移前 `pg_dump` 老库
`experience`/`cases` 两表搬过来 restore。

## Step 4 — 端到端两分支验通
```bash
bash scripts/e2e_experience.sh    # 误报分支:告警走全研判判 FP→蒸误报指纹→二次 AUTO_FP 复用 path=A
bash scripts/e2e_threat.sh        # 威胁分支:jon.snow roast TP→蒸威胁指纹+DSL规则+剧本→二次 AUTO_TP 复用
```
两个绿 = 部署/迁移成功。(威胁分支需图里有一条真 TP roast 告警;造样例见靶场仓
`deploy/setup/42-kerberoast-user.sh`。)

## 日常操作模型(git-ferry)
研判/验证脚本都自 `tee feedback/<name>.out` + `git add/commit/push`。操作者(你/Claude)`git pull` 读结果。
入站惯例:`cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/<x>.sh`。
单条研判:`bash scripts/run_investigation.sh <alert_uid>`;处置人审:`python -m soc_agent.respond_cli list|approve|reject|execute|rollback <plan_id>`。

## 迁移完成判据
Step 2 `verify_all` 全通 + Step 4 两分支全绿 → 新机接管,旧研判机可下线(Neo4j/appliance 在靶场那台,无残余依赖)。

---

## 附:openEuler ARM + podman 实况(2026-07 迁到新研判机，验通存档)

新机 = aarch64 / openEuler 24.09（信创），qwen 与 openGauss 都在 **podman 容器（root 管）**，soc-agent 以 **soc 用户**跑。两分支 e2e 全绿（误报 8/8 + 威胁 12/12）。

**qwen（root 起的 podman 容器，多端口）**：`podman ps` 看端口；`tr '\0' ' ' < /proc/<pid>/cmdline` 看启动参数里有没有 `--enable-auto-tool-choice --tool-call-parser qwen3_xml`（有=能用）。当时:9b 在 `:8002`(能用,32-54s/告警,质量够)、122b 在 `:8010`(能用但 `--enforce-eager` 太慢不实用)。`.env` 就填那个能用端口 + 其 `--served-model-name`。切模型 = 改 `.env` 两行 `LLM_API_BASE`/`LLM_MODEL`。

**openGauss（root，podman）**：
```bash
# root：起容器(镜像 7.0.0-RC3;GS_PASSWORD 需含大小写+数字+特殊、≥8;publish 到 127.0.0.1;数据卷持久)
podman run -d --name opengauss -e GS_PASSWORD='<强口令>' \
  -p 127.0.0.1:5432:5432 -v opengauss-data:/var/lib/opengauss/data localhost/opengauss:7.0.0-RC3
sleep 40 && podman ps -a --filter name=opengauss   # 看 Up + 5432

# root：容器内 omm 超级用户(本地 trust)建库/角色/schema —— 用 podman cp SQL 文件避免引号地狱
cat > /tmp/i1.sql <<'EOF'
CREATE DATABASE soc;
CREATE USER soc_agent WITH PASSWORD '<与 .env OG_PASSWORD 一致>';
GRANT ALL ON DATABASE soc TO soc_agent;
EOF
cat > /tmp/i2.sql <<'EOF'
CREATE SCHEMA IF NOT EXISTS soc AUTHORIZATION soc_agent;
GRANT ALL ON SCHEMA soc TO soc_agent;
EOF
podman cp /tmp/i1.sql opengauss:/tmp/ && podman cp /tmp/i2.sql opengauss:/tmp/
podman exec opengauss su - omm -c "gsql -d postgres -f /tmp/i1.sql"
podman exec opengauss su - omm -c "gsql -d soc -f /tmp/i2.sql"
```
`.env`:`OG_HOST=127.0.0.1 OG_PORT=5432 OG_DATABASE=soc OG_USER=soc_agent OG_PASSWORD=<同上> OG_SCHEMA=soc`。
app 首连自动建 `soc.experience`/`soc.cases` 表。**`psycopg2-binary` 在 aarch64 有轮子、`pip install` 直接过**（口令用 md5 存 → psycopg2 认）。

**注意点**：openGauss 首启日志里 `m_global_systupcaches not init` / `Failed to obtain $GAUSSLOG` 是无害警告;`su - omm -c gsql` 要用 `su -`(加载 omm 环境)才找得到 socket/二进制。
