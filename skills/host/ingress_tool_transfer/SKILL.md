---
name: ingress_tool_transfer
layer: host
technique_ids: [T1105]
description: 研判"工具/载荷下载落地"(Ingress Tool Transfer)告警。当告警涉及"从外部下载工具/载荷到主机""certutil/bitsadmin/curl/PowerShell 下载""LOLBin 拉取远程文件""释放并执行木马/beacon"时选它。此类告警极吵、大多是正常下载,重点是降噪。关键词 ingress tool transfer/下载/certutil/bitsadmin/curl/IWR/DownloadString/mshta/载荷落地。
---
# Ingress Tool Transfer 研判(T1105)

**攻击本质**:把外部工具/载荷(木马、C2 beacon、提权工具、mimikatz)拉进已控主机并落地,为后续执行做准备。

**触发**:下载类行为(内置规则,**极吵、占告警大头,多数并非攻击**)。图内落为下载进程的 `CONNECTED_TO`(IP,标量 dest_port)/`QUERIED`(Domain)/`WROTE`(File)。**核心是降噪,不是逐条深挖。**

## 研判决策树(降噪优先:先证伪批量放,再对残余深挖)
1. **下载进程与父进程是"正常下载器"还是"攻击 LOLBin"?**(recipe「下载进程与父链」)—— 良性:`msedge/chrome/firefox`、`svchost`(WU)、`TiWorker/TrustedInstaller`、`MsMpEng`、`OneDrive/Teams`、`msiexec`。恶意/可疑:`certutil -urlcache -f`、`powershell IWR/DownloadString`、`bitsadmin /transfer`、`mshta http`,且父进程是 `w3wp/cmd/wscript`。
2. **外连目的地可疑吗?**(recipe「外连目标」:IP 信誉/域/端口)—— 微软/厂商 CDN(信誉好、大厂 ASN)→ FP;裸 IP、坏信誉、新注册域、非常见端口 → 升权。
3. **落地文件是什么、写哪、随后被执行吗?**(recipe「落地与执行」)—— 落 `Temp/AppData/ProgramData/Public` 的可执行文件**且随即被 SPAWNED 执行** = 高危闭环;落安装目录且未执行 = 偏良性。
4. **同主机此刻有别的攻击面告警吗?** —— 同窗口有 LSASS/webshell/持久化 → 从"孤立噪声"升为攻击链一环(可让 agent 另查,或结合经验)。

## 误报/良性场景(降噪主战场,逐条)
- **浏览器正常下载** —— 最大宗 FP(父=explorer/浏览器 + 目的=大厂 CDN)。
- **系统/软件更新**(Windows Update svchost/wuauclt、TiWorker、Defender 更新、Chrome/Edge/Teams/OneDrive 自更新)。
- **软件分发/包管理**(SCCM/Intune、msiexec、choco/winget/pip/npm)。
- **管理员正常运维**(手动 curl/IWR 下工具、git clone)—— 靠交互式管理员会话 + 目的信誉 + 落运维目录而非 Temp 区分。

## 判定逻辑
- **false_positive/benign(占绝大多数)**:下载进程 ∈ 白名单更新器/浏览器 **或** 目的信誉好且落安装目录且未执行。
- **suspicious**:LOLBin 下载但目的信誉未知/未见落地执行 → 观察挂起。
- **true_positive**:非白名单 LOLBin/编码下载 **且**(目的坏信誉 **或** 落 Temp/AppData 即被执行 **或** 同主机同窗有其他攻击链告警)。

## 图盲区(取不到就写 missing_evidence)
完整下载 URL/文件名(只有域/IP)、落地文件哈希/信誉(Sysmon FileCreate 常无哈希)、下载进程 EXE 签名、IP 信誉是否实时/覆盖 CDN。
