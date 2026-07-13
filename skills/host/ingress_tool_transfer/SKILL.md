---
name: ingress_tool_transfer
layer: host
technique_ids: [T1105]
description: 研判"工具/载荷下载落地"(Ingress Tool Transfer)告警。当告警涉及"从外部下载工具/载荷到主机""certutil/bitsadmin/curl/PowerShell 下载""LOLBin 拉取远程文件""释放并执行木马/beacon"时选它。此类告警极吵、大多是正常下载,重点是降噪。关键词 ingress tool transfer/下载/certutil/bitsadmin/curl/IWR/DownloadString/mshta/载荷落地。
---
# Ingress Tool Transfer 研判(T1105)

**攻击本质**:把外部工具/载荷(木马、C2 beacon、提权工具、mimikatz)拉进已控主机并落地,为后续执行做准备。

**触发**:下载/掉文件类行为(内置规则,**极吵、占告警大头,多数并非攻击**;常是 EID11 掉文件)。图内落为进程的 `CONNECTED_TO`(IP)/`QUERIED`(Domain)/`WROTE`(File)。**核心是降噪,不是逐条深挖。**

## ★先看两样 recipe 已备好的东西
- **「供给/自检噪声」**:命中 `ansible_exec_wrapper` / `ps_execution_policy_probe`(`__PSScriptPolicyTest_`)= **强证伪 → false_positive**。很多"掉可执行文件"其实是 PowerShell 写策略探针 .ps1 / Ansible 供给,不是下载载荷。
- **「解码后命令(逐层)」**:命令行的 `-EncodedCommand` 已解码,按真身判,别因 base64 就当恶意。

## 研判决策树(降噪优先:先证伪批量放,再对残余深挖)
1. **命中已知良性噪声?** → 是则 FP,到此为止。
2. **触发/下载进程与父进程是"正常下载器"还是"攻击 LOLBin"?**(recipe「触发进程」「父进程」)—— 良性:`msedge/chrome/firefox`、`svchost`(WU)、`TiWorker/TrustedInstaller`、`MsMpEng`、`OneDrive/Teams`、`msiexec`。恶意/可疑:`certutil -urlcache -f`、`powershell IWR/DownloadString`、`bitsadmin /transfer`、`mshta http`,且父进程是 `w3wp/cmd/wscript`。
3. **落地文件是什么、写哪、随后被执行吗?**(recipe「落地文件」「落地即执行」)—— 落 `Temp/AppData/ProgramData/Public` 的可执行文件**且随即被 SPAWNED 执行** = 高危闭环;策略探针 `.ps1`/安装目录且未执行 = 偏良性。
4. **外连目的存在吗?**(recipe「外连目的」)—— ⚠️**IP/域信誉是图盲区(reputation 全空)**,只能看"有没有外连 + 落地是否即执行",别臆造信誉好坏。
5. **同主机此刻有别的攻击面告警吗?** —— 同窗口有 LSASS/webshell/持久化 → 从"孤立噪声"升为攻击链一环。

## 误报/良性场景(降噪主战场,逐条)
- **浏览器正常下载** —— 最大宗 FP(父=explorer/浏览器 + 目的=大厂 CDN)。
- **系统/软件更新**(Windows Update svchost/wuauclt、TiWorker、Defender 更新、Chrome/Edge/Teams/OneDrive 自更新)。
- **软件分发/包管理**(SCCM/Intune、msiexec、choco/winget/pip/npm)。
- **管理员正常运维**(手动 curl/IWR 下工具、git clone)—— 靠交互式管理员会话 + 目的信誉 + 落运维目录而非 Temp 区分。

## 判定逻辑
- **false_positive/benign(占绝大多数)**:命中 Ansible/策略探针噪声 **或** 下载进程 ∈ 白名单更新器/浏览器 **或** 落安装目录/策略探针 `.ps1` 且未执行。
- **suspicious**:LOLBin/编码下载但无落地执行、无外连 → 观察挂起(信誉是盲区,别硬判坏)。
- **true_positive**:非白名单 LOLBin/编码下载 **且**(落 Temp/AppData 即被 SPAWNED 执行 **或** 同主机同窗有其他攻击链告警)。**注意:信誉盲区,不能只凭"有外连"就判 TP。**

## ⚠️只依据证据,禁止臆造
只引用 recipe 实际取回的进程/文件/外连。**信誉字段是盲区(全空),不要脑补"目的地信誉好/坏"**;没取到父进程就别编。缺失 → 写 missing_evidence。

## 图盲区(取不到就写 missing_evidence)
完整下载 URL/文件名(只有域/IP)、落地文件哈希(FileCreate 常无)、下载进程 EXE 签名、**IP/域信誉(reputation/asn 未建模,全空)**。(`-EncodedCommand` 解码后内容 recipe 现已提供。)
