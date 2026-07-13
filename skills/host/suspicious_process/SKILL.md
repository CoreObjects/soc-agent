---
name: suspicious_process
layer: host
technique_ids: [T1059, T1059.001, T1055, T1218]
description: 研判可疑进程/命令执行/LOLBin/恶意子进程告警。当告警涉及"异常父进程派生 shell(w3wp/services/spoolsv 生 cmd/powershell)""编码 PowerShell(-enc/EncodedCommand)""LOLBin 滥用(rundll32/mshta/regsvr32/certutil)""进程注入""可疑命令行"时选它。关键词 suspicious process/command execution/LOLBin/rundll32/mshta/regsvr32/encoded command/powershell -enc/进程注入/父子进程链。
---
# 可疑进程 / LOLBin / 恶意子进程研判(T1059 / T1055 / T1218)

**攻击本质**:借合法二进制(LOLBin:rundll32/mshta/regsvr32/certutil)或从异常父进程(webshell、被利用服务)派生 shell,执行编码命令/下载执行/注入,规避基于"陌生 EXE"的检测。

**触发**:进程创建(Sysmon EID1)命中异常父子链或可疑命令行。图内落为 `(:Event)-[:BY]->父Process`、`-[:SPAWNED]->子Process`,子进程带 `command_line`,派生 `RAN_AS`→Account。

## 研判决策树(端点主判法:父子链还原 + 命令行)
1. **父进程是不是"不该生 shell 的进程"?**(recipe「父子进程」)—— 高危父进程:`w3wp/httpd/tomcat`(webshell)、`services/spoolsv/wmiprvse/sqlservr` 派生 `cmd/powershell/rundll32/mshta` = 强 TP 信号。
2. **命令行有无恶意特征?**(recipe 里的 child command_line)—— `-enc/-EncodedCommand`、`-nop -w hidden`、`DownloadString/IEX/FromBase64String`、`rundll32` 无参/可疑导出、`regsvr32 /s /u /i:http`、`mshta http`、`certutil -decode`。
3. **子进程以什么身份运行?(webshell 判定关键)**(recipe「子进程账号」)—— `IIS APPPOOL\*` / `NETWORK SERVICE` 跑 powershell/cmd = webshell 强指纹。
4. **子进程随后做了什么?(把链拉全)**(recipe「后续行为」:派生/外连/LSASS/注册表)—— 派生 → 外连 C2 / 读 LSASS / 写 Run 键 = 攻击链闭环,直接 TP。
5. **是不是运维/软件的正常派生?** —— 见误报。

## 误报/良性场景(逐条)
- **管理运维正常调 shell**(管理员 explorer/终端派生 powershell/cmd、psexec、schtasks、登录脚本 gpscript→cmd)—— 父=交互式 + 无编码 + 管理员会话。
- **合法软件用 LOLBin**(安装器调 rundll32 带正常导出参数、regsvr32 注册 DLL、msiexec、GPO 脚本)—— `rundll32` **有**合法导出参数 vs 无参/可疑导出。
- **RMM/监控/备份**以服务身份派生子进程;**开发/CI**(node/python/msbuild 派生 shell)。

## 判定逻辑
- **true_positive**:异常父进程(w3wp/services/spoolsv/wmiprvse/sqlservr)派生 shell/LOLBin **或**命令行含 -enc/下载执行 **且**(以服务/低权账户运行 **或**有后续 SPAWNED→外连/LSASS/持久化)。
- **false_positive**:交互式管理员会话 或 合法安装器/GPO 派生,命令行有业务语义、无编码/下载。
- **suspicious**:命令行可疑但父链交互式、无后续恶意行为 → 挂起(⚠️ 进程签名/完整性级别/解码后命令是图盲区)。

## 图盲区(取不到就写 missing_evidence)
进程 EXE 签名/是否 LOLBin 原版、完整性级别/Token 提权、`-EncodedCommand` 解码后内容、注入子行为细节。
