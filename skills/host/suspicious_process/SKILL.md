---
name: suspicious_process
layer: host
technique_ids: [T1059, T1059.001, T1055, T1218]
description: 研判可疑进程/命令执行/LOLBin/恶意子进程告警。当告警涉及"异常父进程派生 shell(w3wp/services/spoolsv 生 cmd/powershell)""编码 PowerShell(-enc/EncodedCommand)""LOLBin 滥用(rundll32/mshta/regsvr32/certutil)""进程注入""可疑命令行"时选它。关键词 suspicious process/command execution/LOLBin/rundll32/mshta/regsvr32/encoded command/powershell -enc/进程注入/父子进程链。
needs: [process_spawn_telemetry, process_access_telemetry, network_flow_telemetry]
---
# 可疑进程 / LOLBin / 恶意子进程研判(T1059 / T1055 / T1218)

**攻击本质**:借合法二进制(LOLBin:rundll32/mshta/regsvr32/certutil)或从异常父进程(webshell、被利用服务)派生 shell,执行编码命令/下载执行/注入,规避基于"陌生 EXE"的检测。

**触发**:可能是进程创建(Sysmon EID1)、脚本文件落地(EID11)、或脚本块日志(EID4104)。**别假设一定有父子链** —— EID11/4104 没有子进程,决定性证据是命令行 / 脚本块本身。recipe 已按事件类型把 `command_line`、`script_block_text`、落地文件、子进程(若有)一并取回。

## ★先看两样 recipe 已备好的东西(避免看不懂编码就误判/幻觉)
- **「解码后命令(逐层)」**:recipe 已把 `-EncodedCommand` 连锁解码。**就按解码后的真身判**,不要因为原始是 base64 就一律当恶意。
- **「供给/自检噪声」**:命中 `ansible_exec_wrapper`(配管工具供给)或 `ps_execution_policy_probe`(`__PSScriptPolicyTest_`,系统执行策略自检)= **强证伪 → 直接 false_positive**。凡用 Ansible 配管的环境海量出现,是头号 FP(如本靶场)。

## 研判决策树(端点主判法:父子链还原 + 命令行)
1. **命中已知良性噪声?** → 是则 FP,到此为止;否则继续。
2. **父进程是不是"不该生 shell 的进程"?**(recipe「父进程」,仅 EID1 有)—— 高危父进程:`w3wp/httpd/tomcat`(webshell)、`services/spoolsv/wmiprvse/sqlservr` 派生 `cmd/powershell/rundll32/mshta` = 强 TP 信号。
3. **命令行(含解码后)有无恶意特征?** —— `DownloadString/IEX/FromBase64String` 拉远程执行、`-nop -w hidden`、`rundll32` 无参/可疑导出、`regsvr32 /s /u /i:http`、`mshta http`、`certutil -decode`、写自启/加计划任务。解码后是良性运维脚本(Ansible/健康检查/`Write-Host`)则降权。
4. **子进程随后做了什么?**(recipe「子进程后续行为」)—— 派生 → 外连 / 读 LSASS = 攻击链闭环,直接 TP。
5. **是不是运维/软件的正常派生?** —— 见误报。

## 误报/良性场景(逐条)
- **★Ansible 配管供给 与 PowerShell 执行策略自检**(`__PSScriptPolicyTest_*.ps1`、`ConvertFrom-AnsibleJson`/`exec_wrapper`)—— 配管环境头号 FP(如本靶场),凭「供给/自检噪声」标签即可判 FP。
- **管理运维正常调 shell**(管理员终端派生 powershell/cmd、psexec、schtasks、登录脚本)—— 交互式 + 解码后有业务语义。
- **合法软件用 LOLBin**(安装器 rundll32 带正常导出参数、regsvr32 注册 DLL、msiexec、GPO)。
- **RMM/监控/备份**以服务身份派生子进程;**开发/CI**(node/python/msbuild 派生 shell)。

## 判定逻辑
- **true_positive**:异常父进程派生 shell/LOLBin **或**(解码后)命令行含远程下载执行/隐藏执行 **且**(以服务/低权账户运行 **或**有后续 SPAWNED→外连/LSASS/持久化);且**未**命中良性噪声。
- **false_positive**:命中 Ansible/执行策略自检噪声 / 交互式管理员会话 / 合法安装器 / 解码后是良性运维脚本。
- **suspicious**:命令行可疑但无解码内容、无父链、无后续行为 → 证据不足,写 missing_evidence 并升级。

## ⚠️只依据证据,禁止臆造
**只能引用 recipe 实际取回的实体/字段**。证据里没有父进程就别写父进程名(别再幻觉出 `cmd.exe`/`CompatTelRunner.exe`),没有子进程就别编。字段缺失 → 写进 missing_evidence,不要脑补。

## 图盲区(取不到就写 missing_evidence)
进程 EXE 签名/是否 LOLBin 原版、完整性级别/Token 提权、注入子行为细节。(`-EncodedCommand` 解码后内容 recipe 现已提供,不再是盲区。)
