# 攻击需求 · 注册表自启持久化(T1547.001)

> **用途**:给公司专职网安/红队的**检测验证需求**。描述真实恶意技战术 + 预期告警 + SOC 应判成什么,便于红队照做验证 TP 通路。**本文只描述技战术与预期,不含可执行 exploit。** SOC/agent 侧不执行任何攻击。

## 对应
- **SOC skill**:`skills/host/registry_persistence`
- **检测规则**:GOAD `local_rules.xml` 100804 —— Sysmon EID13 SetValue 到自启位(Run/RunOnce/Winlogon/服务 ImagePath)→ T1547.001
- **良性验证(已做)**:`deploy/ansible/benign-registry-persistence.yml` 良性写 Run 键 → 验 recipe 取证 + FP 通路

## 技战术(真实恶意,红队照做)
攻击者在已控主机上建立开机自启,常见几种:
1. **Run/RunOnce 键**:把 Run 值指向落在 `Temp/AppData/ProgramData/Public` 的可执行/脚本(payload),写入进程是 shell/脚本(cmd/powershell/wscript/mshta)而非安装器。
2. **Winlogon Shell/Userinit 劫持**:改 `Winlogon\Shell`/`Userinit` 追加恶意程序。
3. **服务 ImagePath**:新建/改服务的 ImagePath 指向恶意二进制。
4. 常配合:payload 落盘(EID11)、随后被执行(EID1)、外连 C2(EID3)。

标准工具:`reg add` / PowerShell `New-ItemProperty` / C2 框架的 persistence 模块(如 Metasploit `persistence`、Sliver/Havoc 的 registry persistence)。

## 预期告警与 SOC 判定(TP 判据)
真实恶意会产同一条 100804(T1547.001)告警,但特征不同 —— SOC 的 registry_persistence recipe 应据此判 **true_positive**:
- **写入进程异常**:cmd/powershell/wscript/mshta/rundll32 等写自启(而非 msiexec/安装器/可信更新器);父链可疑(w3wp/服务派生 shell)。
- **值指向可疑路径**:`\Temp\`、`\AppData\`、`\ProgramData\`、`\Public\`、`\Users\...\` 下的 exe/脚本,或带 `-enc`/下载执行的命令行。
- **落地+执行闭环**:同窗口有该 payload 的 EID11 落盘 + EID1 执行 + EID3 外连。
- **账号**:低权/服务账号写自启(而非管理员在装软件)。

## 图盲区(recipe 已标,需 CA/EDR 补)
被持久化文件的哈希/签名、写入进程 EXE 签名、注册表前值(篡改 vs 新建)。红队报告里附上 payload 路径/哈希便于人工核对。

## 验收
红队按上述打一次真实持久化 → 图里出 T1547.001 告警 → SOC 研判应为 **true_positive** + 处置(如 escalate/隔离主机/删除自启项),且**良性写入仍判 FP**(不误伤)。
