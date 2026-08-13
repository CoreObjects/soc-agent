---
name: registry_persistence
layer: host
technique_ids: [T1547.001, T1112]
description: 研判注册表自启持久化告警。当告警涉及"写 Run/RunOnce/Winlogon/Services 等自启键""注册表被改以开机/登录自动执行""注册表持久化"时选它。关键词 registry persistence/注册表持久化/Run key/RunOnce/Winlogon/自启/autorun/T1547/reg add。
needs: [registry_set_telemetry, process_spawn_telemetry]
---
# 注册表自启持久化研判(T1547.001 / T1112)

**攻击本质**:写 `Run`/`RunOnce`/`Winlogon`/`Services` 等自启键,让载荷在开机/登录时自动执行,获得重启存活的持久化。

**触发**:注册表设值(Sysmon EID13)命中受监控自启键。图内落为 `(:Event)-[:BY]->Process`、`-[:SET]->RegistryValue(hive/key_path/value_name)`,标量 `value_data` = **被写入的启动命令(研判最关键字段)**。

## 研判决策树
1. **写的是哪个键、值指向什么?**(recipe「键与写入值」:key_path/value_name/value_data)—— `value_data` 指向 `Temp/AppData/ProgramData/Public`、带编码 PowerShell/`rundll32`/`mshta`/无引号可疑路径 → 高危;指向 `Program Files\<厂商>\...exe` 且值名=已知软件 → 偏良性。
2. **是谁写的键 —— 安装器还是攻击工具?**(recipe「写入进程与父链」)—— `msiexec/setup/TiWorker/软件自身` = 正常安装/更新;`cmd/powershell/rundll32/reg.exe/wscript` 且父进程可疑 = 恶意持久化。
3. **写键账户与主机权限?**(recipe「写入账号」)—— 域控/高价值主机上非安装器写自启 = 高危。
4. **被持久化的载荷从哪来?** —— 若能溯到此前被下载/释放的文件(与 T1105 串链),TP 佐证(⚠️ 常需 File 哈希,图盲区)。

## 误报/良性场景(逐条)
- **安装器/更新器写自启**(杀软、驱动托盘、OneDrive、Teams、ctfmon、企业代理),由 msiexec/setup/TiWorker 或软件本体写 —— **最大宗 FP**。
- **GPO/登录脚本/企业管理**(SCCM/Intune、GPP 下发自启)。
- **管理员手动配置**(交互式会话 + 目标合法路径)。

## 判定逻辑
- **true_positive**:`value_data` 指向非标准路径(Temp/AppData/Public)或含编码/LOLBin **且**写入进程为 cmd/powershell/rundll32/reg/wscript **且**父链或写入账户可疑。
- **false_positive/benign**:安装器/更新器/GPO 写入,`value_data` 指向签名软件安装目录,值名匹配已知软件。
- **suspicious**:非常见但指向合法目录、写入进程可信度中等 → 挂起(⚠️ 载荷/写入进程签名是图盲区)。

## 图盲区(取不到就写 missing_evidence)
被持久化文件的哈希/签名(判 exe 是否恶意)、写入进程 EXE 签名、注册表前值/是否覆盖(难分篡改 vs 新建)、Winlogon/IFEO/COM 劫持等键是否纳入监控。
