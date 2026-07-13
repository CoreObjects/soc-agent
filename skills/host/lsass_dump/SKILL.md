---
name: lsass_dump
layer: host
technique_ids: [T1003.001]
description: 研判 LSASS 凭据转储告警。当告警涉及"进程访问/读取 lsass.exe 内存""OpenProcess 拿 lsass 句柄""转储 LSASS/导出 NTLM 哈希或票据""mimikatz/procdump/comsvcs 抓密码"时选它。关键词 LSASS/credential dump/凭据转储/mimikatz/procdump/comsvcs/sekurlsa/GrantedAccess/进程内存读取。
---
# LSASS 凭据转储研判(T1003.001)

**攻击本质**:用 OpenProcess 拿 lsass.exe 句柄读其内存,导出 NTLM 哈希/Kerberos 票据/(WDigest 开时)明文口令,用于 PtH、横向、提权。

**触发**:进程访问事件(Sysmon EID10)且目标 = lsass.exe。触发事件在 seed:`(:Event)-[:BY]->源Process`、`-[:ACCESSED]->Process(lsass)`,标量 `granted_access`(工具指纹)、`call_trace`。

**grantedAccess 掩码语义(先读懂)**:关键看**是否含 `0x10`(PROCESS_VM_READ)** = 有人在读 LSASS 内存,才与凭据窃取相关。`0x1010`=Mimikatz sekurlsa;`0x1410`=ProcDump/任务管理器转储;`0x1438/0x143a`=含写位(注入类)恶意度最高;`0x1fffff`=ProcDump 全权限;纯 `0x1000/0x1400`(仅查询、无 0x10)基本良性。

## 研判决策树
1. **源进程是谁?在白名单内吗?掩码含 0x10 吗?**(recipe「源进程与访问掩码」)—— `MsMpEng.exe`(Defender)、`csrss/wininit/lsm/wmiprvse/svchost` 等系统/AV = 强证伪;掩码无 0x10 = 降权。
2. **父子链正常吗?源进程从哪来?**(recipe「父进程链」)—— `services.exe→MsMpEng` 正常;`w3wp/powershell/cmd/rundll32→未知源` 恶意。
3. **调用栈可疑吗?**(`call_trace` 含 dbghelp/dbgcore/UNKNOWN = 强 TP)—— ⚠️ 是否已语义化未知,可能是原始串。
4. **运行身份/权限?**(recipe「运行账号」)—— IIS AppPool/低权身份读 LSASS = 几乎必恶意。
5. **读完干了什么?**(recipe「读后行为」:外连/派生/落地)—— 读后外连坏 IP/写 dump/派生 PsExec = 闭环 TP。

## 误报/良性场景(逐条证伪)
- **Defender/AV/EDR 自身**(MsMpEng 及各 EDR 传感器)—— 真企业头号 FP,按源进程 image + 掩码无 0x10 排除。
- **系统进程**(csrss/wininit/lsm/wmiprvse/svchost)常态查询 LSASS(多为无 0x10 的查询掩码)。
- **备份/凭据管理/APM**读进程内存;**管理员任务管理器/ProcDump 手动抓 dump**(0x1410/0x1fffff,父进程交互式)。

## 判定逻辑
- **true_positive**:`granted_access` 含 0x10(尤其 0x1438/0x143a/0x1fffff)**且**源进程非白名单(cmd/powershell/rundll32/temp 路径)**且**(父链可疑 **或** call_trace 含 dbghelp/UNKNOWN **或** 读后外连/横向)。
- **false_positive/benign**:源进程 ∈ {MsMpEng/系统进程/已报备备份AV} **且**掩码无 0x10。
- **suspicious**:掩码含 0x10 但源进程签名可信/无后续恶意行为 → 挂起(⚠️签名是图盲区,写 missing_evidence)。

## 图盲区(取不到就写 missing_evidence)
源进程 EXE 签名/发布者/哈希(白名单只能按 image 路径,易伪装)、call_trace 是否已语义化、是否真落地 dump 文件及其哈希。
