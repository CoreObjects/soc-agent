---
name: dcsync
layer: identity
technique_ids: [T1003.006]
description: 研判 DCSync(伪装域控拉取口令哈希)告警。当告警涉及"目录复制(GetNCChanges/DS-Replication-Get-Changes)""非域控账号发起复制""导出 krbtgt/域账号哈希"时选它。关键词 DCSync/replication/复制/GetNCChanges/DS-Replication/4662/mimikatz/secretsdump/krbtgt。
---
# DCSync 研判(T1003.006)

**攻击本质**:攻击者持有(或自授)目录复制权限,伪装成 DC 发起复制(GetNCChanges),把任意/全部账号口令哈希(尤其 `krbtgt`→金票)拉下来。

**触发**:目录访问 4662 且访问权限含 `DS-Replication-Get-Changes`(`1131f6aa`)/`-Get-Changes-All`(`1131f6ad`)。触发事件在 seed:`(:Event{event_code:'4662'})-[:BY]->actor Account`、`-[:ACCESSED]->DirectoryObject`,标量 `properties`(复制 GUID)。

## 研判决策树
1. **发起者是不是 DC 机器账号?(先证伪,决定性)**(recipe「发起者与对象」+「域DC」)—— DC 之间本就常年复制。actor 是**用户账号或非 DC 机器账号** → 告警成立;actor 就是本域 DC 机器账号($) → **benign(DC 正常复制)**。
2. **`properties` 是否真含复制 GUID(尤其 Get-Changes-**All**`1131f6ad`)?** —— All 才是拉哈希权限,存在则显著提权。
3. **发起者权限/组?**(recipe「发起者估值」:privileged/组)。
4. **该账号是否本就是复制伙伴?(基线)** —— 首见 = 强信号。⚠️ 复制范围(拉了 krbtgt 还是全部)是 4662 固有盲区。
5. **后续有无金票征兆/横移?**(同 actor 后续异常 Kerberos/横向告警)。

## 误报/良性场景(逐条证伪)
- **DC-to-DC 正常复制**:每台 DC 持续复制 → actor 是 DC 机器账号 → benign(**头号 FP**,靠「域DC」的 dc_host 对上 actor 排除)。
- **Entra Connect / Azure AD 同步账号**(`MSOL_*` 等)做密码哈希同步 → 真企业巨量 FP;GOAD 无。⚠️ 同步账号标记是图盲区,靠经验/名字。
- **备份/AD 审计/安全产品**(Quest/Netwrix/DSInternals)合法复制。

## 判定逻辑
- **true_positive**:actor 为**非 DC、非同步账号**(尤其普通用户),`properties` 含复制 GUID(尤其 -All),无复制伙伴基线;若 actor 近期被提权置信更高。
- **false_positive/benign**:actor 是本域 DC 机器账号(DC 正常复制)/ 已知受权同步/备份账号。
- **suspicious(升级)**:特权管理员账号(非 DC)交互式发起复制 —— 可能合法管理工具也可能窃取的 DA 凭据 → escalate 核实变更工单。

## 图盲区(取不到就写 missing_evidence)
复制范围(krbtgt/全部)、授予复制权的前置 ACL 修改(5136)、DC/同步账号的权威标记、actor 真实工作站(4662 记在 DC 上)。
