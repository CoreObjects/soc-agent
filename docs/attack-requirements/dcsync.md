# 攻击需求 · DCSync 凭据窃取(T1003.006)

> **用途**:给公司专职网安/红队的检测验证需求。描述真实恶意技战术 + 预期告警 + SOC 应判成什么。**本文只描述技战术与预期,不含可执行 exploit。**

## 对应
- **SOC skill**:`skills/identity/dcsync`
- **检测规则**:GOAD `local_rules.xml` 100807 —— 4662 对象访问携【目录复制】扩展权 GUID(DS-Replication-Get-Changes `1131f6aa…` / -All `1131f6ad…` / -In-Filtered-Set `89e95b76…`)→ T1003.006
- **前置遥测(Phase A)**:DC 上开 "Directory Service Access" 审计子类 `{0CCE923B-…}`(`benign-dcsync-replication.yml` 已做)—— 否则 4662 根本不产
- **良性验证(已做)**:`benign-dcsync-replication.yml` 在 DC 上 `repadmin /syncall` 强制正常复制 → DC 机器账号行使复制权 → 良性 4662 → 验 recipe 取证(发起者/复制GUID/是否本域DC)

## ★核心判据:发起者是不是本域 DC 机器账号
4662+复制GUID 对**良性 DC 复制**和**恶意 DCSync** 是同一个告警,唯一区别在**发起者**:
- **发起者 = 本域 DC 机器账号**(如 `WINTERFELL$`,且该主机 is_dc)→ **正常复制,false_positive**。
- **发起者 = 普通用户/非DC账号/非本域机器账号** → **真 DCSync,true_positive**(攻击者拿到了复制权,正在导 krbtgt/全域哈希)。

## 技战术(真实恶意,红队照做)
1. **DCSync(T1003.006)**:攻击者用一个具备 **DS-Replication-Get-Changes(-All)** 权的账号(域管、或被 ACL 后门授权的普通账号),冒充 DC 向真 DC 发起复制请求,拉取任意账号的密码哈希(尤其 `krbtgt` → 打 Golden Ticket)。
   - 工具:`mimikatz "lsadump::dcsync /user:krbtgt"`、`impacket secretsdump.py -just-dc <domain>/<user>@<dc>`、`nxc smb <dc> --ntds`。
2. **前置常配(可选,加分观测)**:**T1484.001/ACL 后门** —— 先给一个普通账号授予复制权(修改域对象 ACL,产 **5136** 目录服务变更),再 DCSync。

## 预期告警与 SOC 判定(TP 判据)
真实 DCSync 产同样的 100807(T1003.006)告警,SOC recipe 应判 **true_positive**:
- **发起者非 DC 机器账号**(核心)——普通用户 `sam` 或非本域机器账号在行使复制权 = 几乎必然恶意。
- **发起者是域管/高价值账号但从异常主机**(非 DC 主机上发起复制)也高度可疑。
- 叠加:近期该账号被授予复制权(5136,若采集)、复制目标含 krbtgt。

## 图盲区(recipe 已标,需补采集/建模)
复制范围(是否含 krbtgt/全域,4662 不直接给被同步的目标账号)、授予复制权的前置 ACL 修改(5136 目录服务变更,当前未接)、DC/授权同步账号的权威白名单标记。

## 验收
红队用一个**非 DC 机器账号**(域管或被后门授权的普通用户)跑 DCSync 拉 krbtgt → 图里出 T1003.006 告警,发起者=该用户 → SOC 研判应为 **true_positive** + 处置(禁用账号/重置 krbtgt 两次/查 ACL 后门);**DC 机器账号正常复制的 4662 仍判 false_positive**。
