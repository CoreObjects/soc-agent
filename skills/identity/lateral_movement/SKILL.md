---
name: lateral_movement
layer: identity
technique_ids: [T1550.002, T1550.003, T1021.001, T1021.002, T1021.006]
description: 研判横向移动/凭据复用(PtH/PtT/异常远程登录)告警。当告警涉及"网络登录(logon type 3/9/10)""NTLM/Kerberos 凭据复用""SMB/RDP/WinRM 远程登录""金票/银票""异常账号登上罕见主机"时选它。关键词 lateral movement/横向/pass-the-hash/pass-the-ticket/PtH/PtT/4624/4768/4776/RDP/WinRM/PsExec/golden ticket。
---
# 横向移动 / PtH / PtT / 异常登录研判(T1550/T1021)

**攻击本质**:复用窃取的认证材料横向移动而无需明文——PtH(网络登录 type3/9 + NTLM)、PtT(伪造/窃取票据,金票 T1558.001/银票 T1558.002)、异常远程登录(type10 RDP)。

**触发**:4624(type3/9/10 远程)/4768(TGT)/4776(NTLM)异常登录。触发事件在 seed:`(:Event)-[:BY]->Account`、`-[:AUTHENTICATED_TO]->Host`、`-[:FROM]->IP`,标量 `logon_type/result`。

## 研判决策树
1. **谁、什么登录类型、登到哪台、从哪来?**(recipe「登录事件」:account/logon_type/目标主机/源IP)。
2. **该账号↔该主机是否正常?(基线)**(recipe「该账号↔该主机基线」:agg 边 count/first_seen)—— **窗口内首见 + 特权账号 + 高价值主机 = 强信号**。
3. **扇出?**(recipe「账号扇出」:登过几台)—— 短时多台 = 横向扩散。
4. **PtH 特征?** type3/9 + NTLM 且无前置交互登录 —— ⚠️ 认证包/KeyLength 未建模,只能靠 logon_type + 4776 存在旁证。
5. **PtT/银票特征?** 成员机 Kerberos 登录但 DC 无对应 4768/4769;金票=超长票据生命周期 —— ⚠️ 生命周期未建模(图盲区)。
6. **来源可疑?**(源 IP 信誉/是否该账号从未关联过的 IP)。

## 误报/良性场景(逐条证伪)
- **正常远程运维**:IT/助台用 RDP(type10)+ 管理共享(type3)横跨多机 → 像横向。区分:来源是已知管理跳板、账号是管理账号、目标集合稳定。
- **服务账号广泛认证**(SCCM/补丁/备份)type3 遍布 → 基线广泛(agg count 高)。
- **NTLM 合法使用**(按 IP 访问、老应用)→ type3 NTLM ≠ PtH。
- **域信任跨域 NTLM 4776** → 多域林里跨信任 4776 良性遍布(可结合信任拓扑判;如本靶场多域)。

**★资产价值(补图第二弹)**:recipe「登录事件」现带 `target_role`/`target_criticality`。登录目标是 `domain_controller`/`certificate_authority`(criticality=critical/high)→ 异常登录显著升权。

## 判定逻辑
- **true_positive**:账号↔主机**首见**(无基线)+ 特权账号 + PtH/PtT 特征,尤其伴随扇出多台 + 落地远程执行/LSASS 访问,来源 IP 新/差信誉。银票(成员机 Kerberos 登录 DC 无对应票)= 高置信。
- **false_positive**:来源已知管理跳板/扫描器;基线广泛的服务账号;到已知老应用的 NTLM;匹配信任拓扑的跨域 4776。
- **suspicious(升级)**:特权账号登罕见主机但单跳无后续 / 因认证包/票据生命周期是图盲区无法完全验证 → escalate。

## 图盲区(取不到就写 missing_evidence)
认证包(NTLM/Kerberos)+KeyLength+冒充级别(PtH 首要签名)、票据生命周期/renew-till(金票)、成员机票据↔DC 硬关联(银票)、来源工作站名解析。
