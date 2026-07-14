# 攻击需求 · 横向移动 / PtH / PtT(T1550 · T1021)

> **用途**:给公司专职网安/红队的检测验证需求。描述真实恶意技战术 + 预期告警 + SOC 应判成什么。**本文只描述技战术与预期,不含可执行 exploit。** SOC/agent 侧不执行任何攻击。

## 对应
- **SOC skill**:`skills/identity/lateral_movement`
- **检测规则**:GOAD `local_rules.xml` 100805 —— 4624 登录型 3(网络)/10(RDP)由真实用户发起(排机器账号/匿名/系统)→ T1021.001
- **良性验证(已做)**:`deploy/ansible/benign-lateral-movement.yml` 从成员机只读访问 DC 的 SYSVOL(良性远程登录)→ 验 recipe 取证

## 技战术(真实恶意,红队照做)
攻击者拿到一个立足点后在域内横向,常见:
1. **Pass-the-Hash(T1550.002)**:用窃取的 NTLM 哈希对远程主机做网络登录(mimikatz `sekurlsa::pth` / impacket `psexec.py -hashes`)→ 目标产 4624 **登录型 3**、AuthPackage=NTLM。
2. **Pass-the-Ticket(T1550.003)**:注入 TGT/TGS 后访问服务(mimikatz `kerberos::ptt` / Rubeus)→ 4624 型 3、AuthPackage=Kerberos。
3. **远程执行/RDP(T1021.001/002/006)**:psexec / wmiexec / evil-winrm / `mstsc` RDP → 4624 型 3 或 **型 10(RDP)**;WinRM=型 3。
4. 常配合:被窃账号短时**登录多台主机**(扇出)、**首次登录**从没登过的高价值主机(DC/CA)、**非工作时段**、源主机异常。

标准工具:impacket(psexec/wmiexec/smbexec)、crackmapexec、evil-winrm、mimikatz、Rubeus。

## 预期告警与 SOC 判定(TP 判据)
真实恶意产同样的 100805(T1021.001)告警,SOC 的 lateral_movement recipe 应据此判 **true_positive**:
- **首次登录高价值主机**:该账号↔该主机基线为空(recipe「该账号↔该主机基线」)且目标是 `domain_controller`/`certificate_authority`(补图 role,critical/high)。
- **账号扇出**:该账号短时登录多台不同主机(recipe「账号扇出」显著 > 基线)。
- **PtH/PtT 签名**(★图盲区):AuthPackage=NTLM + KeyLength=0 + 冒充级别(PtH 首要签名)/ 票据异常(PtT)—— 4624 未带全,recipe 已标 missing_evidence,红队报告附上 AuthPackage/ImpersonationLevel。
- **源主机异常**:src_ip 是非常规跳板 / 与该账号日常不符。

## 图盲区(recipe 已标,需 EDR 补)
认证包(NTLM/Kerberos)+ KeyLength + 冒充级别(PtH 首要签名)、票据生命周期(金/银票)、成员机票据↔DC 硬关联。红队报告附上这些字段便于人工核对。

## 验收
红队从一台机对 DC/高价值主机做 PtH/PtT/远程执行 → 图里出 T1021.001 告警 → SOC 研判应为 **true_positive**(首登高价值主机 + 扇出 + 非常规源)+ 处置(如禁账号/隔离源主机/吊销会话);**良性 SYSVOL 访问仍判 FP/低优**(不误伤)。
