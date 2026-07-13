---
name: adcs
layer: identity
technique_ids: [T1649]
description: 研判 ADCS 证书滥用(ESC)告警。当告警涉及"证书申请/签发(CertRequest)""证书模板滥用""用他人身份取证书/自填 SAN 冒充""向 CA Web 端点 NTLM 中继(ESC8)"时选它。关键词 ADCS/certificate/证书/ESC1/ESC8/certipy/Certify/4886/4887/CA/enrollment。
---
# ADCS 证书滥用研判(T1649)

**攻击本质**:滥用错配的证书模板或 Web 注册端点,拿一张能"以他人身份认证"的证书 = 长期域内持久化/提权。ESC1:模板开 `ENROLLEE_SUPPLIES_SUBJECT`+客户端认证 EKU → 请求时自填任意 SAN 冒充管理员。ESC8:向 CA Web 端点 NTLM 中继,替被中继账号(常是机器账号/DC)取证书。

**触发**:证书申请收到/证书签发(Windows 4886/4887)。触发事件在 seed:`(:Event)-[:BY]->请求者Account`、`-[:REQUESTED]->Service(certificate_authority)`,标量 `template/request_type`。

## 研判决策树
1. **请求者是谁、对哪个 CA/模板?**(recipe「请求者与CA/模板」)—— 低权用户 + 危险模板 = 升权。
2. **证书主体/SAN 是否 ≠ 请求者?(ESC1/ESC6 头号判据)** —— ⚠️**SAN 未建模(图盲区)**,图内无法直接判 mismatch → 写进 missing_evidence。
3. **模板本身危险吗?**(EKU / ENROLLEE_SUPPLIES_SUBJECT / 是否需审批)—— ⚠️只有模板名,EKU/标志未建模 → 图盲区。
4. **低权用户在换取特权认证能力吗?**(recipe「请求者估值」:privileged/组)。
5. **ESC8 角度**:经 Web 端点、"请求者"实为机器账号 + 时间邻近的入站 NTLM 中继 —— ⚠️中继链未建模,只能时序旁证。
6. **证书随后被用来认证了吗?**(被冒充主体随后 PKINIT/4768)—— 落地佐证。

## 误报/良性场景(逐条证伪)
- **正常证书注册/自动注册**(用户认证、机器认证、EFS、802.1x、代码签名)—— 量极大,requester==subject 即非冒充。
- **自动注册续期**(`request_type=renewal`,机器账号为自己续)→ FP。
- **合法 Web 注册**(少数组织正常用)。

## 判定逻辑
- **true_positive**:SAN/主体 ≠ 请求者 且该主体特权(或请求者低权)+ 已知脆弱模板,尤其随后出现被冒充主体的 PKINIT;ESC8:机器账号证书经 Web 端点签发 + 邻近入站 NTLM 中继。
- **false_positive**:requester==subject / 续期 / 身份一致的已知自动注册模板。
- **suspicious(升级)**:**因 SAN/模板 EKU 是图盲区无法判定** → 别硬判,verdict=suspicious + missing_evidence 写清"需 CA 日志核对 SAN 与模板 EKU",处置 escalate。

## 图盲区(取不到就写 missing_evidence)
证书 SAN 及请求者↔主体 mismatch(最关键)、模板 EKU/ENROLLEE_SUPPLIES_SUBJECT/是否需审批、ESC8 中继/强制认证链、CA 审计是否开启。
