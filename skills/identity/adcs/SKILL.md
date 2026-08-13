---
name: adcs
layer: identity
technique_ids: [T1649]
description: 研判 ADCS 证书滥用(ESC)告警。当告警涉及"证书申请/签发(CertRequest)""证书模板滥用""用他人身份取证书/自填 SAN 冒充""向 CA Web 端点 NTLM 中继(ESC8)"时选它。关键词 ADCS/certificate/证书/ESC1/ESC8/certipy/Certify/4886/4887/CA/enrollment。
needs: [cert_request_telemetry]
---
# ADCS 证书滥用研判(T1649)

**攻击本质**:滥用错配的证书模板或 Web 注册端点,拿一张能"以他人身份认证"的证书 = 长期域内持久化/提权。ESC1:模板开 `ENROLLEE_SUPPLIES_SUBJECT`+客户端认证 EKU → 请求时自填任意 SAN 冒充管理员。ESC8:向 CA Web 端点 NTLM 中继,替被中继账号(常是机器账号/DC)取证书。

**触发**:证书申请收到/证书签发(Windows 4886/4887)。触发事件在 seed:`(:Event)-[:BY]->请求者Account`、`-[:REQUESTED]->Service(certificate_authority)`。⚠️4886 携 `attributes`(含请求机器 cdc/rmd)+ `request_id`,**但不携带模板名/EKU/SAN**(那些是图盲区)。

## 研判决策树
1. **请求者是谁、对哪个 CA、从哪台机器?**(recipe「请求者与CA」:req.upn/domain/privileged、ca.service_id、attributes 里的 cdc/rmd 请求机器)—— 低权用户从异常主机请求 = 升权;`attributes` 显示请求机器 == CA/DC 自身则偏运维。
2. **证书主体是否 ≠ 请求者?(ESC1 冒充头号判据)** —— recipe「主体与请求者比对」已给 `subject_dn`/`subject_cn`/`subject_matches_requester`(4887 签发事件才带 subject_dn):
   - `subject_matches_requester=false`(主体≠请求者)→ **疑似冒充,强 TP 信号 / 至少 lean_malicious**;
   - `=true` → 无冒充、正常自签(⚠️SAN 仍是盲区,不能完全排除)→ 倾向良性;
   - `=null`(subject_dn 缺失,多为 4886 请求阶段)→ 仍盲区。
   ⚠️**SAN(subjectAltName)才是 ESC1 真正的冒充载体,与 subject_dn 不同、仍未建模** → 写进 missing_evidence。
3. **模板本身危险吗?**(EKU / ENROLLEE_SUPPLIES_SUBJECT / 是否需审批)—— ⚠️只有模板名,EKU/标志未建模 → 图盲区。
4. **低权用户在换取特权认证能力吗?**(recipe「请求者估值」:privileged/组)。
5. **ESC8 角度**:经 Web 端点、"请求者"实为机器账号 + 时间邻近的入站 NTLM 中继 —— ⚠️中继链未建模,只能时序旁证。
6. **证书随后被用来认证了吗?**(被冒充主体随后 PKINIT/4768)—— 落地佐证。

## 误报/良性场景(逐条证伪)
- **正常证书注册/自动注册**(用户认证、机器认证、EFS、802.1x、代码签名)—— 量极大,requester==subject 即非冒充。
- **自动注册续期**(`request_type=renewal`,机器账号为自己续)→ FP。
- **合法 Web 注册**(少数组织正常用)。

## 判定逻辑
- **true_positive**:`subject_matches_requester=false`(主体≠请求者=冒充)且主体特权/请求者低权;或随后出现被冒充主体的 PKINIT;ESC8 机器账号证书经 Web 端点 + 邻近入站 NTLM 中继。
- **false_positive**:requester==subject 的正常自动注册/续期/已知安全模板。
- **suspicious + lean(SAN/模板是图盲区、无法完全确证时按 subject 比对分诊)**:
  - `subject≠请求者` → **suspicious / lean=malicious**(疑似 ESC1,优先核 CA 日志);
  - `subject==请求者` → **suspicious / lean=benign**(大概率正常自签,SAN 仍盲、低优先);
  - `subject_dn 缺失` → **suspicious / lean=unknown**。
  处置用 escalate/monitor,missing_evidence 写清"需 CA 日志核对 SAN 与模板 EKU"。

## 图盲区(取不到就写 missing_evidence)
证书 SAN 及请求者↔主体 mismatch(最关键)、模板 EKU/ENROLLEE_SUPPLIES_SUBJECT/是否需审批、ESC8 中继/强制认证链、CA 审计是否开启。
