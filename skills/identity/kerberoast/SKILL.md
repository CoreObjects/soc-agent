---
name: kerberoast
layer: identity
technique_ids: [T1558.003]
description: 研判 Kerberoasting(服务票据离线爆破)告警。当告警涉及"请求 Kerberos 服务票据/TGS""RC4/0x17 弱加密票据请求""带 SPN 的服务账号被大量取票""疑似离线爆破服务账号口令"时选它。关键词 Kerberoast/TGS/service ticket/SPN/RC4/0x17/4769/GetUserSPNs/Rubeus。
---
# Kerberoasting 研判(T1558.003)

**攻击本质**:任意域用户向 DC 请求某带 SPN 账号的服务票据(TGS),票据用该服务账号的 NTLM 哈希加密;攻击者离线爆破还原其明文口令。RC4(etype `0x17`)是爆破工具(Rubeus/GetUserSPNs)刻意索取的可离线破解格式——现代域几乎不该出现用户 SPN 的 RC4 票据,视为异常直到被证伪。

**触发**:Security **4769**(TGS-REQ)且 `enc_type=0x17`(RC4)且服务名非机器账号($结尾)。触发事件已在 seed 里,`(:Event{event_code:'4769'})-[:BY]->请求者Account`、`-[:REQUESTED]->服务Account/Service`、`-[:FROM]->IP`、`-[:ON_HOST]->DC`。

## 研判决策树(逐步用 run_cypher 取证)

1. **请求者是普通用户,还是服务/机器账号?(先证伪)**
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account)
   RETURN req.sam, req.domain, req.type, req.privileged, e.enc_type, e.ticket_options
   ```
   服务账号常年取票、机器账号规则已排除;普通用户请 RC4 才可疑。

2. **目标 SPN 账号价值几何?**
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:REQUESTED]->(tgt)
   OPTIONAL MATCH (tgt)-[:MEMBER_OF]->(g:Group)
   RETURN tgt.sam, tgt.privileged, collect(g.name) AS groups
   ```
   特权服务账号(域管组等)= 高价值目标,升权。

3. **RC4 对该请求者是否历史异常?(看基线)**
   ```cypher
   MATCH (req:Account {sam:$req_sam})<-[:BY]-(ev:Event {event_code:'4769'})
   RETURN ev.enc_type AS enc, count(*) AS n ORDER BY n DESC
   ```
   该请求者一贯用 AES、突然 RC4 → 异常;一贯 RC4(老应用)→ 基线,降权。也看聚合边 `(req)-[r:REQUESTED]->(tgt) RETURN r.first_seen, r.count`(首次接触该服务?)。

4. **单票还是 SPN 扫描(扇出)?——强 TP 信号**
   ```cypher
   MATCH (req:Account {sam:$req_sam})<-[:BY]-(ev:Event {event_code:'4769'})-[:REQUESTED]->(tgt)
   WHERE ev.event_time > $t0 - 600
   RETURN count(DISTINCT tgt) AS distinct_spns
   ```
   短时(<10min)去重 SPN ≥5 = GetUserSPNs 式扫描。

5. **来源主机/会话符合该用户日常吗?**
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:FROM]->(ip:IPAddress)
   OPTIONAL MATCH (h:Host)-[:HAS_IP]->(ip)
   RETURN ip.ip, h.hostname, h.role
   ```

5.5. **★跨域信任检查(证伪跨域 RC4 误报 —— 多域林头号 FP,必查)**
   请求者域与目标服务所属域之间**若有信任**,跨域用 RC4 请票就是**正常**的(不是攻击)。
   ```cypher
   MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account)
   MATCH (e)-[:REQUESTED]->(tgt)
   OPTIONAL MATCH (dreq:Domain {netbios: req.domain})-[:TRUSTS]-(dtgt:Domain)
   RETURN req.domain AS req_domain, tgt.sam AS target,
          collect(DISTINCT dtgt.fqdn) AS req_domain_trusts
   ```
   若目标(或其所属域)落在 `req_domain_trusts` 里 → **跨域信任的正常 RC4 → false_positive**。
   (请求者是机器账号/域控[$ 结尾]时,跨域引荐票更是常态,基本可定 FP。)

6. **爆破是否已成功?(看横向落地)**
   ```cypher
   MATCH (tgt:Account {sam:$tgt_sam})<-[:BY]-(ev2:Event {event_code:'4624'})-[:AUTHENTICATED_TO]->(h:Host)
   WHERE ev2.event_time > $roast_time
   RETURN h.hostname, ev2.logon_type
   ```
   被 roast 的服务账号在告警后从**新主机**登录 = 爆破成功已用凭据,铁证。

## 误报/良性场景(逐条证伪)
- **跨林/跨域信任默认 RC4**(除非启用 AES)→ 跨域 4769 携 RC4。**多域林带信任时这是头号 FP**(如本靶场):请求者域 TRUSTS 目标域(**用第 5.5 步查实**)→ 判 FP。别只凭"域不同"猜,要查到 TRUSTS 边才定 FP。
- **只支持 RC4 的老应用/服务账号**(老 MSSQL/Java 等)→ 一贯 RC4 基线(第 3 步 count 高、first_seen 久)→ FP。
- **漏扫/AD 评估工具**(PingCastle/BloodHound/Nessus 凭据扫描)批量取票 → 像扫描;来源为已知扫描器主机/账号 → FP。
- **服务账号正常取票 / 用户映射网络驱动器触发单张 4769** → FP。

## 判定逻辑
- **true_positive**:普通用户 → 对从未接触过的服务 SPN 请 RC4,且短时扇出 ≥5 去重 SPN、来源非扫描器;或被 roast 账号随后从新主机登录。
- **false_positive**:**请求者域与目标域之间有 TRUSTS 边**(跨域信任的正常 RC4,第 5.5 步查实,多域林头号 FP)/ 一贯 RC4 的老应用单票 / 已知扫描器来源。
- **suspicious(升级)**:对高价值 SPN 的 RC4、但低量无扇出、请求者无基线——证据不足,写 missing_evidence(如"无法判定 SPN 是否 high-value/是否蜜罐/是否已授权扫描器")并升级,别硬判。

## 图盲区(取不到就在 missing_evidence 里说明)
SPN 服务类别与是否 high-value(仅 privileged 布尔)、蜜罐/decoy 标记、已授权扫描器标记、离线爆破本身(只能由后续登录反推)。
