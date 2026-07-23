# 待办:缺遥测的告警类型(遥测就绪后再做)

> 对 `research/alert-triage-methodology.md` 四层告警清单做覆盖梳理时发现:有几类告警**不是不想做,是靶场当前没有对应遥测进图** —— 建了 skill 也没告警可路由(死代码)。**先存档,等相应遥测接入后再做。**

## 清单

### 网络层
1. **IDS/NDR 签名 + 信誉直判**(方法学 F1 path B:比对已知恶意 DNS/C2 域名·IP 情报信誉)
   - 缺:Suricata/Zeek 探针出的告警进图。当前两个网络 skill(`c2_beacon` / `suspicious_outbound`)其实都是**主机侧 Sysmon EID3/EID22 冒充网络层**,不是真 IDS/NDR。
   - 解锁需:soc-graph-ingest 接 Suricata/Zeek → `:Alert{source:suricata}` + 签名/matched-content/JA3/SNI 等字段进图。

2. **网络流量向横向移动**(SMB/东西向 NetFlow;区别于身份层认证向的 `lateral_movement`)
   - 缺:NetFlow / Zeek conn.log 进图。

### 富化 / 情报(横切)
3. **外部 IP/域信誉喂数**
   - 图模型已留 `:IPAddress.reputation` / `:Domain.reputation` 槽,但**无喂数**(read 返 null)。
   - 解锁需:soc-graph-ingest 接威胁情报源(VT / AbuseIPDB / OTX / Shodan…)富化这两个槽。

### 四层之外(方法学 F7 提到的取证源,靶场无)
4. **邮件**(头部 / 附件哈希 / SPF / DKIM / DMARC)—— 靶场 GOAD 无邮件遥测。
5. **云**(CloudTrail / Azure / GCP IAM)—— 靶场无云遥测。

## 关联
- 这些是覆盖梳理里被判为**缺遥测**而暂缓的部分;**能做的"payload/签名直判"优先项**(应用层认证绕过/广义 OWASP、身份层 AS-REP 等)另行推进。
- 其中 **1、3 一旦遥测就绪,属"payload/签名直判(方法 B)"家族**,可直接复用那套经验库检索能力(实体台账召回 + 指纹召回),不用重造。

## 状态
- 记录时间:2026-07-22
- 触发条件:对应遥测(Suricata/Zeek/NetFlow/情报源/邮件/云)接入 soc-graph-ingest 并有告警进图后,再回来建 skill。
