---
name: c2_beacon
layer: network
technique_ids: [T1071, T1071.001, T1071.004, T1568, T1568.002]
description: 研判 C2 信标 / DNS beacon / 周期性外连告警。当告警涉及"进程周期性回连某 IP/域(信标节律)""DNS 隧道/DGA 域名""可疑/低信誉/新注册域外连""HTTP(S) 心跳式外连"时选它。关键词 C2/beacon/信标/DNS tunneling/DGA/callback/periodic connection/命令控制/心跳。
supported_pivots: [process, endpoint]
---
# C2 信标 / DNS beacon 研判(T1071 / T1568)

**攻击本质**:植入体按固定节律(可带 jitter)周期性回连 C2 取指令/回传。载体 = HTTP(S) 外连(Sysmon EID3)或 DNS 查询(EID22 把域名当信道),常配可疑/低信誉/DGA/动态解析域名。

**现实约束**:host-only + Sysmon,无包级/流级数据。信标靠**数连接/查询事件 count + first_seen/last_seen 定粗信号(聚合边不存 count,现算)+ 事件按 time 算节律**;`reputation`/解析扇出未建模(依赖它的判据要能降级)。

## 研判决策树(先证伪"是不是正常轮询",再逐层坐实)
1. **哪个"进程→目标"对?粗信号?**(recipe「外连聚合(周期性)」/「DNS查询聚合(周期性)」:count 高 + first↔last 跨度长 = 强嫌疑)。
2. **节律真规整吗?**(相邻事件间隔的中位数/变异系数)—— 低方差=机器节律。⚠️ 精确 jitter/主频需事件序列图外算(图盲区)。
3. **命令行编码启动?解开是什么?目标域新不新?**(recipe「发起命令解码(逐层)」+「供给/自检噪声」+「目标域新鲜度」:d.first_seen)—— 解码见真身、命中良性供给=证伪、新域=升权。⚠️ reputation/DGA 情报/解析扇出未建模=盲区。
4. **发起进程正常吗?**(recipe「发起进程」:parent/account/image)—— `chrome/edge` 良性;`rundll32/powershell/regsvr32/无名进程`直接外连 = 高危;Office→powershell→外连 = 攻击链。

## 误报/良性场景(先逐条排除)
- **软件更新/补丁轮询**(Windows Update、Chrome/Edge updater、winget、厂商 agent)—— 极规整;进程已知 + 目标厂商域/CDN。
- **EDR/监控/管理 agent 心跳**(Wazuh/Defender 云/SCCM)—— 本就是"信标";进程=已知 agent、目标=内部。
- **CDN/反代/DNS 负载均衡**(一域多 IP 易被当 fast-flux)—— 知名 CDN(Akamai/Cloudflare)、ASN 属 CDN。
- **NTP/内部 DNS 递归**、遥测/许可 ping、云 API 轮询。
> 共同特征:**进程已知 + 目标域信誉好/非新 + 目标是供应商/CDN/内部** → 先假定 FP。

## 判定逻辑(三者叠加才 TP,单项高误报)
- **true_positive**:① 周期性(count 高 + 跨度长 + 间隔低方差)**且** ② 目标可疑(reputation 差/新域/DGA/扇出异常)**且** ③ 发起进程异常(非浏览器/可疑父链/无签名)。
- **false_positive**:仅① + 进程是已知更新/agent + 目标信誉好(正常轮询/心跳)。
- **suspicious**:①+③ 但②缺(reputation 空且域名不新)→ 升级情报查询/沙箱,别直接封。**周期性单独出现绝不 TP。**

## 图盲区(取不到就写 missing_evidence)
精确信标周期/jitter 显著性、包级 inter-arrival/字节量/时长、DNS 深度特征(记录类型/子域熵/NXDOMAIN/TTL)、TLS/JA3/SNI、reputation 是否有真情报值。**这些要 NDR/Zeek 探针才有,host-only 的原理性天花板。**
