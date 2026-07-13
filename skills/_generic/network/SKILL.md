---
name: generic_network
layer: network
technique_ids: []
description: 网络层通用研判兜底(没有更专门 skill 匹配该网络/外连告警类型时用)。
---
# 网络层通用研判(兜底)

没有更专门的 skill 覆盖这条网络告警,按通用方法论研判。基础证据已由通用取证收齐。

## 五步判序(通用,必守)
1. **先证伪**:最可能的良性解释?(正常轮询/更新/CDN/心跳/内部管理流量)。
2. **看基线/周期性**:count 高 + 时间跨度长 + 间隔规整?
3. **看目标可疑度**:reputation 差/新域/DGA(⚠️ reputation 常空)。
4. **看发起进程**:非浏览器/非更新程序、可疑父链、无签名。
5. **看数据量/方向**(host-only 下多为图盲区)。

## 网络层要点(host-only 现实)
只有主机侧 Sysmon 的网络维度(EID3 外连/EID22 DNS),无包级/流级。**信标判定靠聚合边 count/first/last + 事件按 time 算节律**;三者叠加(周期性 + 目标可疑 + 发起进程异常)才 TP,单项高误报。**"存在与嫌疑"能报,"内容与确证"需 NDR/Zeek 探针。**

## 判定
证据充分给明确 verdict;**证据不足(reputation 空、无节律数据、需探针)→ verdict=suspicious + missing_evidence + escalate,别硬判**。
