---
name: generic_application
layer: application
technique_ids: []
description: 应用层通用研判兜底(没有更专门 skill 匹配该 Web/应用告警类型时用)。
---
# 应用层通用研判(兜底)

没有更专门的 skill 覆盖这条应用/Web 告警,按通用方法论研判。基础证据已由通用取证收齐。

## 五步判序(通用,必守)
1. **先证伪**:最可能的良性解释?(正常业务撞签名、扫描器噪声、CRS 高误报)。
2. **看基线**:单发还是一片扫描?
3. **看资产价值**:打的哪个站点/主机?
4. **看时序与扇出**:源 IP 近期打击画像。
5. **看落地**:是否得手。

## 应用层要点(两条现实主义原则)
1. **签名命中 = 有人试了**,≠ 攻击成功、≠ 恶意 → **FP 优先假设**。
2. **判"是否得手"必须跨层看主机落地**(被打 Web 主机上 Web 进程派生 shell / 写脚本 / 外连)。证据只停在 WAF 请求侧的一律标"证据不足"而非 TP。可用 run_cypher pivot 到 web_host 的主机侧事件(如有 auto 模式)。

## 判定
证据充分给明确 verdict;**证据不足(无跨层落地、HTTP 响应码/payload 取不到)→ verdict=suspicious + missing_evidence + escalate,别硬判**。
