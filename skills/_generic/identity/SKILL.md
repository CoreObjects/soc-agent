---
name: generic_identity
layer: identity
technique_ids: []
description: 身份层通用研判兜底(没有更专门 skill 匹配该身份/AD 告警类型时用)。
---
# 身份层通用研判(兜底)

没有更专门的 skill 覆盖这条身份/AD 告警,按通用方法论研判。基础证据已由通用取证收齐(触发事件 + 主语账号 + 宾语 + 主机)。

## 五步判序(通用,必守)
1. **先证伪**:这条最可能的良性解释是什么?(跨域信任/服务账号常态/已知扫描器/管理运维)能一眼排掉吗?
2. **看基线新颖度**:这个"账号×目标×行为"是头一回还是常态?
3. **看权限/资产价值**:账号是否特权(privileged/属特权组)?目标是否高价值/DC?
4. **看时序与扇出**:单发还是短时批量?
5. **看横向落地**:之后有无异常登录/凭据使用/提权?

## 身份层要点
认证/AD 类看:账号 `privileged`、`MEMBER_OF` 组、域间 `TRUSTS`(跨域认证常为正常)、logon_type、来源。可用 run_cypher 顺着主语账号补查这些(如有 auto 模式)。

## 判定
证据充分给明确 verdict;**证据不足(无专门 skill、关键判据取不到)→ verdict=suspicious + missing_evidence 写清缺什么 + 处置 escalate,别硬判 TP/FP**。
