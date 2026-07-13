---
name: generic_host
layer: host
technique_ids: []
description: 主机/端点层通用研判兜底(没有更专门 skill 匹配该主机/进程/文件/注册表告警类型时用,如解码/混淆/计划任务等)。
---
# 主机/端点层通用研判(兜底)

没有更专门的 skill 覆盖这条主机告警,按通用方法论研判。基础证据已由通用取证收齐(触发事件 + 主语进程 + 宾语 + 主机)。

## 五步判序(通用,必守)
1. **先证伪**:最可能的良性解释?(AV/EDR、系统进程、运维、合法安装器/更新器)一眼能排掉吗?
2. **看基线新颖度**:这个进程/父子链/文件是头一回还是常态?
3. **看权限/资产价值**:运行账号是否特权?主机是否高价值?
4. **看时序与扇出**。
5. **看横向落地**:之后有无外连 C2 / 读 LSASS / 写自启 / 派生 shell。

## 主机层要点(端点主判法)
**父子进程链还原 + 命令行 + 源进程 + 落地文件 + 后续行为**。异常父进程(w3wp/services/spoolsv/wmiprvse/sqlservr)派生 shell/LOLBin、编码命令(-enc)、可疑父链 = 强信号。可用 run_cypher 顺 process_guid 沿 SPAWNED 回溯父链、看 CONNECTED_TO/WROTE/ACCESSED(如有 auto 模式)。

## 判定
证据充分给明确 verdict;**证据不足(无专门 skill、进程签名/解码命令等取不到)→ verdict=suspicious + missing_evidence + 处置 escalate,别硬判**。
