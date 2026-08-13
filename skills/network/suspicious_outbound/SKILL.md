---
name: suspicious_outbound
layer: network
technique_ids: [T1571, T1090, T1041, T1048]
description: 研判可疑外连 / 罕见进程 C2 通道 / 非标准端口 / 数据外带告警。当告警涉及"本不该联网的进程(rundll32/regsvr32/mshta)直接外连""非常用端口外连(4444/8080/1080/高位随机)""经代理跳板外连""疑似数据外带"时选它。关键词 suspicious outbound/非标准端口/non-standard port/proxy/C2 channel/rundll32 外连/data exfiltration/数据外带。
supported_pivots: [process, endpoint]
needs: [network_flow_telemetry, process_spawn_telemetry]
---
# 可疑外连 / 罕见进程 C2 通道研判(T1571 / T1090)

**攻击本质**:C2 走**非常用端口**(绕基于端口的策略)或经**代理/中继**跳板;或由**本不该联网的进程**(LOLBin:rundll32/regsvr32/mshta/powershell)直接对外发起连接。

## 研判决策树
1. **目标是外部还是内部?端口是不是非常用?**(recipe「进程与目标+父链」:dst_ip/dst_port/proto)—— ip.type/asn/geo/reputation 未建模=盲区。
2. **发起进程是不是"不该联网"的进程?父链可疑吗?**(同上:parent/account/image)—— `image` ∈ LOLBin/无签名;`winword→powershell→外连` 典型攻击链。
3. **命令行是编码启动吗?解开是什么?**(recipe「发起命令解码(逐层)」+「供给/自检噪声」)—— EncodedCommand 解开=看真身;命中 Ansible 供给/执行策略自检=强证伪。
4. **这个"进程→外部 IP"是一次性还是反复?**(recipe「外连聚合(反复性)」:count/first_seen/last_seen,数连接事件现算)—— 反复 = 通道而非误触。

## 误报/良性场景
- **PowerShell/脚本正当外连**(DevOps 调 REST API/拉包/包管理经代理)—— 目标=内部制品库/已知供应商、账号=CI/服务账号、命令行运维意图。
- **企业出网强制走代理**(所有外连 dest_port=代理端口 3128/8080 + 目标=内部代理 IP)—— 易被当"非标准端口 C2";区分:ip.type=内部、目标是已知代理。
- **非标准端口的正当业务**(DB/消息队列/被管设备 22/1433/3306/5672/8443、协作软件动态端口)。

## 判定逻辑
- **true_positive**:罕见进程 + 外部目标 + (非常用端口 或 目标信誉差/新域) + 反复性/可疑父链。LOLBin 外连外部 IP 即使单次也升为可疑待定 + 拉父链;叠加目标可疑即 TP。
- **false_positive**:目标是内部代理/已知供应商/内部服务;进程是对应客户端;命令行有明确运维语义。
- **suspicious**:仅"非标准端口"单条件(代理/业务端口一大把)→ 必须叠加发起进程异常或目标可疑才升级。

## 图盲区(取不到就写 missing_evidence)
代理之后的真实外部目标(T1090)、协议 vs 端口错配(无 DPI)、四元组字节量/时长(判扫描 vs 稳定通道)、reputation 多半空。**代理后落点、加密内容需探针。**
