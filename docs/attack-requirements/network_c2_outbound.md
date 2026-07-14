# 攻击需求 · C2 信标 / 可疑外连(T1071 · T1571 · T1090 · T1568)

> **用途**:给公司专职网安/红队的检测验证需求。描述真实恶意技战术 + 预期告警 + SOC 应判成什么。**本文只描述技战术与预期,不含可执行 exploit。**

## 对应
- **SOC skill**:`skills/network/c2_beacon`、`skills/network/suspicious_outbound`
- **检测规则**:GOAD `local_rules.xml` 100806 —— Sysmon EID3 网络连接由脚本/LOLBin(powershell/cmd/cscript/mshta/rundll32/certutil/regsvr32)发起 → T1071.001
- **良性验证(已做)**:`benign-network-beacon.yml` powershell 对内网做几次周期 TCP 连接 → 验 recipe 取证(进程/目标/聚合边周期性)

## ★重要限制:host-only,信誉/内容是盲区
本环境只有主机侧 Sysmon 网络维度(EID3 外连 / EID22 DNS),**无 NDR/Zeek**。所以:
- **能判**:外连的存在性、发起进程、聚合边的周期性(count/first/last/间隔规整度)、目标是否新域(DNS)。
- **判不了(需 NDR + 威胁情报)**:IP/域信誉、JA3/TLS 指纹、字节量/时长、代理后的真实落点、包内容。recipe 已把信誉标为图盲区。

## 技战术(真实恶意,红队照做)
1. **C2 信标(T1071.001/.004)**:植入(Cobalt Strike/Sliver/Havoc/Metasploit)以固定周期 + jitter 回连 C2(HTTP/HTTPS/DNS)。
2. **非标准端口 C2(T1571)** / **代理隧道(T1090)** / **DNS 隧道(T1568.002)**。
3. 常配合:发起进程是脚本/LOLBin 或落在 `C:\Users`/`Temp` 的载荷、目标是新注册域/坏信誉 IP、规整的信标间隔。

标准工具:Cobalt Strike、Sliver、Havoc、Metasploit meterpreter、dnscat2、chisel。

## 预期告警与 SOC 判定(TP 判据)
真实 C2 产同样的 100806(T1071.001)告警,SOC recipe 应据此判 **true_positive**(在 host-only 天花板内):
- **周期性**:聚合边 count 高 + 时间跨度长 + 间隔规整(recipe「外连聚合(周期性)」)—— 真信标 vs 我们良性 6 连(burst)的区别在**长时间跨度 + 规整间隔**。
- **发起进程可疑**:非浏览器/非更新器的脚本/LOLBin、可疑父链、无签名。
- **目标可疑**:新域(DNS first_seen 近)/ DGA 样式 / 坏信誉(★信誉需情报源,盲区——红队报告附上 C2 域/IP 便于人工核对)。
- **三者叠加**才 TP;单项高误报。

## 图盲区(recipe 已标,需 NDR/情报补)
IP/域信誉、精确信标周期/jitter 显著性、字节量/时长、DNS 深度特征(记录类型/子域熵/NXDOMAIN)、TLS/JA3、代理后真实落点。

## 验收
红队起一个真 C2 信标(长周期回连) → 图里出 T1071.001 告警 → SOC 研判应为 **true_positive**(周期性 + 可疑进程 + [人工/情报核实]坏目标)+ 处置(如封 IP/隔离主机);**良性周期连接(浏览器更新等)仍判 FP/suspicious**。
