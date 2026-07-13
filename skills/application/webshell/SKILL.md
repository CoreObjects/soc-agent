---
name: webshell
layer: application
technique_ids: [T1505.003]
description: 研判 Webshell 上传/落地/利用告警。当告警涉及"上传可执行脚本到 Web 目录(.aspx/.php/.jsp)""Web 进程(w3wp/php-cgi)写脚本文件到站点根""webshell 被回连执行(Web 进程派生 cmd/powershell)"时选它。关键词 webshell/web shell/aspx/php/jsp/china chopper/behinder/冰蝎/inetpub/wwwroot/w3wp。
---
# Webshell 上传与落地研判(T1505.003)

**攻击本质**:把可执行脚本(.aspx/.ashx/.php/.jsp)写进 Web 可访问目录,获得持久化远程命令通道。**这是应用层证据最薄、最必须靠跨层坐实的旗舰案例**:WAF 只看到"一个上传请求",是否真落盘成 webshell、能否回连执行,全在主机侧。

**触发**:WAF 侧信号弱且不稳(很多 webshell 上传对 CRS 是"干净"的 multipart)。**真正高保真信号在主机侧**:Web 工作进程(w3wp/php-cgi)在 wwwroot/inetpub 下写出脚本扩展名文件(Sysmon EID11 WROTE)。

## 研判决策树
1. **Web 主机上,Web 进程有没有写出脚本文件到 web 目录?(核心问句,主机侧起手)**(recipe「主机侧-落盘脚本」)—— w3wp WROTE 脚本到 wwwroot/inetpub + 脚本扩展名 = 强信号。
2. **这个 webshell 有没有被执行(回连/命令)?**(recipe「主机侧-执行/回连」)—— w3wp 随后 SPAWNED cmd/powershell(铁证)或外连 C2。
3. **能对上一条 Web 上传告警/请求吗?** —— 同 Host + 时间窗(⚠️ 请求↔落盘无因果强键,是"同 Host + 近邻"弱关联)。
4. **文件是不是已知恶意?**(File.sha256 对经验/黑名单;⚠️ 哈希常空)。

## 误报/良性场景
- **合法部署/发布**:CI/CD、部署账号写 .aspx/.php 到站点目录 —— 区分靠**谁写的**:正常发布是部署进程/msdeploy,**不是 w3wp 应用池身份**(w3wp 自己写脚本文件本就极罕见)。
- **应用自身生成脚本/缓存**(部分 CMS 编译缓存),路径是已知缓存目录、随后被 include 且无外连。
- **临时上传目录**(图片/附件区,非可执行、非脚本扩展名)。

## 判定逻辑(跨层三件套齐 = 确定级)
- **false_positive**:脚本由部署/管理账号或部署进程写入、落已知缓存目录、无 w3wp 派生 shell、无外连。
- **confirmed TP(落地 webshell)**:w3wp WROTE 脚本到 web 根 + 能对上上传请求(时间窗)。
- **confirmed TP + 活跃利用(最高危)**:上 + w3wp 随后 SPAWNED cmd/powershell 或外连 C2 → 立即处置(隔离主机、封源 IP、删文件、取证)。
- **判定核心**:`WROTE`(落盘)+`SPAWNED`(执行)+`CONNECTED_TO`(回连)三段齐 → 确定级,无需依赖薄弱的 WAF 请求侧。

## 图盲区(取不到就写 missing_evidence)
上传请求的文件名/multipart 内容/落盘路径(WAF 侧给不出)、请求↔落盘的因果强键(现靠同 Host+时间窗)、HTTP 响应码、落盘文件哈希、站点物理路径映射(判 URL 可达/可执行)。
