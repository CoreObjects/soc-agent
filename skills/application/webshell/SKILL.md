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
1. **WAF 侧:上传类请求打了什么、被拦否?**(recipe「告警(WAF上传请求)」:`payload`/`target_uri`/`http_status`/`outcome`/命中 CRS 规则)—— `outcome=blocked` = 上传被拦,基本止于尝试。
2. **★后端 Web 进程有没有写出脚本 + 随后派生/外连?(核心,判是否落地)**(recipe「跨层-后端落地(落盘+利用)」)—— w3wp/php-cgi `WROTE` 脚本到 wwwroot/inetpub/htdocs(脚本扩展名)+ 随后 `SPAWNED` cmd/powershell 或 `CONNECTED_TO` 外连 = 三件套铁证。**后端为被监控主机时才有;容器化后端(本靶场 DVWA)= 盲区**。
3. **能对上这条 WAF 上传请求吗?** —— 同 Host + 时间窗(⚠️ 请求↔落盘无因果强键,是"同 Host + 近邻"弱关联)。
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
**已入图可用**:WAF 侧 `payload`/`http_status`/`outcome`(被拦否)/命中 CRS 规则/打击端点。
**仍盲**:后端 Web 主机主机侧遥测(容器化=无 `WROTE`/`SPAWNED`→跨层三件套空)、上传 multipart 内容/落盘路径、请求↔落盘的因果强键(现靠同 Host+时间窗)、落盘文件哈希、站点物理路径映射(判 URL 可达/可执行)。
