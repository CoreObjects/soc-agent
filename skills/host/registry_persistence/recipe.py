"""注册表自启持久化(T1547.001 / T1112)确定性取证 —— 结构化 finding 版。

从触发事件(EID13 SET)取被写的键/值名/value_data(启动命令)+ 写入进程/父链/账号,
抽出规范化 findings + 实体 bindings。被持久化文件的哈希/写入进程签名是图盲区。

finding 词典(方法论):autostart_write(触发,键类由 key_path 归类)/ nonstandard_target(红,
value_data 指向 Temp/AppData/Public/ProgramData 等非标准落地)/ installer_writer(白,写入进程是
安装器 msiexec/setup/TiWorker 等)/ suspicious_writer(红,写入进程是 cmd/powershell/rundll32/reg/
wscript 等 LOLBin)/ privileged_account(特权账号写入)。
红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类经验(qwen 学)。
★可移植承重 key = writer_image 原始值(结论学出来,非硬编码良性/恶意名单),守 [[soc-signature-portability-redline]]。
"""
import re

from soc_agent.forensics import Finding, Forensics

# key_path → 自启键类(先判 RunOnce,免被 Run 抢;归类而非把整条 key_path 裸值当 attr)
_KEY_TYPE_RULES = [
    ("runonce", re.compile(r"RunOnce", re.I)),
    ("run", re.compile(r"\\Run(?:\\|$)|CurrentVersion\\Run", re.I)),
    ("winlogon", re.compile(r"Winlogon", re.I)),
    ("services", re.compile(r"\\Services(?:\\|$)", re.I)),
]

# value_data 指向的非标准落地路径(用户可写/临时目录)—— 载荷藏这里 = 高危信号
_NONSTANDARD_TARGET = re.compile(
    r"\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Public\\|\\ProgramData\\|"
    r"%TEMP%|%APPDATA%|%PUBLIC%|%PROGRAMDATA%", re.I)

# 安装器/更新器(通用 Windows 安装机制,非厂商名单)—— 写自启多为正常安装/更新
_INSTALLER_WRITER = re.compile(
    r"\bmsiexec(?:\.exe)?\b|\bsetup(?:\.exe)?\b|\bTiWorker(?:\.exe)?\b|"
    r"\bTrustedInstaller(?:\.exe)?\b|\bwusa(?:\.exe)?\b", re.I)

# LOLBin/脚本宿主(通用 Windows 二进制)—— 写自启常见于恶意持久化
_SUSPICIOUS_WRITER = re.compile(
    r"\bcmd(?:\.exe)?\b|powershell|\bpwsh(?:\.exe)?\b|rundll32|\breg(?:\.exe)?\b|"
    r"wscript|cscript|mshta|regsvr32", re.I)


def classify_key_type(key_path) -> str:
    """把 key_path 归类成 run/runonce/winlogon/services/other(取不到 → unknown)。"""
    p = str(key_path or "")
    if not p:
        return "unknown"
    for name, rx in _KEY_TYPE_RULES:
        if rx.search(p):
            return name
    return "other"


def is_nonstandard_target(value_data) -> bool:
    return bool(value_data and _NONSTANDARD_TARGET.search(str(value_data)))


def is_installer_writer(image) -> bool:
    return bool(image and _INSTALLER_WRITER.search(str(image)))


def is_suspicious_writer(image) -> bool:
    return bool(image and _SUSPICIOUS_WRITER.search(str(image)))


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 1. 被写的键/值 + value_data(启动命令)+ 写入进程/父链  (★cypher 不动)
    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:SET]->(rv:RegistryValue) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
        "RETURN rv.hive AS hive, rv.key_path AS key_path, rv.value_name AS value_name, "
        "e.value_data AS value_data, p.process_guid AS proc_guid, p.image AS writer_image, "
        "p.command_line AS writer_cmdline, parent.image AS parent, "
        "h.hostname AS host",
        aid=aid)
    b = base[0] if base else {}
    ctx["键与写入值+写入进程"] = b
    pg = b.get("proc_guid")
    writer_image, host, value_data = b.get("writer_image"), b.get("host"), b.get("value_data")

    if writer_image:
        bindings["process"] = writer_image        # 进程/镜像 → 保留原值(可移植承重 key)
    if host:
        bindings["host"] = host

    # 触发本身:一次自启键写入(键类归类进 attrs,供指纹按"写哪种自启键"泛化;整条 key_path 只留 ctx)
    if b:
        findings.append(Finding(
            "regpersist.autostart_write",
            {"hive": b.get("hive"), "key_type": classify_key_type(b.get("key_path"))},
            evidence_ref=aid, polarity="neutral"))

    # value_data 指向非标准落地路径(Temp/AppData/Public/ProgramData)= 可疑目标(presence;裸值留 ctx)
    if is_nonstandard_target(value_data):
        ctx["非标准落地路径(value_data)"] = value_data
        findings.append(Finding("regpersist.nonstandard_target", {}, polarity="red"))

    # 写入进程画像:安装器(白)vs LOLBin/脚本宿主(红)—— writer_image 原值进 attrs,承重 key
    if is_installer_writer(writer_image):
        findings.append(Finding("regpersist.installer_writer", {"writer_image": writer_image}, polarity="white"))
    if is_suspicious_writer(writer_image):
        findings.append(Finding("regpersist.suspicious_writer", {"writer_image": writer_image}, polarity="red"))

    # 2. 写入账号 + 权限  (★cypher 不动)
    if pg:
        rows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=pg)
        ctx["写入账号"] = rows
        acc = rows[0] if rows else {}
        sam, domain = acc.get("sam"), acc.get("domain")
        if sam:
            bindings["account"] = sam
            if domain:
                bindings["account_domain"] = domain
        if acc.get("privileged"):
            findings.append(Finding("regpersist.privileged_account", {"sam": sam}, polarity="neutral"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="被持久化文件的哈希/签名、写入进程 EXE 签名、注册表前值/是否覆盖(篡改 vs 新建)、"
                                 "Winlogon/IFEO/COM 劫持等键是否纳入监控 —— 未建模")
