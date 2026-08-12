"""WP7:读侧 pivot 多态 + 覆盖度感知。

要证的四件事(前两件是"网是真的",后两件才是能力):
  1. **拿不到主语时不再静默返回空** —— 产出 `_coverage.absent`;
  2. **部分失明要按轴说清楚** —— 有流、没进程时,周期性照常出,进程画像那一轴单独报缺;
  3. ★**零 Windows 事件也能出结论** —— c2_beacon / suspicious_outbound 在纯端点(Zeek/NetFlow 形状)
     数据上产出非空 findings 且 `pivot.kind=='endpoint'`(WP7 的业务验收标准);
  4. **元 finding 不进指纹** —— 否则"瞎了→判 FP"会被蒸馏成经验,以后一瞎就自动放过。

★为什么这套测试值得存在:这三个 recipe 的失败模式是**静默**的 —— 锚点查询零行 → findings 空 →
落深度 LLM → 给出一个自信的空结论,全程不报错。"没崩"在这里什么都不证明,只有
"该出 finding 时真出了、该喊瞎时真喊了"才算数。
"""
from pathlib import Path

import pytest

from soc_agent.forensics import Finding
from soc_agent.graph.pivot import Pivot, resolve_pivot
from soc_agent.models import Alert
from soc_agent.recipe_lib import coverage_absent, probe
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"
_PIVOT_Q = "labels(subj) AS subj_labels"


class RecordingGraph:
    """按 Cypher 子串返回预置行,并记下每条实际执行的查询(用来断言"真的换了主语")。"""

    def __init__(self, table):
        self.table = table
        self.queries = []

    def run_cypher(self, query, **params):
        self.queries.append((query, params))
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []

    def q(self, substr):
        return [qq for qq, _ in self.queries if substr in qq]


def _recipe(name):
    return SkillRegistry(_SKILLS).by_name(name).recipe


def _pivot_row(labels, node, hostname=None, src_labels=None, src=None):
    return (_PIVOT_Q, [{"subj_labels": labels, "subj": node,
                        "src_labels": src_labels, "src": src, "hostname": hostname}])


def _absent(fo):
    return [f for f in fo.findings if f.finding_id == "_coverage.absent"]


# ---------------------------------------------------------------- resolve_pivot

@pytest.mark.parametrize("labels,node,kind,label,key", [
    (["Process"], {"process_guid": "g-1"}, "process", "Process", "process_guid"),
    (["IPAddress"], {"ip": "10.1.1.5"}, "endpoint", "IPAddress", "ip"),
    (["Account"], {"sam": "jon.snow"}, "principal", "Account", "sam"),
    (["Host"], {"hostname": "srv02"}, "host", "Host", "hostname"),
])
def test_resolve_pivot_reads_subject_label(labels, node, kind, label, key):
    g = RecordingGraph([_pivot_row(labels, node)])
    p = resolve_pivot(g, "a1")
    assert (p.kind, p.label, p.key_prop, p.via) == (kind, label, key, "BY")
    assert p.key_value == node[key]


def test_resolve_pivot_falls_back_to_from_then_on_host():
    """主语缺失时退 FROM(外部请求没有本地主体),再退 ON_HOST;★`via` 必须跟着变。"""
    g = RecordingGraph([_pivot_row(None, None, src_labels=["IPAddress"], src={"ip": "203.0.113.9"})])
    p = resolve_pivot(g, "a1")
    assert (p.kind, p.via, p.key_value) == ("endpoint", "FROM", "203.0.113.9")
    assert ":IPAddress {ip:$pk}" in p.match() and "-[:FROM]->" in p.match()

    g2 = RecordingGraph([_pivot_row(None, None, hostname="srv02")])
    p2 = resolve_pivot(g2, "a1")
    assert (p2.kind, p2.via, p2.key_value) == ("host", "ON_HOST", "srv02")


def test_resolve_pivot_returns_none_when_nothing_resolvable():
    assert resolve_pivot(RecordingGraph([]), "a1") is None
    assert resolve_pivot(RecordingGraph([_pivot_row(None, None)]), "a1") is None
    # 标签认得、但强键为空 → 不能当主语用(拿它去 MATCH 会恒零行)
    assert resolve_pivot(RecordingGraph([_pivot_row(["Process"], {"process_guid": None})]), "a1") is None


def test_pivot_match_renders_label_key_and_edge():
    p = Pivot("process", "Process", "process_guid", "g-1")
    assert p.match() == "(e:Event)-[:BY]->(x:Process {process_guid:$pk})"


# ---------------------------------------------------------------- 覆盖度感知

@pytest.mark.parametrize("name,tech", [("c2_beacon", "T1071.001"),
                                       ("suspicious_outbound", "T1571"),
                                       ("webshell", "T1505.003")])
def test_unresolvable_pivot_emits_coverage_absent_not_silent_empty(name, tech):
    """★没有主语时**必须说自己瞎了**。这是本包的核心:空 findings 与"确实没发现异常"
    在下游无法区分,而后者会让 LLM 自信地给出空结论。"""
    g = RecordingGraph([])                       # 连触发事件都查不到
    fo = _recipe(name)(g, Alert.from_node({"alert_uid": "x", "technique_ids": [tech]}), {})
    assert fo.finding_ids() == {"_coverage.absent"}
    assert _absent(fo)[0].attrs["skill"] == name
    assert fo.blind_spots, "必须给一句人读的「看不到什么」"


def test_probe_records_absence_when_expected_rows_missing():
    findings = []
    rows = probe(RecordingGraph([]), "MATCH (n) RETURN n", skill="s", need="dns_telemetry",
                 findings=findings)
    assert rows == [] and findings[0].finding_id == "_coverage.absent"
    assert findings[0].attrs["need"] == "dns_telemetry"

    findings2 = []
    rows2 = probe(RecordingGraph([("RETURN n", [{"n": 1}])]), "MATCH (n) RETURN n",
                  skill="s", need="dns_telemetry", findings=findings2)
    assert rows2 and findings2 == []


def test_meta_findings_never_enter_a_fingerprint():
    """★`_` 前缀的元 finding 不得被蒸馏进指纹 —— 否则"缺遥测→没发现→FP"会变成免责条款。"""
    from soc_agent.experience.distill import distill

    class _Verdict:
        verdict, rationale, verdict_id = "false_positive", "无异常", "v1"

    class _LLM:
        def chat(self, msgs, tools=None, tool_choice=None):
            raise AssertionError("只有元 finding 时不该还去问模型")

    assert distill(_LLM(), None, [coverage_absent("webshell", need="process_telemetry")],
                   {}, _Verdict()) is None

    seen = {}

    class _LLM2:
        def chat(self, msgs, tools=None, tool_choice=None):
            seen["enum"] = tools[0]["function"]["parameters"]["properties"][
                "decisive_finding_ids"]["items"]["enum"]
            return type("R", (), {"tool_calls": []})()

    distill(_LLM2(), None,
            [coverage_absent("webshell", need="process_telemetry"),
             Finding("webshell.in_webroot", {})], {}, _Verdict())
    assert seen["enum"] == ["webshell.in_webroot"], "元 finding 混进了可蒸馏集合"


# ------------------------------------------- ★业务验收:零 Windows 事件也要出结论

def test_c2_beacon_on_endpoint_pivot_yields_findings_without_any_process():
    """★WP7 业务验收(单测形态):一条**只有源 IP** 的流记录(Zeek/NetFlow 形状),
    c2_beacon 必须仍然产出非空 findings、周期性判据照常成立、且**明说进程那一轴瞎了**。
    迁移前这里是 `base==[]` → findings 空 → 静默。"""
    g = RecordingGraph([
        _pivot_row(["IPAddress"], {"ip": "10.1.1.5"}, hostname="zeek-sensor"),
        ("src.ip AS src_ip", [{"proc_guid": None, "image": None, "command_line": None,
                               "src_ip": "10.1.1.5", "dst_port": 8443,
                               "dst_ip": "45.77.10.10", "dst_domain": None, "host": None}]),
        ("sum(coalesce(e.count,1)) AS count",
         [{"count": 180, "first_seen": "2026-07-15T00:00:00", "last_seen": "2026-07-15T06:00:00"}]),
    ])
    fo = _recipe("c2_beacon")(g, Alert.from_node(
        {"alert_uid": "z1", "technique_ids": ["T1071.001"], "time": "2026-07-15"}), {})

    assert fo.findings, "零进程数据上仍必须有 findings(这正是迁移前失败的地方)"
    assert fo.context["主语(pivot)"]["kind"] == "endpoint"
    pb = next(f for f in fo.findings if f.finding_id == "c2.periodic_beacon")
    assert pb.polarity == "red" and pb.attrs["count_bucket"] == "massive"
    # 进程那一轴按轴报缺,而不是整条 recipe 弃疗
    assert [f.attrs["need"] for f in _absent(fo)] == ["process_telemetry"]
    assert "c2.suspicious_process" not in fo.finding_ids()
    assert fo.bindings["src_ip"] == "10.1.1.5"
    # ★真的换了主语:聚合查询必须 pivot 在 IPAddress 上,不是残留的 Process
    agg = g.q("sum(coalesce(e.count,1))")[0]
    assert "(x:IPAddress {ip:$pk})" in agg and ":Process" not in agg


def test_suspicious_outbound_on_endpoint_pivot_yields_findings_without_any_process():
    g = RecordingGraph([
        _pivot_row(["IPAddress"], {"ip": "10.1.1.5"}),
        ("src.ip AS src_ip", [{"proc_guid": None, "image": None, "command_line": None,
                               "parent": None, "account": None, "src_ip": "10.1.1.5",
                               "dst_ip": "203.0.113.5", "dst_port": 4444, "proto": "tcp",
                               "host": None}]),
        ("sum(coalesce(e.count,1)) AS count",
         [{"count": 30, "first_seen": "2026-07-20T01:00:00", "last_seen": "2026-07-20T03:00:00"}]),
    ])
    fo = _recipe("suspicious_outbound")(g, Alert.from_node(
        {"alert_uid": "z2", "technique_ids": ["T1571"]}), {})

    ids = fo.finding_ids()
    assert {"outbound.connection", "outbound.nonstandard_port", "outbound.repetitive"} <= ids
    assert next(f for f in fo.findings if f.finding_id == "outbound.repetitive").polarity == "red"
    assert [f.attrs["need"] for f in _absent(fo)] == ["process_telemetry"]
    assert "outbound.lolbin" not in ids, "没有 image 时不得凭空判 LOLBin"
    agg = g.q("sum(coalesce(e.count,1))")[0]
    assert "(x:IPAddress {ip:$pk})" in agg and ":Process" not in agg


def test_webshell_on_host_pivot_keeps_path_axis_and_declares_writer_blindness():
    """纯 FIM 源(无写入进程归因):落盘路径这一轴仍然有效,
    但核心判别①(写入者是不是 web 进程)结构上不成立 → 必须显式报缺。
    ★不硬凑:writer_is_webproc=False 读起来像"查过了不是",事实是"不知道谁写的"。"""
    g = RecordingGraph([
        _pivot_row(["Host"], {"hostname": "castelblack"}),
        ("collect(DISTINCT f.path) AS dropped_paths",
         [{"writer_guid": None, "writer_image": None, "writer_cmd": None,
           "dropped_paths": [r"C:\inetpub\wwwroot\uploads\shell.aspx"],
           "host": "castelblack", "host_role": "member_server", "host_criticality": "medium"}]),
    ])
    fo = _recipe("webshell")(g, Alert.from_node(
        {"alert_uid": "z3", "technique_ids": ["T1505.003"]}), {})

    ids = fo.finding_ids()
    assert {"webshell.file_drop", "webshell.in_webroot"} <= ids       # 路径轴仍然成立
    assert "webshell.web_process_writer" not in ids                   # 不凭空断言写入者
    assert "webshell.security_agent_writer" not in ids                # 也不凭空证伪
    assert [f.attrs["need"] for f in _absent(fo)] == ["process_telemetry"]
    assert fo.context["主语(pivot)"]["kind"] == "host"


# ------------------------------------------------------- Windows 侧零回归的护栏

@pytest.mark.parametrize("name,const,expect_edge", [
    ("c2_beacon", "_BASE_PROCESS", "-[:BY]->(p:Process)"),
    ("suspicious_outbound", "_BASE_PROCESS", "-[:BY]->(p:Process)"),
    ("webshell", "_BASE_PROCESS", "-[:BY]->(w:Process)"),
])
def test_process_branch_query_is_untouched(name, const, expect_edge):
    """★process 分支的锚点查询必须**保持原样** —— Windows 侧零回归的依据就是"它没被动过"。
    真机行集 diff 在 ferry 脚本里跑;这里守的是"别哪天顺手改了还没人发现"。"""
    q = _recipe(name).__globals__[const]
    assert q.startswith("MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)")
    assert expect_edge in q


# ------------------------------------------- 闸门脚本自身的可信度(先证明网是真的)

def _parity():
    """把 scripts/pivot_parity.py 当模块加载(它不是包的一部分)。"""
    import importlib.util
    p = Path(__file__).resolve().parents[1] / "scripts" / "pivot_parity.py"
    spec = importlib.util.spec_from_file_location("pivot_parity", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _fo(findings=(), bindings=None, context=None, blind=""):
    from soc_agent.forensics import Forensics
    return Forensics(findings=list(findings), bindings=dict(bindings or {}),
                     context=dict(context or {}), blind_spots=blind)


def test_parity_diff_catches_real_regressions():
    """★闸门脚本的 `diff()` 必须在**有差异时会红**,否则真机跑出的"零差异"毫无意义。
    这里逐种弄坏一次,每种都必须被抓到;只有事先声明的三项新增才放行。"""
    d = _parity().diff
    base = _fo([Finding("c2.periodic_beacon", {"channel": "http", "count_bucket": "high"})],
               {"process": "rundll32.exe"}, {"进程与目标": {"dst_ip": "1.2.3.4"}}, "盲区一句话")

    assert d(base, base) == []                                        # 同一份产物必须零差异

    gone = _fo([], {"process": "rundll32.exe"}, {"进程与目标": {"dst_ip": "1.2.3.4"}}, "盲区一句话")
    assert any("findings 少了" in x for x in d(base, gone))            # 少 finding

    extra = _fo(list(base.findings) + [Finding("c2.new_domain", {})],
                base.bindings, base.context, base.blind_spots)
    assert any("未声明" in x for x in d(base, extra))                  # 多出未声明的 finding

    changed = _fo([Finding("c2.periodic_beacon", {"channel": "http", "count_bucket": "massive"})],
                  base.bindings, base.context, base.blind_spots)
    assert any("内容变了" in x for x in d(base, changed))               # attrs 悄悄变了

    rebound = _fo(base.findings, {"process": "powershell.exe"}, base.context, base.blind_spots)
    assert any("binding process 变了" in x for x in d(base, rebound))

    ctx_changed = _fo(base.findings, base.bindings, {"进程与目标": {"dst_ip": "9.9.9.9"}},
                      base.blind_spots)
    assert any("context[进程与目标] 变了" in x for x in d(base, ctx_changed))

    assert d(base, _fo(base.findings, base.bindings, base.context, "别的话")) != []   # 盲区措辞

    # ★而事先声明过的三项新增必须放行(否则闸门会对着正确的改动一直红)
    declared = _fo(list(base.findings) + [coverage_absent("c2_beacon", need="process_telemetry")],
                   dict(base.bindings, src_ip="10.1.1.5"),
                   dict(base.context, **{"主语(pivot)": {"kind": "endpoint"}}),
                   base.blind_spots)
    assert d(base, declared) == []


def test_parity_can_load_a_recipe_from_git():
    """`load_old` 真能从 git 取出历史版本并加载 —— 闸门的整个前提就是这一步。"""
    m = _parity().load_old("skills/network/c2_beacon/recipe.py", "HEAD")
    assert callable(getattr(m, "collect", None))


# ------------------------------------------- 声明与实现不许漂移 / 坏 recipe 不许静默

def test_skill_md_declares_the_same_pivots_the_recipe_implements():
    """SKILL.md 的 `supported_pivots` 与 recipe 的 `SUPPORTED_PIVOTS` 必须一致。

    ★两处都要有,是因为它们服务不同读者:SKILL.md 是给 LLM/人看的能力声明(路由与预期),
    recipe 常量是运行时真正的判据。两边一旦漂移,就会出现"声称能接 Zeek、实际报缺"或反过来,
    而这种不一致**不会让任何测试变红** —— 所以在这里钉死。
    """
    reg = SkillRegistry(_SKILLS)
    from soc_agent.skills_runtime import parse_frontmatter
    checked = 0
    for name in ("c2_beacon", "suspicious_outbound", "webshell"):
        s = reg.by_name(name)
        meta, _ = parse_frontmatter((s.path / "SKILL.md").read_text(encoding="utf-8"))
        declared = meta.get("supported_pivots")
        assert declared, f"{name}: SKILL.md 没声明 supported_pivots"
        assert list(declared) == list(s.recipe.__globals__["SUPPORTED_PIVOTS"]), \
            f"{name}: SKILL.md 声明 {declared} 与 recipe 实现不一致"
        checked += 1
    assert checked == 3


def test_broken_recipe_is_isolated_but_not_silent(tmp_path):
    """★坏掉的 recipe 只能降级**该 skill**,而且必须留下原因。

    以前 `_load_attr` 直接吞异常 → 语法错的 recipe 表现为"这个 skill 没有取证能力",
    系统照跑、从此永远走裸 LLM,没有任何信号。今天这个坑我自己踩了一次(中文引号被规范化成
    ASCII 引号 → SyntaxError → 现象只是 `'NoneType' object is not callable`)。
    """
    good = tmp_path / "good"
    good.mkdir()
    (good / "SKILL.md").write_text("---\nname: good\nlayer: network\n---\nbody", encoding="utf-8")
    (good / "recipe.py").write_text("def collect(graph, alert, seed=None):\n    return None\n",
                                    encoding="utf-8")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "SKILL.md").write_text("---\nname: bad\nlayer: network\n---\nbody", encoding="utf-8")
    (bad / "recipe.py").write_text("def collect(  # 故意写坏\n", encoding="utf-8")

    reg = SkillRegistry(tmp_path)
    assert callable(reg.by_name("good").recipe), "坏 skill 不能拖垮好 skill"
    assert reg.by_name("good").recipe_error is None
    assert reg.by_name("bad").recipe is None
    assert "SyntaxError" in (reg.by_name("bad").recipe_error or ""), "失败原因被吞了"
    assert [n for n, _ in reg.load_errors()] == ["bad"]
