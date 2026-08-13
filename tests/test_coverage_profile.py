"""WP9 读侧:照测出来的覆盖度说话。

这些测试守的是几条"错了不会红、只会让结论悄悄变差"的性质:
  · **"不知道" ≠ "什么都缺"** —— 没测过时必须什么都不改变(否则全系统偏向"证据不足");
  · **needs 名必须解析得出来** —— 拼错的 need 永远匹配不上,于是永远不报盲区(静默失效);
  · **元 finding 不进指纹** —— 否则"瞎了 → 判 FP"会被学成经验,以后一瞎就自动放过;
  · **手写盲区不被覆盖** —— 那里面绝大部分是模型盲区,是方法论,不该被测量结果冲掉。
"""
import pathlib

from soc_agent.forensics import Finding, Forensics
from soc_agent.graph import coverage as C
from soc_agent.skills_runtime import SkillRegistry

_ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeGraph:
    def __init__(self, rows=(), boom=False):
        self.rows, self.boom, self.calls = list(rows), boom, 0

    def run_cypher(self, q, **kw):
        self.calls += 1
        if self.boom:
            raise RuntimeError("图挂了")
        return self.rows


class FakeSkill:
    def __init__(self, name, needs):
        self.name, self.needs = name, needs


def _fact(activity, status="present", subjects=()):
    return {"activity": activity, "status": status, "subjects": list(subjects),
            "family": "?", "events": 1, "sources": ["x"], "stale_days": 0,
            "arrival_on": "Event"}


# --------------------------------------------------------------------- 最要紧的一条

def test_unknown_coverage_changes_nothing():
    """★图里一条 :Coverage 都没有(还没测过)⇒ 什么都不报。

    反过来把"查不到"当成"全都缺",每条 recipe 都会喊自己瞎了,研判会**整体**偏向
    "证据不足" —— 而根因只是没人跑过测量。这类"缺省值把系统推向错误方向"的坑,
    比崩溃难查得多。
    """
    p = C.load(FakeGraph(rows=[]))
    assert p.known is False
    assert p.missing(["process_spawn_telemetry", "dns_query_telemetry"]) == []
    fo = Forensics(findings=[Finding("x.y")], blind_spots="原有的模型盲区")
    out = C.annotate(fo, FakeSkill("s", ["process_spawn_telemetry"]), p)
    assert [f.finding_id for f in out.findings] == ["x.y"]
    assert out.blind_spots == "原有的模型盲区"


def test_graph_failure_degrades_to_unknown_not_to_crash():
    p = C.load(FakeGraph(boom=True))
    assert p.known is False and p.missing(["process_spawn_telemetry"]) == []


# --------------------------------------------------------------------- 画像问询

def test_profile_answers_presence_subjects_and_pivot_kinds():
    p = C.load(FakeGraph(rows=[
        _fact("network.flow", subjects=["FROM:IPAddress", "ON_HOST:Host"]),
        _fact("process.spawn", subjects=["BY:Process", "ON_HOST:Host"]),
        _fact("module.load", status="absent"),
    ]))
    assert p.known and p.has("network.flow") and not p.has("module.load")
    assert p.subjects("network.flow") == {"FROM:IPAddress", "ON_HOST:Host"}
    # ★这是 WP7 与 WP9 的接缝:没有 BY:Process ⇒ process pivot 在这套部署上解不出来
    assert p.pivot_kinds("network.flow") == {"endpoint", "host"}
    assert p.pivot_kinds("process.spawn") == {"process", "host"}
    assert p.pivot_kinds("module.load") == set()


def test_grouped_need_is_satisfied_by_any_one_activity():
    """分组 need(如 process_telemetry)只要**任一**活动有数据就算有 ——
    残缺该由 recipe 按轴报(WP7 干的事),不在这一层一刀切。"""
    p = C.load(FakeGraph(rows=[_fact("process.spawn"), _fact("process.access", status="absent")]))
    assert p.missing(["process_telemetry"]) == []
    assert p.missing(["process_access_telemetry"]) == ["process_access_telemetry"]


# --------------------------------------------------------------------- annotate 行为

def test_deployment_gap_produces_a_meta_finding_and_appends_blind_spots():
    p = C.load(FakeGraph(rows=[_fact("auth.logon"), _fact("process.spawn", status="absent"),
                               _fact("process.access", status="absent")]))
    fo = Forensics(blind_spots="进程 EXE 签名/发布者 —— 图未建模")
    out = C.annotate(fo, FakeSkill("lsass_dump", ["process_spawn_telemetry"]), p)
    metas = [f for f in out.findings if f.finding_id == "_coverage.absent"]
    assert len(metas) == 1
    assert metas[0].attrs["scope"] == "deployment", "要能与 WP7 的 scope='alert' 分开"
    assert metas[0].attrs["need"] == "process_spawn_telemetry"
    # ★手写的模型盲区必须还在 —— 它是方法论,不该被测量结果冲掉
    assert out.blind_spots.startswith("进程 EXE 签名/发布者 —— 图未建模")
    assert "本环境缺这些遥测(实测,非推断)" in out.blind_spots
    assert "process.spawn" in out.blind_spots, "要说清缺的是哪一类活动,不能只给个抽象名"


def test_no_gap_means_no_noise():
    """★遥测齐全的环境不该冒出任何覆盖盲区 —— 这是误报侧的闸门。"""
    p = C.load(FakeGraph(rows=[_fact("process.spawn"), _fact("network.flow"), _fact("dns.query")]))
    fo = Forensics(blind_spots="原样")
    out = C.annotate(fo, FakeSkill("c2_beacon", ["network_flow_telemetry", "dns_query_telemetry",
                                                 "process_spawn_telemetry"]), p)
    assert not [f for f in out.findings if f.finding_id == "_coverage.absent"]
    assert out.blind_spots == "原样"


def test_blindness_alone_never_sediments_experience():
    """★"瞎了 → 判 FP" 一旦被蒸馏成经验,以后一瞎就自动放过 —— 最贵的一种污染。

    直接拿真的 `distill` 验:唯一的 finding 是"我看不到"时,**必须一条经验都不沉淀**。
    """
    from soc_agent.experience.distill import distill
    from soc_agent.models import Verdict

    class BoomLLM:                        # 走到 LLM 就说明前面的过滤没拦住
        def chat(self, *a, **kw):
            raise AssertionError("只有元 finding 时不该调用 LLM 去蒸馏经验")

    p = C.load(FakeGraph(rows=[_fact("process.spawn", status="absent")]))
    fo = C.annotate(Forensics(), FakeSkill("lsass_dump", ["process_spawn_telemetry"]), p)
    assert [f.finding_id for f in fo.findings] == ["_coverage.absent"]
    v = Verdict(verdict="false_positive", confidence=0.9, summary="s", rationale="r",
                agent="t")
    assert distill(BoomLLM(), "lsass_dump", fo.findings, {}, v) is None


# --------------------------------------------------------------------- 词表不许漂

def test_every_declared_need_resolves():
    """★拼错一个 need 名,它就永远匹配不上、于是永远不报盲区 —— 静默失效,必须卡死。"""
    reg = SkillRegistry(_ROOT / "skills")
    unknown = {}
    for s in reg.all():
        bad = [n for n in (s.needs or []) if n not in C.NEED_ACTIVITIES]
        if bad:
            unknown[s.name] = bad
    assert unknown == {}, f"SKILL.md 里有解析不了的 needs:{unknown}"


def test_specific_skills_declare_the_telemetry_their_queries_depend_on():
    """抽查几条:声明必须跟 recipe 实际查的谓语边对得上,不能凭印象写。"""
    reg = SkillRegistry(_ROOT / "skills")
    by = {s.name: set(s.needs or []) for s in reg.all()}
    assert "auth_ticket_request_telemetry" in by["kerberoast"]      # REQUESTED + 4769
    assert "directory_access_telemetry" in by["dcsync"]             # ACCESSED + 4662
    assert "auth_logon_telemetry" in by["lateral_movement"]         # AUTHENTICATED_TO + 4624
    assert "cert_request_telemetry" in by["adcs"]                   # REQUESTED(证书)
    assert "registry_set_telemetry" in by["registry_persistence"]   # SET
    assert {"network_flow_telemetry", "dns_query_telemetry"} <= by["c2_beacon"]


# --------------------------------------------------------------------- 验收标准

def test_auth_only_tenant_makes_host_layer_skills_say_they_are_blind():
    """★计划里的验收口径:只有认证+告警、无进程遥测的租户 ——
    主机层 skill 必须**明说看不到**,而不是交出一份空 findings 被读成"没发现异常"。"""
    p = C.load(FakeGraph(rows=[
        _fact("auth.logon", subjects=["BY:Account", "ON_HOST:Host"]),
        _fact("auth.ticket_request", subjects=["BY:Account"]),
        _fact("process.spawn", status="absent"), _fact("process.access", status="absent"),
        _fact("file.write", status="absent"), _fact("registry.set", status="absent"),
        _fact("network.flow", status="absent"), _fact("dns.query", status="absent"),
    ]))
    reg = SkillRegistry(_ROOT / "skills")
    blind, fine = [], []
    for s in reg.all():
        if not s.needs:
            continue
        out = C.annotate(Forensics(), s, p)
        (blind if any(f.finding_id == "_coverage.absent" for f in out.findings) else fine
         ).append(s.name)
    for name in ("lsass_dump", "registry_persistence", "suspicious_process",
                 "c2_beacon", "suspicious_outbound", "webshell"):
        assert name in blind, f"{name} 在无进程/网络遥测的租户上必须报覆盖盲区"
    # 反面:身份层靠认证遥测,这个租户有,不该报
    for name in ("kerberoast", "lateral_movement"):
        assert name in fine, f"{name} 只靠认证遥测,这个租户有,不该冒出盲区"


def test_cache_avoids_a_graph_query_per_alert():
    C.reset_cache()
    g = FakeGraph(rows=[_fact("auth.logon")])
    C.get(g)
    C.get(g)
    assert g.calls == 1, "覆盖度是慢变量,不该每条告警查一次图"
    C.reset_cache()


def test_fallback_activity_table_matches_the_authoritative_one():
    """★这里放了一份 ACTIVITIES 兜底表(soc-agent 独立部署时用不到 soc-graph-ingest)。

    两份逐字一致的表就是会漂,而漂了**不报错** —— 只会让某个 need 永远匹配不上、
    于是永远不报盲区。两个仓都在场时(开发机/CI)就把它卡死;
    只有一个仓时这条自动跳过,但那种环境本来也改不到入图侧的词表。
    """
    import importlib
    try:
        real = importlib.import_module("ingest.activity_map").ACTIVITIES
    except Exception:
        return                     # 只 clone 了 soc-agent:无从比对,也无从改坏
    assert set(C._ACTIVITIES) == set(real), (
        "soc_agent/graph/coverage.py 的兜底 ACTIVITIES 与 ingest/activity_map.py 漂了:"
        f"少={sorted(set(real) - set(C._ACTIVITIES))} 多={sorted(set(C._ACTIVITIES) - set(real))}")
