"""演示脚本的守护:它包住的那些流水线函数必须真实存在。

★为什么值得一条常驻测试:演示脚本靠**按名字替换**真实函数来插日志。
  哪天有人重命名了流水线里的某一步,替换就会**静默不生效** ——
  脚本照跑、输出照样完整好看,只是**少了那一步**,而看的人(领导)根本不可能发现。
  这是「不报错、只变差」那一类失败里最难堪的一种:它发生在给人看的场合。

  所以这里钉死两件事:①每个挂载点都存在;②挂载点清单与脚本里实际包的一致
  (否则清单自己会过期,就又变成一个假绿灯)。
"""
import ast
import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "demo_pipeline.py"

# 演示脚本要包住的流水线步骤(模块 cli 上的名字)
CLI_TAPS = ["collect_forensics", "consult", "_reuse_tp", "_reuse_fp", "_recall_hit_ledgers",
            "choose_investigator", "_compose_dispositions", "snapshot_case", "sediment"]
CLI_ENTRIES = ["build_pipeline", "run_investigation"]
GRAPH_TAPS = ["seed", "get_alert", "write_result", "run_cypher"]


@pytest.mark.parametrize("name", CLI_TAPS + CLI_ENTRIES)
def test_cli_tap_targets_exist(name):
    from soc_agent import cli
    assert hasattr(cli, name), f"演示脚本要包 cli.{name},但它不存在(改过名?)"


@pytest.mark.parametrize("name", GRAPH_TAPS)
def test_graph_tap_targets_exist(name):
    from soc_agent.graph.client import Neo4jGraph
    assert hasattr(Neo4jGraph, name), f"演示脚本要包 graph.{name},但它不存在(改过名?)"


def test_router_has_route():
    from soc_agent.orchestrator import SkillRouter
    assert hasattr(SkillRouter, "route")


def test_the_tap_list_matches_what_the_script_actually_wraps():
    """★清单不能自己过期:脚本里实际出现的 `C.<name>` 赋值,必须与上面的清单一致。

    只检查「清单里的都存在」是不够的 —— 那样脚本里少包一步、或多包了一个没列进清单的,
    这条测试都发现不了,清单就成了摆设。
    """
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    assigned = set()
    for node in ast.walk(tree):
        # 形如 C.consult = tap(...)
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "C":
                    assigned.add(t.attr)
        # 形如 setattr(C, nm, ...) —— 循环里批量包的那两个,名字在同一文件的字面量里
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "setattr":
            src = ast.unparse(node)
            for n in ("_reuse_tp", "_reuse_fp"):
                if n in _SCRIPT.read_text(encoding="utf-8"):
                    assigned.add(n)
            assert "C" in src
    assert assigned == set(CLI_TAPS), (
        f"脚本实际包的与清单不一致:脚本={sorted(assigned)} 清单={sorted(CLI_TAPS)}")


def test_script_imports_without_touching_the_graph():
    """脚本必须能在**没有图/没有大模型**的机器上导入 —— 否则本地改不动、只能上真机试。"""
    spec = importlib.util.spec_from_file_location("demo_pipeline", _SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert callable(m.main) and callable(m.install_taps)


def test_demo_mode_is_the_default_so_a_demo_never_pollutes_production():
    """★默认必须是演示模式(不写台账/不写经验)。

    为做一次汇报而往生产台账和经验库里写东西,是那种「当时没人注意、以后查不清」的污染。
    默认只打印,要写得显式加 --write。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert '"--write", action="store_true"' in src
    assert "if write:" in src and "_stub(" in src


# --------------------------------------------------- 完整性(领导要看的就是这几条)

def test_llm_tap_target_exists():
    """★大模型调用的**唯一**入口必须叫这个名字。

    提示词打印同样靠「按名字包裹」:`QwenClient.chat` 一旦改名,提示词就**静默不再打印**,
    而演示照样跑完、看起来完整 —— 恰恰是最需要可核对的那部分没了。
    """
    from soc_agent.llm.qwen import QwenClient
    assert hasattr(QwenClient, "chat")


def test_every_llm_caller_goes_through_that_one_entry():
    """★"漏不掉任何一次调用"这句话得能证。

    全仓扫一遍:凡是调大模型的地方,都必须是 `.chat(`。
    出现别的调用方式(如 `.complete(` / 直接 requests.post 到 /v1/chat)就说明存在旁路,
    那样演示里就会缺一次提示词而没人知道。
    """
    import re
    root = _ROOT / "soc_agent"
    bypass = []
    for p in root.rglob("*.py"):
        src = p.read_text(encoding="utf-8")
        for m in re.finditer(r"\bllm\.(\w+)\(", src):
            if m.group(1) != "chat":
                bypass.append(f"{p.relative_to(_ROOT)}: llm.{m.group(1)}(")
    assert not bypass, f"存在绕过 chat() 的大模型调用,演示会漏打提示词:{bypass}"


def test_nothing_is_truncated_in_the_demo_renderers():
    """★不截断。截断过的东西没法核对,看起来就像编的 —— 领导明确要求「有多长就是多长」。

    钉住:渲染入口是 `full()`,且脚本里不再有把展示值切短的旧 `brief()`。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "def full(" in src
    assert "def brief(" not in src, "brief() 会截断展示值,已被要求移除"
    assert "此处截断" not in src


def test_deep_path_is_the_default_and_the_override_is_labelled():
    """★默认把告警当没见过的、完整走深度通道;而且必须**显式标注这是演示口径**。

    不标注的话,看的人会以为生产每条都请大模型 —— 那会把成本预期带偏,
    等于用一个好看的演示误导决策。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert '"--reuse", action="store_true"' in src          # 复用是**要显式打开**的
    assert "演示强制" in src and "不是生产行为" in src
    assert 'rep.decision = "FALLTHROUGH"' in src


def test_sediment_really_runs_but_lands_in_a_throwaway_store():
    """★蒸馏与考试**真跑**(否则「自进化」那一环只是嘴上说),但不落生产经验库。

    为做一次汇报而往经验库里塞东西,是那种当时没人注意、以后查不清的污染。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "InMemoryExperienceStore()" in src
    assert "_orig_sediment(" in src
    from soc_agent.experience.store import InMemoryExperienceStore
    assert hasattr(InMemoryExperienceStore, "all")          # 演示要把学到的东西列出来


# --------------------------------------------------- 浅层(三级漏斗第一级)

CASCADE_TAPS = ["sig_consult", "force_deep", "shallow_triage", "_sig_learn"]


@pytest.mark.parametrize("name", CASCADE_TAPS)
def test_cascade_tap_targets_exist(name):
    """★浅层三步的挂载点必须存在。

    浅层是三级漏斗的第一级(签名库前置 → 硬底线 → 浅层 LLM 分诊),
    首版演示**整级都没出现** —— 因为它由 `SOC_CASCADE_ENABLED` 控制、默认关,
    而脚本既没打开它、也没打印这个开关状态,等于把一整级藏起来了。
    这条钉住:名字改了就红,不会再悄悄少一级。
    """
    from soc_agent.cascade import run
    assert hasattr(run, name), f"演示脚本要包 cascade.run.{name},但它不存在(改过名?)"


def test_cascade_taps_patch_the_module_that_actually_calls_them():
    """★必须打到 `cascade.run` 的命名空间上,不是打到定义处的模块。

    `run.py` 用的是 `from .signature import sig_consult` / `from .floor import force_deep`,
    也就是**导入期就把函数绑进自己的命名空间**了。去补 signature.py / floor.py 是**没用的** ——
    补了不报错,浅层照跑,只是探针一次都不触发,演示又少一级而看不出来。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    for name in ("sig_consult", "force_deep", "shallow_triage"):
        assert f"CAS.{name} = " in src, f"{name} 必须打在 cascade.run(别名 CAS)上"
    from soc_agent.cascade import run
    import soc_agent.cascade.signature as sig
    import soc_agent.cascade.floor as floor
    assert run.sig_consult is sig.sig_consult          # 同一对象 ⇒ 必须补 run 这一侧
    assert run.force_deep is floor.force_deep


def test_shallow_tier_is_on_by_default_and_the_env_value_is_printed():
    """★演示默认打开浅层,并且**同时打印 .env 里的真实配置**。

    浅层生产可能是关的。只显示"开"而不显示"配置里是关的",看的人会以为生产就这么跑 ——
    和强制不走复用却不标注是同一类误导。
    """
    src = _SCRIPT.read_text(encoding="utf-8")
    assert '"--cascade", choices=["on", "off", "env"], default="on"' in src
    assert "SOC_CASCADE_ENABLED" in src
    assert "两者不一致" in src and "演示口径" in src
    assert "pl.cascade_enabled = use_cascade" in src


def test_shallow_terminal_is_forced_to_escalate_unless_reuse():
    """★浅层判成误报本可就地终局 —— 演示要展示完整漏斗,必须强制升级并标注。"""
    src = _SCRIPT.read_text(encoding="utf-8")
    assert "needs_deep=True" in src
    assert "演示要展示完整漏斗" in src


def test_run_investigation_still_branches_on_that_field():
    """★演示是靠改 `pl.cascade_enabled` 打开浅层的 —— 生产的分支依据必须还是这个字段。

    哪天 run_investigation 换成读别的开关,这条会红;否则演示会**静默退回只走深度**。
    """
    import inspect
    from soc_agent import cli
    assert "cascade_enabled" in inspect.getsource(cli.run_investigation)


# --------------------------------------------------- 端到端第 2 步(对演练图跑研判)

def test_e2e_verdict_refuses_the_production_and_shadow_graphs():
    """★演练数据绝不能进生产图或影子图。

    这条硬拒绝不是客气话:本仓真吃过亏 —— tap 验证的环境变量残留在 shell 里,
    金丝雀往影子写、生产图空,差点误判成 Kafka 坏了。所以拒绝要写在脚本里,不是靠人记着。
    """
    src = (_ROOT / "scripts" / "e2e-verdict.sh").read_text(encoding="utf-8")
    for bad in ("*7687*", "*7688*"):
        assert bad in src and "拒绝" in src
    assert "*7689*" in src                                   # 只放行演练图


def test_e2e_verdict_reuses_the_demo_pipeline_instead_of_a_slimmed_copy():
    """★复用 demo_pipeline(它包的是生产真实函数、打印完整提示词、不截断)。

    为一次验证另写"精简版流水线",验的就是一条生产不走的路 —— 本仓一路踩的就是这个。
    """
    src = (_ROOT / "scripts" / "e2e-verdict.sh").read_text(encoding="utf-8")
    assert "scripts/demo_pipeline.py" in src
    assert "--write" not in src.split("RUN=(")[-1].split("[3] 小结")[0]   # 默认不写生产


def test_e2e_alert_picker_uses_the_real_graph_client_api():
    """`run_cypher` 是 `**params` 不是 dict —— 传 {} 会 TypeError,而那只在真机上才炸。"""
    import inspect

    from soc_agent.graph.client import Neo4jGraph
    sig = inspect.signature(Neo4jGraph.run_cypher)
    assert any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    src = (_ROOT / "scripts" / "e2e_alerts.py").read_text(encoding="utf-8")
    assert "g.run_cypher(Q)" in src and "run_cypher(Q, {})" not in src


def test_e2e_alert_picker_builds_the_graph_client_the_production_way():
    """★整条构造路径都要与生产一致,不是只对一个方法签名。

    第一版写 `Neo4jGraph()`(它要 3 个位置参数)——**只在真机上才炸**,
    因为本地没有图、任何"能不能连上"的问题都测不出来。
    上一版刚在 `run_cypher` 上犯过同类错,说明钉一个方法不够,得钉构造。
    """
    import inspect

    from soc_agent.config import Config
    from soc_agent.graph.client import Neo4jGraph
    src = (_ROOT / "scripts" / "e2e_alerts.py").read_text(encoding="utf-8")
    assert "Config.from_env()" in src, "必须走与生产同一条配置入口"
    assert "Neo4jGraph()" not in src
    need = [n for n, p in inspect.signature(Neo4jGraph.__init__).parameters.items()
            if n != "self" and p.default is inspect.Parameter.empty]
    assert need, "构造签名变了?这条断言就是防它悄悄变"
    for n in need:                                    # uri/user/password 逐个都得传进去
        assert f"cfg.neo4j_{n}" in src or f"cfg.{n}" in src, f"没传 {n}"
