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
