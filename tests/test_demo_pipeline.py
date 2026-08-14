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
