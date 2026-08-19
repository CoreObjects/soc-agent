"""`sediment-yield` 探针的防漂移自检 —— 它复刻了 distill 的两条免费退出规则,这里保证复刻的还是现网那份。

为什么要有这条:探针的全部结论都建立在"distill 在调 LLM **之前**会因为
①verdict 不是 TP/FP/benign ②没有非元 finding 而直接 return"上。
这两条规则一旦在 distill 里改了而探针没跟着改,探针会继续报一个看起来很像样的分母 ——
既不报错,也不指向现网。**闸门自己过期**比闸门报错危险得多(profile_predicate 已经吃过一次)。

放测试套件而不是只在脚本里 assert:每次改 distill 都会红,逼着探针跟上。
"""
import importlib.util
import inspect
import pathlib

import soc_agent.experience.distill as D

_SPEC = importlib.util.spec_from_file_location(
    "sediment_yield",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "sediment_yield.py")
SY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SY)

_SRC = inspect.getsource(D.distill)


def test_可蒸的_verdict_集合与_distill_一致():
    """探针拿 `_DISTILLABLE` 当分母。它和 distill 第一道退出必须是同一个集合。"""
    assert tuple(SY._DISTILLABLE) == ("true_positive", "false_positive", "benign")
    assert '("true_positive", "false_positive", "benign")' in _SRC


def test_kind_由_verdict_导出_而不是蒸出来的():
    """★整个"把收敛检查提到 distill 之前"的前提就是这一条:
    kind 不需要调 LLM 就能知道。它要是变成模型输出的,前提就没了。"""
    assert 'kind = "threat" if verdict.verdict == "true_positive" else "benign_fp"' in _SRC
    assert SY.kind_of("true_positive") == "threat"
    assert SY.kind_of("false_positive") == "benign_fp"
    assert SY.kind_of("benign") == "benign_fp"


def test_kind_推导在_LLM_调用之前():
    """顺序也要钉:kind 得在 llm.chat 之前算出来,否则"免费"就不成立。"""
    assert _SRC.index("kind = ") < _SRC.index("llm.chat")


def test_元finding_不进指纹这条也还在():
    """探针按 `_` 前缀筛掉元 finding 来复刻第二道退出。"""
    assert 'startswith("_")' in _SRC
