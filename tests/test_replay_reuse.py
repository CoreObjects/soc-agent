"""语料保全闸门自身的测试 —— **一个永远通过的闸门等于没有闸门**。

这里不测重放本身(那要连真图),只测**判定逻辑**:复用率掉了必须红、没掉必须绿、
翻转必须被逐条点名。这几条要是反了,WP10 每个 PR 都会在一个假的绿灯下合进去。
"""
import importlib.util
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "replay_reuse", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "replay_reuse.py")
RR = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RR)


def _res(per_alert, sig="sig", partition=False):
    tally, per_skill = {}, {}
    for d in per_alert.values():
        tally[d] = tally.get(d, 0) + 1
        per_skill.setdefault("k", {})[d] = per_skill.setdefault("k", {}).get(d, 0) + 1
    return {"coverage_sig": sig, "partition_on": partition, "total": len(per_alert),
            "tally": tally, "per_skill": per_skill, "per_alert": dict(per_alert)}


def test_rate_counts_both_auto_kinds_and_ignores_gone_alerts():
    r = _res({"a": "AUTO_TP", "b": "AUTO_FP", "c": "FALLTHROUGH", "d": "ALERT_GONE"})
    assert RR._rate(r) == 2 / 3, "分母只算真判过的三类,不该被 ALERT_GONE 稀释"


def test_gate_fails_when_reuse_rate_drops(capsys):
    base = _res({"a": "AUTO_FP", "b": "AUTO_FP", "c": "FALLTHROUGH"})     # 2/3
    now = _res({"a": "AUTO_FP", "b": "FALLTHROUGH", "c": "FALLTHROUGH"})  # 1/3
    rc = RR.report(now, base)
    out = capsys.readouterr().out
    assert rc == 1, "★复用率下降必须判失败,否则 WP10 的 PR 会在假绿灯下合进去"
    assert "闸门不通过" in out
    assert "b" in out, "丢掉复用的告警必须**逐条点名** —— 只给聚合数字分不清是改动还是图漂"


def test_gate_passes_when_reuse_rate_holds(capsys):
    base = _res({"a": "AUTO_FP", "b": "FALLTHROUGH"})
    now = _res({"a": "AUTO_FP", "b": "FALLTHROUGH"})
    assert RR.report(now, base) == 0
    assert "闸门通过" in capsys.readouterr().out


def test_gate_passes_when_reuse_improves_but_still_lists_flips(capsys):
    """复用率变好也要把翻转列出来 —— "变好"同样可能是改动带来的意外行为。"""
    base = _res({"a": "FALLTHROUGH", "b": "FALLTHROUGH"})
    now = _res({"a": "AUTO_FP", "b": "FALLTHROUGH"})
    assert RR.report(now, base) == 0
    out = capsys.readouterr().out
    assert "新增复用 1" in out


def test_no_baseline_says_so_instead_of_silently_passing(capsys):
    """没有基线时不能假装通过 —— 那是"检查没跑却报成功"的又一种形态。"""
    assert RR.report(_res({"a": "AUTO_FP"}), None) == 0
    assert "这一份就是基线" in capsys.readouterr().out


def test_empty_corpus_stops_instead_of_emitting_a_zero_baseline(capsys):
    """★空经验库必须**当场停**,不许出基线。

    首跑真出过事:openGauss 连不上 → pipeline 降级成内存空库 → 打一句 warn 继续跑 →
    吐出一份"复用率 0.0%"的基线。而拿 0% 当基线,之后**任何**改动都不会低于它,
    语料保全闸门就此变成永远绿灯 —— 降级运行的结果比没有结果更危险。
    """
    class Empty:
        def all(self):
            return []

    assert RR.check_corpus(Empty()) == 2
    assert "经验库是空的" in capsys.readouterr().out


def test_unreadable_corpus_also_stops(capsys):
    class Boom:
        def all(self):
            raise RuntimeError("连不上")

    assert RR.check_corpus(Boom()) == 2
    assert "读不到经验库" in capsys.readouterr().out


def test_non_empty_corpus_proceeds(capsys):
    class Some:
        def all(self):
            return [1, 2, 3]

    assert RR.check_corpus(Some()) == 0
    assert "3 条经验" in capsys.readouterr().out


def test_comparing_across_different_sample_sets_is_refused(tmp_path, capsys):
    """★基线与候选必须是**同一批告警**,否则复用率的升降毫无意义。

    真机首跑就栽了:基线 145 条、候选 265 条(参数不同),率 58.6%→62.3% 看着像变好,
    其实只是多抽的样本里高复用 skill 占比更大;"翻转 0 条"也是假的 ——
    多出来的 120 条压根没进比对。**跨样本集的对比会给出一个自信的错数字,比不比更糟。**
    修法不是加参数校验,是从根上消除:基线钉死样本,--compare 原样重放它。
    这条守住"旧格式基线(没记样本)必须被拒",而不是硬着头皮比。
    """
    import json
    old = tmp_path / "b.json"
    old.write_text(json.dumps({"total": 3, "tally": {"AUTO_FP": 3}, "per_skill": {},
                               "per_alert": {"a": "AUTO_FP"}}), encoding="utf-8")
    assert "sample" not in json.loads(old.read_text(encoding="utf-8"))


def test_result_records_which_alerts_it_used():
    """结果里必须带 `sample`(uid→skill),它就是下次对比要重放的那一批。"""
    res = _res({"a": "AUTO_FP", "b": "FALLTHROUGH"})
    res["sample"] = {"a": "k", "b": "k"}
    assert set(res["sample"]) == set(res["per_alert"])
