"""PROFILE 探针的**防漂移**自检 —— 探针写死了"新形式",这里保证它写死的就是现网跑的那份。

为什么要有这条:首版探针把新形式硬编码在脚本里,之后 kerberoast 按首跑结论补了
`ticket_kind` 判别位、lateral_movement 补了 `outcome`,**脚本没跟着改**。
于是它继续测一个代码里已经不存在的写法 —— 跑出来的绿或红都不指向现网,
而且从输出上完全看不出来。这类"闸门自己过期了"的失败,比闸门报错危险得多。

所以放进测试套件而不是只在脚本里 assert:每次 CI 都会因 recipe 改动而红,
逼着探针跟着更新,而不是等下一次真机跑出来一个不知道在测什么的结论。
"""
import importlib.util
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "profile_predicate",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "profile_predicate.py")
PP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(PP)


def test_probe_cases_match_the_live_recipes():
    """★每条 case 的新形式 WHERE 必须逐字出现在它所属的 recipe 里。

    这条红了 = 改了 recipe 的谓词却没同步探针 ⇒ 去改 `CASES`,别改这条测试。
    """
    assert PP._assert_live(PP.CASES) == []


def test_drift_check_actually_fails_when_it_should():
    """故障注入:把新形式改一个字,自检必须报出来 —— 否则它只是装饰。"""
    name, old, new, pk, path = PP.CASES[0]
    mutated = (name, old, new.replace("auth.logon", "auth.logon_TYPO"), pk, path)
    bad = PP._assert_live([mutated])
    assert len(bad) == 1 and path in bad[0]


def test_where_extraction_stops_at_the_next_clause():
    """WHERE 子句要抽干净:抽多了会把后面的 MATCH 也带进比对,永远对不上。"""
    q = ("MATCH (e:Event)-[:BY]->(:Account {sam:$s}) "
         "WHERE e.event_code='4624' OR e.activity='auth.logon' "
         "MATCH (e)-[:AUTHENTICATED_TO]->(:Host) RETURN 1")
    assert PP._where_of(q) == "WHERE e.event_code='4624' OR e.activity='auth.logon'"
    assert PP._where_of("MATCH (n) RETURN n") is None


def test_unordered_makes_collect_lists_comparable():
    """`collect(DISTINCT …)` 无序 —— 判等必须按集合,否则每跑一次都可能假红。"""
    a = [{"endpoints_hit": ["/a", "/b"], "n": 2}]
    b = [{"endpoints_hit": ["/b", "/a"], "n": 2}]
    assert PP._unordered(a) == PP._unordered(b)
    assert a != b                                          # 原样比是不等的
    c = [{"endpoints_hit": ["/a", "/X"], "n": 2}]          # 内容真变了,仍要不等
    assert PP._unordered(a) != PP._unordered(c)
