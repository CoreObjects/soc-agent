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


def _plan(op, details, hits=1, children=()):
    """造一棵 PROFILE 计划树 —— 算子名带 `@neo4j` 后缀,与驱动真实返回的一致。"""
    return {"operatorType": f"{op}@neo4j", "dbHits": hits, "rows": 1,
            "args": {"Details": details}, "children": list(children)}


def test_label_scan_is_detected_despite_the_database_suffix():
    """★首版判据写 `o == 'NodeByLabelScan'`,而驱动回的是 `'NodeByLabelScan@neo4j'`。

    等号永远不成立 ⇒ 「不得退化成全标签扫」这条**从首跑起一次都没生效过**,恒 False。
    真机报告里因此出现自相矛盾:算子链印着 `NodeByLabelScan@neo4j`,同一行写 `全标签扫=False`。
    判据不生效比判据报错危险 —— 它长得像通过。这条测试就钉死这个后缀。
    """
    ops = PP._walk(_plan("NodeByLabelScan", "e:Event", 900000), [])
    assert [o for o, _h, _r, _d in ops] == ["NodeByLabelScan"]          # 后缀已剥掉
    assert PP.scans(ops) == [("NodeByLabelScan", "e:Event", 900000)]


def test_only_event_label_scan_counts_as_the_disaster():
    """扫 :Account(几十个节点)和扫 :Event(90 万)不是一回事,不能一概判死。"""
    ev = PP._walk(_plan("NodeByLabelScan", "e:Event"), [])
    acc = PP._walk(_plan("NodeByLabelScan", "a:Account"), [])
    assert any("Event" in d for _o, d, _h in PP.scans(ev))
    assert not any("Event" in d for _o, d, _h in PP.scans(acc))


def test_index_seek_is_not_mistaken_for_a_scan():
    """寻址算子不能被算成扫描 —— 否则闸门天天假红,很快就没人看了。"""
    assert PP.scans(PP._walk(_plan("NodeUniqueIndexSeek", "a:Account(sam)"), [])) == []


def test_details_falls_back_to_identifiers():
    """老版本 Neo4j 的计划没有 args.Details —— 退回 identifiers,别把对象说明丢成空。"""
    p = {"operatorType": "NodeByLabelScan@neo4j", "dbHits": 5, "rows": 1,
         "identifiers": ["e"], "children": []}
    assert PP._walk(p, [])[0][3] == "e"


def test_unordered_makes_collect_lists_comparable():
    """`collect(DISTINCT …)` 无序 —— 判等必须按集合,否则每跑一次都可能假红。"""
    a = [{"endpoints_hit": ["/a", "/b"], "n": 2}]
    b = [{"endpoints_hit": ["/b", "/a"], "n": 2}]
    assert PP._unordered(a) == PP._unordered(b)
    assert a != b                                          # 原样比是不等的
    c = [{"endpoints_hit": ["/a", "/X"], "n": 2}]          # 内容真变了,仍要不等
    assert PP._unordered(a) != PP._unordered(c)
