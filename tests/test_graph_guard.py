"""只读守卫:agent 的 run_cypher 工具只能读事实层,绝不能写。

这是第一道防线(第二道 = 打开 Neo4j READ 会话,写会被库直接拒)。
守卫要放行正常 MATCH/RETURN/变长路径/只读 CALL,拦截 CREATE/MERGE/DELETE/SET/REMOVE/
写类 apoc、以及多语句里夹带的写。label/属性里恰好叫 Create/created 不能误伤。
"""
import pytest

from soc_agent.graph.guard import ReadOnlyViolation, assert_read_only, is_read_only

READ = [
    "MATCH (a:Alert {alert_uid:$id}) RETURN a",
    "MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)-[:BY]->(acc:Account) RETURN acc.sam, acc.domain",
    "MATCH p=(acc:Account)-[:AUTHENTICATED_TO*1..3]->(h:Host) RETURN p",
    "MATCH (n:Create) RETURN n",                       # Create 作 label,不是写
    "MATCH (e:Event) RETURN e.created_flag",           # created 作属性名,不是写
    'MATCH (a) WHERE a.name = "CREATE" RETURN a',      # 字符串字面量里的 CREATE 不算写
    "CALL apoc.path.expandConfig($n, {}) YIELD path RETURN path",
]

WRITE = [
    "CREATE (n:Foo) RETURN n",
    "MATCH (a) SET a.x = 1",
    "MATCH (a) DETACH DELETE a",
    "MERGE (n:Foo {id:1})",
    "MATCH (a) REMOVE a.x",
    "MATCH (a:Alert) RETURN a; CREATE (x:Y)",          # 多语句注入写
    "CALL apoc.create.node(['X'], {}) YIELD node RETURN node",
    "MATCH (a) DELETE a",
]


@pytest.mark.parametrize("q", READ)
def test_read_queries_allowed(q):
    assert is_read_only(q) is True
    assert assert_read_only(q) == q          # 放行,原样返回,不抛


@pytest.mark.parametrize("q", WRITE)
def test_write_queries_blocked(q):
    assert is_read_only(q) is False
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(q)


def test_blank_is_not_read_only():
    assert is_read_only("   ") is False
