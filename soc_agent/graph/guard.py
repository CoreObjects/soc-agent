"""只读 Cypher 守卫。

agent 的 `run_cypher` 工具只允许读事实层。写(经验层)只走专用 write_verdict/
write_disposition,不经此工具。守卫是**第一道防线**——给 LLM 清晰早拒 + 明确报错;
**硬保证**是打开 Neo4j READ 会话(写事务库层直接拒)。故守卫求实用,不必绝对完备。

策略:先剥掉字符串/反引号字面量(里面的 CREATE 之类不算写),再扫写类子句关键字
(要求是独立词、且不被 `:`(label)或 `.`(属性)前缀,避免 :Create/.created 误伤)、
写类 apoc 命名空间、LOAD CSV。命中任一 → 判为写、拒绝。
"""
import re

__all__ = ["is_read_only", "assert_read_only", "ReadOnlyViolation"]


class ReadOnlyViolation(Exception):
    """run_cypher 收到疑似写操作。"""


# 字符串/反引号字面量(含转义);先替换掉再扫关键字
_STRING_LIT = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`", re.S)
# 写类子句:独立词,前面不是 : (label) 或 . (属性) 或字母数字
_WRITE_CLAUSE = re.compile(r"(?<![:.\w])(CREATE|MERGE|DELETE|REMOVE|SET|DROP|FOREACH)(?![\w])", re.I)
_WRITE_APOC = re.compile(r"\bapoc\.(create|merge|refactor|atomic)\b", re.I)
_LOAD_CSV = re.compile(r"\bLOAD\s+CSV\b", re.I)


def _strip_literals(cypher: str) -> str:
    return _STRING_LIT.sub("''", cypher)


def is_read_only(cypher: str) -> bool:
    if not cypher or not cypher.strip():
        return False
    body = _strip_literals(cypher)
    if _WRITE_CLAUSE.search(body):
        return False
    if _WRITE_APOC.search(body):
        return False
    if _LOAD_CSV.search(body):
        return False
    return True


def assert_read_only(cypher: str) -> str:
    """放行则原样返回,否则抛 ReadOnlyViolation。"""
    if not is_read_only(cypher):
        raise ReadOnlyViolation(f"只读守卫拒绝(疑似写操作): {cypher!r}")
    return cypher
