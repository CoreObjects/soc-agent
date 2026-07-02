"""图元素数据模型（映射器输出;纯数据,写 Neo4j 前的中间表示）。"""
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Node:
    labels: Tuple[str, ...]        # 如 ("Event","Authentication") 或 ("Account",)
    key: dict                      # 身份属性(落图时按此 MERGE)
    props: dict = field(default_factory=dict)


@dataclass
class Edge:
    type: str                      # ACTOR/TARGET/FROM/TO/PRODUCES/ON_HOST/PARENT_OF/...
    src: Node
    dst: Node
    props: dict = field(default_factory=dict)


@dataclass
class Mapping:
    event: Node                    # :Event 超类节点
    nodes: List[Node] = field(default_factory=list)   # 对象节点
    edges: List[Edge] = field(default_factory=list)   # 角色边 + 结构边
