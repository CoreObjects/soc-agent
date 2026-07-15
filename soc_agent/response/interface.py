"""处置接口文档(interface)—— 原语语义的唯一来源 + 换真企业设备的换点。

一份文档声明靶场处置面开放的每个基础处置原语:目标类型/参数/前置/爆炸半径/风险/可逆性/inverse/
执行点(enforcement_point)。composer 读它知道能调哪些原语;agent 语义层(护栏/台账/目标解析)读它
拿 kind/gating/期望目标类型/inverse —— 不再把这些散落硬编码。真企业部署 = 指向他们设备实现同一 schema
的文档,agent 逻辑不动。

core(Interface/Primitive)纯 dict 驱动、可离线单测(不依赖 yaml);load_interface 是薄文件包装
(.yaml 走 PyYAML、.json 走 stdlib),便于把契约写成人读的 interface.yaml。
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

__all__ = ["Interface", "Primitive", "load_interface", "default_interface"]

# 非执行、agent 侧语义动作(不是靶场原语):不进接口文档,但受控词表要认。
NON_EXECUTING = {"escalate", "monitor", "none"}


@dataclass
class Primitive:
    id: str
    category: str = "endpoint"          # identity | network | endpoint
    summary: str = ""
    target: dict = field(default_factory=dict)      # {kind, key_field, extra_keys}
    params: list = field(default_factory=list)      # [{name,type,required,source,role?}]
    preconditions: list = field(default_factory=list)
    gating: str = "gated"               # gated(需人审) | auto(只读/无害)
    blast_radius: str = "single_target"  # single_target | host | domain
    risk_default: str = "high"
    reversible: dict = field(default_factory=lambda: {"mode": "none"})
    enforcement_point: Optional[str] = None
    planned_by_composer: bool = True     # 纯 inverse(enable/unblock/release/restore)置 False,composer 不规划
    raw: dict = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return self.target.get("kind") or "none"

    @property
    def key_field(self) -> Optional[str]:
        return self.target.get("key_field")

    def required_params(self) -> List[str]:
        return [p["name"] for p in self.params if p.get("required")]

    @classmethod
    def from_dict(cls, d: dict) -> "Primitive":
        return cls(
            id=d["id"], category=d.get("category", "endpoint"), summary=d.get("summary", ""),
            target=dict(d.get("target") or {}), params=list(d.get("params") or []),
            preconditions=list(d.get("preconditions") or []),
            gating=d.get("gating", "gated"), blast_radius=d.get("blast_radius", "single_target"),
            risk_default=d.get("risk_default", "high"),
            reversible=dict(d.get("reversible") or {"mode": "none"}),
            enforcement_point=d.get("enforcement_point"),
            planned_by_composer=d.get("planned_by_composer", True),
            raw=dict(d),
        )


class Interface:
    """处置接口文档。原语语义的只读来源;未知原语一律从严(gated、kind=none 不硬造 :ON)。"""

    def __init__(self, version: str, primitives: List[Primitive]):
        self.version = version
        self._by_id = {p.id: p for p in primitives}

    # ---- 构造 ----
    @classmethod
    def from_dict(cls, data: dict) -> "Interface":
        prims = [Primitive.from_dict(p) for p in (data.get("primitives") or [])]
        return cls(version=str(data.get("version") or ""), primitives=prims)

    # ---- 查询 ----
    def ids(self) -> set:
        return set(self._by_id)

    def is_known(self, pid: str) -> bool:
        return pid in self._by_id

    def get(self, pid: str) -> Optional[Primitive]:
        return self._by_id.get(pid)

    def kind_of(self, pid: str) -> str:
        p = self._by_id.get(pid)
        return p.kind if p else "none"

    def target_key_field(self, pid: str) -> Optional[str]:
        p = self._by_id.get(pid)
        return p.key_field if p else None

    def is_gated(self, pid: str) -> bool:
        p = self._by_id.get(pid)
        return True if p is None else p.gating != "auto"   # 未知从严:gated

    def blast_radius(self, pid: str) -> str:
        p = self._by_id.get(pid)
        return p.blast_radius if p else "single_target"

    def is_domain_scoped(self, pid: str) -> bool:
        return self.blast_radius(pid) == "domain"

    def touches_endpoint(self, pid: str) -> bool:
        p = self._by_id.get(pid)
        return bool(p and p.category == "endpoint")

    def reversible_mode(self, pid: str) -> str:
        p = self._by_id.get(pid)
        return (p.reversible.get("mode") if p else None) or "none"

    def inverse_of(self, pid: str) -> Optional[str]:
        p = self._by_id.get(pid)
        return p.reversible.get("inverse") if p else None

    def composer_menu_ids(self) -> set:
        """composer 可规划的正向原语(排除纯 inverse)。"""
        return {p.id for p in self._by_id.values() if p.planned_by_composer}


def load_interface(path) -> Interface:
    """从文件加载接口文档。.json 走 stdlib;.yaml/.yml 走 PyYAML;

    ★缺 PyYAML(如离线单测的 venv)时,自动回退到同名 .json(由 interface.yaml 生成、一并入库)。
    interface.yaml 是人读的权威源;interface.json 是机器/离线可加载副本(sync-check 测试防漂移)。
    """
    p = Path(path)
    if p.suffix.lower() == ".json":
        import json
        return Interface.from_dict(json.loads(p.read_text(encoding="utf-8")) or {})
    try:
        import yaml
    except ImportError as e:
        alt = p.with_suffix(".json")
        if alt.exists():
            return load_interface(str(alt))
        raise ImportError(f"加载 {p.name} 需要 PyYAML(pip install pyyaml);或提供同名 .json") from e
    return Interface.from_dict(yaml.safe_load(p.read_text(encoding="utf-8")) or {})


_DEFAULT_CACHE: dict = {}


def default_interface(path=None) -> Interface:
    """进程内缓存的默认接口文档(按路径缓存)。path 缺省 = 仓库根 interface.yaml。"""
    if path is None:
        path = Path(__file__).resolve().parents[2] / "interface.yaml"
    path = str(path)
    if path not in _DEFAULT_CACHE:
        _DEFAULT_CACHE[path] = load_interface(path)
    return _DEFAULT_CACHE[path]
