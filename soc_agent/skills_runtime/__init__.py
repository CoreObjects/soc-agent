"""skills_runtime —— 加载"活的研判模块"(skill)并按告警选取。

skill = 一个目录:
  SKILL.md    方法论(frontmatter: name/layer/technique_ids/description + 正文决策树)
  recipes/    ① 取证脚本(慢通道沉淀;P3 起用)
  patterns/   ② 攻击模式判别→处置(慢通道沉淀;P4 起用)

选择:告警 technique 命中具体 skill;未覆盖 → 该层通用兜底(_generic/<layer>)。
frontmatter 用极简自解析(免 yaml 依赖):`key: value`,列表写 `[a, b]`。
"""
import importlib.util
from dataclasses import dataclass
from dataclasses import field as dataclasses_field
from pathlib import Path
from typing import Optional

__all__ = ["Skill", "load_skill", "SkillRegistry", "SkillNotFound", "parse_frontmatter"]


class SkillNotFound(Exception):
    """没有 skill 能匹配该告警(且无可用兜底)。"""


def _parse_value(v: str):
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [x.strip().strip('"').strip("'") for x in inner.split(",") if x.strip()]
    return v.strip('"').strip("'")


def parse_frontmatter(text: str):
    """返回 (meta: dict, body: str)。无 frontmatter 则 meta={}。"""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    fm, i = [], 1
    while i < len(lines) and lines[i].strip() != "---":
        fm.append(lines[i])
        i += 1
    body = "\n".join(lines[i + 1:]) if i < len(lines) else ""
    meta = {}
    for ln in fm:
        if ":" not in ln:
            continue
        k, _, v = ln.partition(":")
        meta[k.strip()] = _parse_value(v)
    return meta, body


@dataclass
class Skill:
    name: str
    layer: Optional[str]
    technique_ids: list
    description: str
    methodology: str            # SKILL.md 正文(方法论决策树)
    path: Path
    is_generic: bool = False
    recipe: Optional[object] = None                # recipe.py::collect(graph,alert,seed)→证据(慢通道喂 LLM)
    # ★recipe 加载失败的原因(语法/导入错)。**隔离但不静默**:
    #   以前这里只 `return None`,一个坏 recipe 就把该 skill 静默降级成"没有取证能力",
    #   系统照跑、只是从此永远走裸 LLM —— 与 `_coverage.absent` 要治的是同一类病
    #   (不报错、结论悄悄变差)。存下来,让 `registry.load_errors()` 能把它喊出来。
    recipe_error: Optional[str] = None
    # ★这个 skill 的判别**赖以成立**的遥测类别(SKILL.md 的 `needs:`,通用类别名不写厂商)。
    #   WP9 用它对着实测覆盖度算部署级缺口:整类没有 ⇒ 明说"我看不到",
    #   而不是照常跑出一份空 findings 然后被读成"没发现异常"。
    needs: list = dataclasses_field(default_factory=list)


def _load_attr(dir_path: Path, filename: str, attr: str):
    """加载 skill 目录里某 .py 的某函数 → `(func|None, error|None)`。
    ★出错不抛(每文件隔离,坏文件不拖垮 registry),但**把原因带出来**,不吞。"""
    fp = dir_path / filename
    if not fp.exists():
        return None, None
    try:
        spec = importlib.util.spec_from_file_location(f"skill_{attr}_{dir_path.name}", fp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, attr, None)
        return fn, (None if fn else f"{filename} 里没有 {attr}()")
    except Exception as e:          # 语法/导入错等 → 该 skill 缺这块能力,但不炸整个加载
        return None, f"{type(e).__name__}: {e}"


def _load_recipe(dir_path: Path):
    return _load_attr(dir_path, "recipe.py", "collect")


def load_skill(dir_path, is_generic: bool = False) -> Skill:
    dir_path = Path(dir_path)
    meta, body = parse_frontmatter((dir_path / "SKILL.md").read_text(encoding="utf-8"))
    tids = meta.get("technique_ids") or []
    if isinstance(tids, str):
        tids = [tids] if tids else []
    needs = meta.get("needs") or []
    if isinstance(needs, str):
        needs = [needs] if needs else []
    recipe, recipe_error = _load_recipe(dir_path)
    return Skill(
        name=meta.get("name") or dir_path.name,
        layer=meta.get("layer") or None,
        technique_ids=list(tids),
        description=meta.get("description") or "",
        methodology=body.strip(),
        path=dir_path,
        is_generic=is_generic,
        recipe=recipe,
        recipe_error=recipe_error,
        needs=list(needs),
    )


class SkillRegistry:
    """加载 skills 根目录下所有 skill;按告警选取。"""

    def __init__(self, skills_dir):
        self.dir = Path(skills_dir)
        self._skills: list[Skill] = []
        if self.dir.exists():
            for md in sorted(self.dir.rglob("SKILL.md")):
                d = md.parent
                rel = d.relative_to(self.dir)
                is_generic = bool(rel.parts) and rel.parts[0] == "_generic"
                self._skills.append(load_skill(d, is_generic=is_generic))

    def all(self) -> list:
        return list(self._skills)

    def load_errors(self) -> list:
        """`[(skill 名, 原因)]` —— recipe 加载失败的 skill。★启动/诊断时必须看它:
        一个语法坏掉的 recipe 不会让任何东西崩,只会让那条线从此永远走裸 LLM。"""
        return [(s.name, s.recipe_error) for s in self._skills if s.recipe_error]

    def specific(self) -> list:
        """非兜底 skill(供 LLM 路由做 Discovery 的候选集)。"""
        return [s for s in self._skills if not s.is_generic]

    def by_name(self, name: str) -> Optional[Skill]:
        for s in self._skills:
            if s.name == name:
                return s
        return None

    def generic_for_layer(self, layer: Optional[str]) -> Optional[Skill]:
        if not layer:
            return None
        for s in self._skills:
            if s.is_generic and s.layer == layer:
                return s
        return None

    def select(self, alert, layer: Optional[str] = None) -> Skill:
        """① technique 命中具体 skill;② 否则该层通用兜底;都没有 → SkillNotFound。"""
        tids = set(alert.technique_ids or [])
        for s in self._skills:
            if not s.is_generic and tids & set(s.technique_ids):
                return s
        if layer:
            for s in self._skills:
                if s.is_generic and s.layer == layer:
                    return s
        raise SkillNotFound(
            f"无 skill 匹配 technique={sorted(tids)} layer={layer}"
        )
