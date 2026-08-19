"""`dc-derive` 探针的防漂移自检:它的短名归一必须**就是** dcsync recipe 那一份。

探针第 [4] 段的结论是"推出来的 DC 和卡死的 actor 对不对得上",而这个比对完全取决于短名归一。
要是探针自己写一份归一,它可能报"100% 对得上",而线上 recipe 用另一套规则照样点不着火 ——
一个不报错的假绿,还会据此得出"数据没问题"的错结论。所以钉死:同一个函数对象。
"""
import importlib.util
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DD = _load("dc_derive", "scripts/dc_derive.py")
RECIPE = _load("dcsync_recipe_ref", "skills/identity/dcsync/recipe.py")


def test_探针用的就是_recipe_那份短名归一():
    assert DD._short.__name__ == RECIPE._short.__name__
    for s in ("kingslanding$", "KINGSLANDING", "kingslanding.sevenkingdoms.local",
              "  Winterfell$  ", None, ""):
        assert DD._short(s) == RECIPE._short(s)


def test_三种主机名形态归一到同一个短名():
    """actor 是 `kingslanding$`,而 Host.hostname 可能是短名、FQDN 或大写 —— 都得对上,
    否则 [4] 段会因为形态差异报"对不上",把一个数据齐全的环境误诊成缺数据。"""
    forms = ["kingslanding$", "KINGSLANDING", "kingslanding",
             "kingslanding.sevenkingdoms.local", "KINGSLANDING.SEVENKINGDOMS.LOCAL"]
    assert len({DD._short(f) for f in forms}) == 1
