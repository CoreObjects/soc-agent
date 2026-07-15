"""判别特征签名规范化。

规则库键 = skill + 层(exculpatory 先证伪 / incriminating 坐实)+ 判别特征值。
canonicalize() 把一组判别特征 → 稳定规范签名(顺序无关、值归一)+ sig_hash(sha256)。
★键是【作者选的判别特征值】,不是盲哈希整坨证据 —— 跟作废的 pattern_key 两回事。
"""
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class LayerSig:
    skill: str
    layer: str            # "exculpatory" | "incriminating"
    features: dict        # {判别特征名: 值}(桶化后)
    sig: str              # 规范串 k=v;… (键排序、值归一)
    sig_hash: str         # sha256(skill|layer|sig)


def _norm(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"       # bool 先于 int 判(True 是 int 子类)
    if v is None:
        return "null"
    return str(v)


def canonicalize(skill: str, layer: str, features: dict) -> LayerSig:
    sig = ";".join(f"{k}={_norm(features[k])}" for k in sorted(features))
    sig_hash = hashlib.sha256(f"{skill}|{layer}|{sig}".encode("utf-8")).hexdigest()
    return LayerSig(skill=skill, layer=layer, features=dict(features), sig=sig, sig_hash=sig_hash)
