"""快通道匹配 + 分层签名建构。

判别器产分层特征 → to_signatures 规范化成有序 LayerSig(先证伪在前)。
match_active 按层序查 active 规则:豁免层(FP)命中优先于坐实层(TP)—— 先证伪。
生成侧:layer_for_verdict 定该 verdict 落哪层(FP/benign 落 exculpatory 粗键、TP/suspicious 落 incriminating 细键)。
"""
from typing import List, Optional

from .repository import PatternRepository
from .rule import PatternRule
from .signature import LayerSig, canonicalize

_EXCULPATORY_VERDICTS = {"false_positive", "benign"}


def to_signatures(skill: str, layers: List[dict]) -> List[LayerSig]:
    """判别器分层特征 → 有序 LayerSig(保持判别器给的层序:先证伪在前)。"""
    return [canonicalize(skill, l["layer"], l["features"]) for l in layers]


def layer_for_verdict(verdict: str) -> str:
    """该 verdict 该在哪层生成规则:证伪类落 exculpatory(粗键),其余落 incriminating(细键)。"""
    return "exculpatory" if verdict in _EXCULPATORY_VERDICTS else "incriminating"


def match_active(repo: PatternRepository, skill: str, layers: List[dict]) -> Optional[PatternRule]:
    """快通道:按层序查 active 规则,首个命中返回(豁免层优先→先证伪);全不中→None。"""
    for sig in to_signatures(skill, layers):
        rule = repo.find_active(sig.sig_hash)
        if rule is not None:
            return rule
    return None


def signature_for_verdict(skill: str, layers: List[dict], verdict: str) -> Optional[LayerSig]:
    """生成规则时:取该 verdict 对应层的签名(该层不在判别结果里→None)。"""
    want = layer_for_verdict(verdict)
    for sig in to_signatures(skill, layers):
        if sig.layer == want:
            return sig
    return None
