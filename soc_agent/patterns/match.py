"""快通道匹配 + 分层签名建构。

签名函数产分层特征 → to_signatures 规范化成有序 LayerSig(先证伪在前)。
match_all 跑全部签名后【全局两趟先证伪】查 active 规则:先所有类型的豁免层(FP)、再所有坐实层(TP)。
生成侧:layer_for_verdict 定该 verdict 落哪层(FP/benign 落 exculpatory 粗键、TP/suspicious 落 incriminating 细键)。
"""
from typing import List, Optional

from .repository import PatternRepository
from .signature import LayerSig, canonicalize

_EXCULPATORY_VERDICTS = {"false_positive", "benign"}


def to_signatures(skill: str, layers: List[dict]) -> List[LayerSig]:
    """签名函数分层特征 → 有序 LayerSig(保持给定的层序:先证伪在前)。"""
    return [canonicalize(skill, l["layer"], l["features"]) for l in layers]


def layer_for_verdict(verdict: str) -> str:
    """该 verdict 该在哪层生成规则:证伪类落 exculpatory(粗键),其余落 incriminating(细键)。"""
    return "exculpatory" if verdict in _EXCULPATORY_VERDICTS else "incriminating"


_LAYER_ORDER = ("exculpatory", "incriminating")


def match_all(repo: PatternRepository, sig_list):
    """快通道:跑全部签名后【全局两趟先证伪】——先拿所有攻击类型的 exculpatory 签名碰 active FP 规则,
    再碰所有 incriminating(坐实)。★保证 A 类型的坐实不越过 B 类型的证伪。首个命中返回 (rule, entry);
    entry 携 skill+bindings 供快通道套模板换实例。全不中→None。sig_list = signatures.run_all 的输出。"""
    for want in _LAYER_ORDER:
        for entry in sig_list or []:
            for lyr in entry.get("layers") or []:
                if lyr.get("layer") != want:
                    continue
                sig = canonicalize(entry["skill"], lyr["layer"], lyr["features"])
                rule = repo.find_active(sig.sig_hash)
                if rule is not None:
                    return rule, entry
    return None


def signature_for_verdict(skill: str, layers: List[dict], verdict: str) -> Optional[LayerSig]:
    """生成规则时:取该 verdict 对应层的签名(该层不在判别结果里→None)。"""
    want = layer_for_verdict(verdict)
    for sig in to_signatures(skill, layers):
        if sig.layer == want:
            return sig
    return None
