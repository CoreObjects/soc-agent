"""处置面契约层:处置接口文档(interface)= 原语语义的唯一来源。

- interface.py:Interface/Primitive + load_interface。原语的 kind/gating/blast_radius/inverse/期望目标类型
  全从这份文档取,不再散落硬编码在 models/disposition 里 —— 换真企业设备 = 换接口文档,agent 逻辑不动。
"""
from .interface import Interface, Primitive, load_interface, default_interface

__all__ = ["Interface", "Primitive", "load_interface", "default_interface"]
