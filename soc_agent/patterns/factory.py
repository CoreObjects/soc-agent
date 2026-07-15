"""规则库工厂:按 config 选实现。

og_enabled(OG_HOST 有值)→ openGauss 权威 + 进程内热读缓存;否则内存 fake(本地/单测)。
"""
from .cache import CachedPatternRepository
from .repository import InMemoryPatternRepository


def make_repository(cfg):
    if not getattr(cfg, "og_enabled", False):
        return InMemoryPatternRepository()
    from .opengauss_repo import OpenGaussPatternRepository
    backing = OpenGaussPatternRepository(
        host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
        user=cfg.og_user, password=cfg.og_password,
        schema=getattr(cfg, "og_schema", "app"))
    return CachedPatternRepository(backing)
