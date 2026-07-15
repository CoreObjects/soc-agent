"""配置:从环境变量 / .env 读端点与参数。

真实端点/口令只放 server2 本地 .env(已 gitignore),绝不入公开仓。
os.environ 覆盖 .env 文件。极简 .env 解析,免 python-dotenv 依赖。
"""
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = ["Config", "load_dotenv"]

_REPO_ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path) -> dict:
    """解析 .env(KEY=VALUE 行)为 dict。文件不存在返回 {}。不写进 os.environ。"""
    env: dict = {}
    p = Path(path)
    if not p.exists():
        return env
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = re.split(r"\s+#", v, maxsplit=1)[0]      # 剥行内注释(值后 "空格+#…";在原始值上做,避免 strip 后 # 顶到行首)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


@dataclass
class Config:
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_database: Optional[str]
    llm_api_base: str
    llm_model: str
    llm_api_key: str
    skills_dir: str
    max_iterations: int
    # 攻击模式规则库(图外权威 = openGauss;OG_HOST 为空 → 用内存 fake,便于本地/单测)
    og_host: str
    og_port: int
    og_db: str
    og_user: str
    og_password: str
    og_schema: str

    @property
    def og_enabled(self) -> bool:
        return bool(self.og_host)

    @classmethod
    def from_env(cls, env=None, dotenv_path=None) -> "Config":
        merged: dict = {}
        if dotenv_path is not None:
            merged.update(load_dotenv(dotenv_path))
        merged.update(dict(env) if env is not None else dict(os.environ))

        def g(key, default=None):
            v = merged.get(key)
            return v if v not in (None, "") else default

        return cls(
            neo4j_uri=g("NEO4J_URI", ""),
            neo4j_user=g("NEO4J_USER", "neo4j"),
            neo4j_password=g("NEO4J_PASSWORD", ""),
            neo4j_database=g("NEO4J_DATABASE", None),
            llm_api_base=g("LLM_API_BASE", ""),
            llm_model=g("LLM_MODEL", "qwen32b-ft"),
            llm_api_key=g("LLM_API_KEY", "EMPTY"),
            skills_dir=g("SKILLS_DIR", str(_REPO_ROOT / "skills")),
            max_iterations=int(g("MAX_ITERATIONS", "12")),
            og_host=g("OG_HOST", ""),
            og_port=int(g("OG_PORT", "5432")),
            og_db=g("OG_DB", "soc"),
            og_user=g("OG_USER", "soc_agent"),
            og_password=g("OG_PASSWORD", ""),
            og_schema=g("OG_SCHEMA", "app"),
        )
