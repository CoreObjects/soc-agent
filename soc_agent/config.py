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
    llm_timeout: int              # 单次 LLM 调用超时(秒);慢的大模型(如 122b enforce-eager)按需调大
    skills_dir: str
    max_iterations: int
    # 靶场处置面 HTTP appliance(server2 直接调,免两台来回跑);空 → 退回图台账队列 + range-runner 通道
    response_url: str
    response_token: str
    # 第二类经验库 openGauss(server2 原生 5432,非 docker);空 OG_HOST → 经验层降级为"永远走 LLM"
    og_host: str
    og_port: int
    og_database: str
    og_user: str
    og_password: str
    og_schema: str
    # 浅度研判 cascade(openJiuwen)总开关;默认关=现状深度-only,不引 openjiuwen(3.10 可跑)
    cascade_enabled: bool = False
    # 处置模式:manual=只生成处置指令(待处置)不执行、留人审(默认);auto=自动走执行通道(护栏对 DC/CA 仍留待处置)
    response_mode: str = "manual"
    # Web 控制台单一 operator token(Bearer);空=不校验(本机/内训开放),配上=写路由 401 无/错 token
    web_token: str = ""
    # 告警轮询(poller):轮询间隔秒 / 并发 / 每批条数 / 毒告警连续失败上限
    poller_interval: float = 10.0
    poller_concurrency: int = 2
    poller_batch: int = 50
    poller_retry_cap: int = 3

    @property
    def appliance_enabled(self) -> bool:
        return bool(self.response_url)

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
            llm_timeout=int(g("LLM_TIMEOUT", "600")),
            skills_dir=g("SKILLS_DIR", str(_REPO_ROOT / "skills")),
            max_iterations=int(g("MAX_ITERATIONS", "12")),
            response_url=g("RESPONSE_URL", ""),
            response_token=g("RESPONSE_TOKEN", ""),
            og_host=g("OG_HOST", ""),
            og_port=int(g("OG_PORT", "5432")),
            og_database=g("OG_DATABASE", "soc"),
            og_user=g("OG_USER", "soc"),
            og_password=g("OG_PASSWORD", ""),
            og_schema=g("OG_SCHEMA", "soc"),
            cascade_enabled=str(g("SOC_CASCADE_ENABLED", "")).strip().lower()
            in ("1", "true", "yes", "on"),
            response_mode=("auto" if str(g("SOC_RESPONSE_MODE", "manual")).strip().lower() == "auto"
                           else "manual"),
            web_token=g("SOC_WEB_TOKEN", ""),
            poller_interval=float(g("POLLER_INTERVAL", "10")),
            poller_concurrency=int(g("POLLER_CONCURRENCY", "2")),
            poller_batch=int(g("POLLER_BATCH", "50")),
            poller_retry_cap=int(g("POLLER_RETRY_CAP", "3")),
        )
