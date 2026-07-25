"""进程级单例依赖 + token 门(FastAPI Depends;测试用 dependency_overrides 覆盖)。

- graph/exp_store/appliance/llm 惰性建、进程内复用(neo4j 驱动 + httpx 线程安全;经验库套 _Locked)。
- 与 poller 分进程,各持自己的连接(读同一套 Neo4j/openGauss)。
"""
from fastapi import Depends, Header, HTTPException

from ..config import Config

_state: dict = {}          # 进程单例缓存


def get_config() -> Config:
    if "cfg" not in _state:
        _state["cfg"] = Config.from_env(dotenv_path=".env")
    return _state["cfg"]


def get_graph():
    if "graph" not in _state:
        from ..graph.client import Neo4jGraph
        c = get_config()
        _state["graph"] = Neo4jGraph(c.neo4j_uri, c.neo4j_user, c.neo4j_password, c.neo4j_database)
    return _state["graph"]


def get_exp_store():
    if "exp" not in _state:
        from ..cli import _open_stores
        _state["exp"] = _open_stores(get_config())[0]     # (exp_store, case, payload_corpus)[0]
    return _state["exp"]


def get_appliance():
    if "appliance" not in _state:
        from ..response.appliance_client import ApplianceClient
        c = get_config()
        _state["appliance"] = ApplianceClient(c.response_url, c.response_token)
    return _state["appliance"]


def get_llm():
    """Copilot 聊天用;缺 LLM 端点或建不起来 → 抛,由 chat 路由转 503。"""
    if "llm" not in _state:
        from ..llm.qwen import QwenClient
        c = get_config()
        _state["llm"] = QwenClient(c.llm_api_base, c.llm_model, c.llm_api_key, c.llm_timeout)
    return _state["llm"]


def get_llm_safe():
    """Copilot 用:建不起来(缺端点/依赖)→ 返回 None,由 chat 路由转 503(不 500)。"""
    try:
        return get_llm()
    except Exception:
        return None


def require_token(authorization: str = Header(default=""), cfg: Config = Depends(get_config)):
    """单一 operator token(Bearer)。未配 web_token → 开放;配了 → 无/错 token 一律 401。"""
    token = (cfg.web_token or "").strip()
    if not token:
        return None
    if authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="无效或缺失 token")
    return True
