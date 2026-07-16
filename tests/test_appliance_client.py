"""处置面 HTTP 客户端:server2 → 靶场 appliance 的受控接口(execute/rollback/reset)。

只验方法→路径→载荷映射 + enabled(不真发 HTTP)。真连通在 server2 上 curl /health 验。
"""
from soc_agent.response.appliance_client import ApplianceClient


class _Rec(ApplianceClient):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.calls = []

    def _request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return {"status": "executed"}


def test_enabled_only_when_url_set():
    assert not ApplianceClient(url="").enabled
    assert ApplianceClient(url="http://x:8765").enabled


def test_execute_posts_primitive_and_params():
    c = _Rec(url="http://r:8765", token="t")
    c.execute("disable_account", {"sam": "hacker2"})
    assert c.calls[0] == ("POST", "/execute", {"primitive": "disable_account", "params": {"sam": "hacker2"}})


def test_rollback_posts_handle():
    c = _Rec(url="http://r:8765")
    c.rollback({"inverse": "enable_account", "params": {"sam": "hacker2"}})
    assert c.calls[0] == ("POST", "/rollback", {"rollback_handle": {"inverse": "enable_account", "params": {"sam": "hacker2"}}})


def test_reset_posts_accounts_flag():
    c = _Rec(url="http://r:8765")
    c.reset(accounts=True)
    assert c.calls[0] == ("POST", "/reset", {"accounts": True})


def test_health_is_get():
    c = _Rec(url="http://r:8765")
    c.health()
    assert c.calls[0] == ("GET", "/health", None)


def test_url_trailing_slash_normalized():
    assert ApplianceClient(url="http://r:8765/").url == "http://r:8765"
