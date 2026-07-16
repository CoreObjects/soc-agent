"""处置面 HTTP 客户端 —— server2 直接调靶场 appliance 的受控接口(execute/rollback/reset)。

agent 永不碰机器:只 HTTP 调这个受控接口;真做/护栏/审计都在 appliance 侧。
真企业换设备 = 换 RESPONSE_URL 指向他们设备实现同一 schema 的服务,agent 逻辑不动。
stdlib urllib,无三方依赖。_request 抽出便于离线单测。
"""
import json
import urllib.request

__all__ = ["ApplianceClient", "ApplianceError"]


class ApplianceError(Exception):
    pass


class ApplianceClient:
    def __init__(self, url, token=None, timeout=180):
        self.url = (url or "").rstrip("/")
        self.token = token or None
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _request(self, method, path, payload=None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("X-Response-Token", self.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8")
        except Exception as e:                       # 网络/超时/HTTP 错 → 统一抛,调用方决定退回队列通道
            raise ApplianceError("%s %s: %s" % (method, path, e)) from e
        return json.loads(body) if body else {}

    def health(self):
        return self._request("GET", "/health")

    def primitives(self):
        return self._request("GET", "/primitives")

    def execute(self, primitive, params):
        return self._request("POST", "/execute", {"primitive": primitive, "params": params})

    def rollback(self, rollback_handle):
        return self._request("POST", "/rollback", {"rollback_handle": rollback_handle})

    def reset(self, accounts=True):
        return self._request("POST", "/reset", {"accounts": accounts})
