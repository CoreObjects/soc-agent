"""经验库连接的自愈 —— 这是生产上"高斯经常连不上"的真因所在。

★机制:poller 是**常驻进程**,原实现在启动时连一次、三个 Store 共用那条连接用一辈子,
  而全模块**没有任何**重连/健康检查(改之前 grep `InterfaceError|reconnect|ping` 命中数 = 0)。
  配上 openGauss 的 `session_timeout`(**默认 600 秒**,PostgreSQL 没这个参数):
  poller 只要 10 分钟没做经验读写,服务端就掐掉会话,
  **此后每次经验读写都抛 InterfaceError,直到有人重启 poller**。

★它一直没被发现,是因为**表现与"没有匹配的经验"一模一样**:查不到就走大模型,
  链路照常出结论,只是复用永远不命中、蒸馏永远落不了地。
  现网数字对得上:experience 28 行(≈启动后头 10 分钟写的),cases 10.3 万
  (批处理脚本写的,每次新进程新连接,不受影响)。
"""
import pytest

from soc_agent.experience import opengauss as OG


class _Cur:
    def __init__(self, owner, dead):
        self.owner, self.dead = owner, dead

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, *a):
        if self.dead:
            raise RuntimeError("connection already closed")   # 模拟 InterfaceError
        self.owner.executed.append(sql)

    def fetchone(self):
        return (1,)

    def fetchall(self):
        return []


class _Conn:
    """假连接:`kill()` 之后所有 execute 都抛 —— 就是被 session_timeout 掐掉的样子。"""

    def __init__(self):
        self.dead, self.executed, self.closed = False, [], 0

    def kill(self):
        self.dead = True

    def cursor(self):
        return _Cur(self, self.dead)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed += 1


@pytest.fixture()
def wired(monkeypatch):
    """把 `_connect` 换成发假连接的工厂,记录建了几条。"""
    made = []

    def fake(_cfg):
        c = _Conn()
        made.append(c)
        return c

    monkeypatch.setattr(OG, "_connect", fake)
    return made


def test_first_use_connects_lazily(wired):
    lc = OG.LiveConn(cfg=None)
    assert wired == []                       # ★惰性:构造时不连(进程起得来,即使库暂时不在)
    with lc.cursor() as cur:
        cur.execute("SELECT 1")
    assert len(wired) == 1


def test_it_heals_after_the_server_kills_the_session(wired):
    """★核心:会话被掐掉之后,下一次使用必须**自动重连**并成功,而不是一直抛到进程重启。"""
    lc = OG.LiveConn(cfg=None)
    with lc.cursor() as cur:
        cur.execute("SELECT 1")
    wired[0].kill()                          # openGauss session_timeout 到了
    with lc.cursor() as cur:                 # 下一次读写
        cur.execute("SELECT 2")
    assert len(wired) == 2, "没有重连 —— 这正是生产上那个 bug"
    assert lc.reconnects == 1                # ★可观测:现网这个数应该 > 0
    assert wired[0].closed == 1              # 死连接要关掉,别泄漏


def test_reconnect_failure_is_loud_not_silent(monkeypatch):
    """★连不上要**抛**。静默降级会让"库连不上"和"没有匹配的经验"再次无法区分 ——
    那正是这个 bug 藏了这么久的原因。"""
    calls = {"n": 0}

    def flaky(_cfg):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Conn()
        raise RuntimeError("could not connect to server")

    monkeypatch.setattr(OG, "_connect", flaky)
    lc = OG.LiveConn(cfg=None)
    with lc.cursor() as cur:
        cur.execute("SELECT 1")
    lc._conn.kill()
    with pytest.raises(RuntimeError, match="could not connect"):
        lc.cursor()


def test_session_timeout_is_disabled_at_connect_time():
    """双保险:连上就把服务端空闲超时关掉(会话级)。★这条是 openGauss 与 PG 的关键差异。"""
    import inspect
    src = inspect.getsource(OG._connect)
    assert "session_timeout = 0" in src
    assert "statement_timeout" in src        # 原有的 15s 语句超时不许弄丢


def test_a_pg_without_that_parameter_does_not_break_connect():
    """别的 PG 兼容库没有 session_timeout —— 那不是错,不能因此连不上。"""
    import inspect
    src = inspect.getsource(OG._connect)
    assert "except Exception" in src and "rollback" in src


def test_open_stores_uses_liveconn_not_a_bare_connection():
    """★三个 Store 必须共用**会自愈的**那条,而不是裸连接(改之前就是裸的)。"""
    import inspect
    src = inspect.getsource(OG.open_stores)
    assert "LiveConn(cfg)" in src
    assert "_connect(cfg)" not in src


def test_liveconn_quacks_like_a_connection_so_stores_need_no_change():
    """Store 里用的就是 `conn.cursor()` / `conn.commit()` —— 少一个方法就会在真机上才炸。"""
    for name in ("cursor", "commit", "rollback", "close"):
        assert callable(getattr(OG.LiveConn, name)), name
    assert isinstance(OG.LiveConn.closed, property)
