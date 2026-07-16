"""P5' daemon —— 常驻轮询图里「未研判」告警,自动跑现有编排研判+沉淀+回写。

设计定调:**单弱 vLLM 是唯一瓶颈** → 单实例、慢通道串行就是最优(多 worker 打不过一个 vLLM、只会抢着双烧)。
- 发现:`(:Alert)` 无 `:CONCLUDED` 出边 + arrival 早于 settle 窗口 now-Δ(等佐证事实到齐)+ 范围闸(只自动研判有签名覆盖的 technique)。
- 每告警工作单元 = 复用 `cli.run_investigation`(get_alert→seed→investigate→write_result),循环体零新逻辑。
- 背压:单线程串行 → 慢通道天然 1 在飞,跑不过 vLLM 就把积压留在图里慢慢排。
- 可靠性:单实例 PID 锁 + 崩溃幂等重做(未结论重启即重跑;上次沉了 openGauss 规则没写图 → 这次快通道 0-LLM 命中再写)+ 毒告警连败死信。
- 运行:--once(排空一趟,ferry 验收)/ --selftest(内存 fake 自检)/ 常驻。
"""
import argparse
import os
import signal
import sys
import time
from pathlib import Path

from .models import InvestigationResult, Verdict

__all__ = ["Daemon", "acquire_singleton", "SingletonError", "main"]

# 未研判选择器:无 CONCLUDED 出边 + 过 settle 窗口 + 范围闸(空清单=全放开);高危优先、同级 FIFO 不饿死。
_SELECT_CYPHER = (
    "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
    "AND coalesce(a.arrival_ms, 0) < $cutoff_ms "
    "AND ($techs = [] OR any(t IN coalesce(a.technique_ids, []) WHERE t IN $techs)) "
    "RETURN a.alert_uid AS uid "
    "ORDER BY coalesce(a.severity, 0) DESC, coalesce(a.arrival_ms, 0) ASC "
    "LIMIT $batch"
)


class SingletonError(Exception):
    """已有活着的 daemon 实例持锁。"""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)          # 信号 0 = 只探活不真发信号(POSIX)
    except (OSError, ProcessLookupError):
        return False
    return True


def acquire_singleton(pid_path, alive_fn=_pid_alive):
    """单实例锁:pid 文件里若是活进程 → 拒;不存在/陈旧(进程已死)→ 抢占写本进程 pid。"""
    p = Path(pid_path)
    if p.exists():
        try:
            old = int((p.read_text(encoding="utf-8").strip() or "0"))
        except (ValueError, OSError):
            old = 0
        if old and alive_fn(old):
            raise SingletonError("daemon 已在运行(pid=%d,锁=%s)" % (old, pid_path))
    p.write_text(str(os.getpid()), encoding="utf-8")
    return p


def _default_investigate(graph, orch, uid):
    """默认每告警工作单元 = 现成 cli.run_investigation(惰性导入避免装配期环)。"""
    from .cli import run_investigation
    return run_investigation(graph, orch, uid)


class Daemon:
    def __init__(self, graph, orch, cfg, investigate_fn=_default_investigate):
        self.graph = graph
        self.orch = orch
        self.cfg = cfg
        self.investigate_fn = investigate_fn
        self._attempts = {}          # uid → 连续失败次数(内存;成功即清零)
        self._dead = set()           # 已死信的 uid(本进程内不再重选)
        self._stop = False

    # ---- 选择 ----
    def _select(self, now_ms):
        cutoff = now_ms - self.cfg.daemon_settle_s * 1000
        rows = self.graph.run_cypher(
            _SELECT_CYPHER, cutoff_ms=cutoff,
            techs=list(self.cfg.daemon_techniques), batch=self.cfg.daemon_batch_size)
        return [r["uid"] for r in rows if r.get("uid") and r["uid"] not in self._dead]

    # ---- 单条处理(含毒告警死信)----
    def _process(self, uid):
        try:
            self.investigate_fn(self.graph, self.orch, uid)
            self._attempts.pop(uid, None)                 # 成功 → 清失败计数
            return "concluded"
        except Exception as exc:                          # 研判/回写异常:计数,连败到顶转死信
            self._attempts[uid] = self._attempts.get(uid, 0) + 1
            if self._attempts[uid] >= self.cfg.daemon_max_attempts:
                self._dead_letter(uid, exc)
                return "dead_lettered"
            return "failed"

    def _dead_letter(self, uid, exc):
        """连败到顶 → 写一条兜底 suspicious verdict 让告警闭环+出台账给人看,不再无限重选(承接 R5 每条告警都闭环)。"""
        self._dead.add(uid)
        v = Verdict(verdict="suspicious", lean="unknown", confidence=0.0,
                    summary="daemon 连续 %d 次自动研判失败,转人工" % self.cfg.daemon_max_attempts,
                    rationale="daemon 异常:%s" % exc,
                    missing_evidence=["daemon 未能完成自动研判"], agent="daemon")
        result = InvestigationResult(alert_uid=uid, path="B", verdict=v, dispositions=[])
        try:
            self.graph.write_result(uid, result)
        except Exception:
            pass                                          # 死信回写再失败也不拖垮循环(下轮 _dead 已挡)

    # ---- 一趟排空 ----
    def run_once(self, now_ms=None):
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        uids = self._select(now_ms)
        counts = {"selected": len(uids), "concluded": 0, "failed": 0, "dead_lettered": 0}
        for uid in uids:
            if self._stop:
                break
            counts[self._process(uid)] += 1
        return counts

    # ---- 常驻 ----
    def stop(self, *_a):
        self._stop = True

    def serve(self, sleep_fn=None):
        sleep_fn = sleep_fn or time.sleep
        while not self._stop:
            c = self.run_once()
            if c["selected"]:
                _log("run_once: %s" % c)
            if self._stop:
                break
            sleep_fn(self.cfg.daemon_poll_interval_s)


def _log(msg):
    print("[daemon %s] %s" % (time.strftime("%H:%M:%SZ", time.gmtime()), msg), flush=True)


# ---------- --selftest(内存 fake,不碰真基建)----------
class _FakeGraph:
    def __init__(self, uids):
        self._uids = list(uids)
        self.writes = []

    def run_cypher(self, q, **p):
        return [{"uid": u} for u in self._uids]

    def write_result(self, uid, result):
        self.writes.append(uid)


def _selftest():
    seen = []
    cfg = argparse.Namespace(daemon_poll_interval_s=1, daemon_batch_size=20, daemon_settle_s=120,
                             daemon_techniques=["T1558.003"], daemon_max_attempts=2, daemon_slow_concurrency=1)
    g = _FakeGraph(["u1", "u2", "poison"])

    def fake_inv(graph, orch, uid):
        if uid == "poison":
            raise RuntimeError("boom")
        seen.append(uid)

    d = Daemon(graph=g, orch=object(), cfg=cfg, investigate_fn=fake_inv)
    c1 = d.run_once(now_ms=10**12)
    c2 = d.run_once(now_ms=10**12)                        # poison 第2次连败 → 死信
    ok = (seen == ["u1", "u2", "u1", "u2"] and c1["concluded"] == 2 and c1["failed"] == 1
          and c2["dead_lettered"] == 1 and g.writes == ["poison"])
    print("selftest: seen=%s c1=%s c2=%s writes=%s" % (seen, c1, c2, g.writes))
    print("SELFTEST: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="P5' daemon:轮询未研判告警自动研判")
    ap.add_argument("--once", action="store_true", help="排空一趟后退出(git-ferry 验收用)")
    ap.add_argument("--selftest", action="store_true", help="内存 fake 自检,不碰真基建")
    ap.add_argument("--dotenv", default=None, help=".env 路径(端点/口令)")
    ap.add_argument("--pidfile", default=None, help="单实例 PID 锁路径(默认 <repo>/daemon.pid)")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    from .config import Config
    from .cli import build_orchestrator

    repo_root = Path(__file__).resolve().parents[1]
    cfg = Config.from_env(dotenv_path=args.dotenv or str(repo_root / ".env"))
    pidfile = args.pidfile or str(repo_root / "daemon.pid")
    try:
        acquire_singleton(pidfile)
    except SingletonError as e:
        print("⛔ %s" % e)
        return 1

    graph, orch, _repo = build_orchestrator(cfg)
    daemon = Daemon(graph=graph, orch=orch, cfg=cfg)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, daemon.stop)              # 优雅停:跑完当前告警再退
        except (ValueError, OSError):
            pass                                         # 非主线程/不支持 → 略
    try:
        if args.once:
            c = daemon.run_once()
            _log("--once 完成:%s" % c)
        else:
            _log("常驻启动:interval=%ds batch=%d settle=%ds techs=%s"
                 % (cfg.daemon_poll_interval_s, cfg.daemon_batch_size, cfg.daemon_settle_s,
                    cfg.daemon_techniques or "全放开"))
            daemon.serve()
            _log("已优雅停止")
    finally:
        graph.close()
        try:
            os.remove(pidfile)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
