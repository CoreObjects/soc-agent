"""告警轮询研判运行时:持续从图里捞未研判告警 → run_investigation → 写台账 → 循环。

- 存量按 `arrival_ms` 升序消化(先旧后新);排空后 sleep(interval) 轮询新入图的。
- **CONCLUDED 作幂等水位**:已研判的不再捞;进程重启自动从"还没 CONCLUDED 的"续,不重判。
- **毒告警防护**:研判抛异常 → `poller_retries+1`;达 `retry_cap` → 打 `poller_skip` 不再重捞
  (防一条坏告警每轮重试卡死队列)。
- **2 并发**(默认)worker 线程池;**优雅退出**(SIGTERM/SIGINT:停止取新、排队未起的跳过、在跑的收尾)。

纯逻辑(batch_cypher/poison_props)与 I/O 解耦,mock graph 即可测(不引 neo4j/openjiuwen)。
默认研判入口 run_investigation 惰性导入 —— 本模块 3.10 可 import。
"""
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor

__all__ = ["Poller", "batch_cypher", "poison_props"]

# 取批:未 CONCLUDED、未 poller_skip、按到达序升序(存量先旧后新;新告警随后自然接上)
_BATCH_CYPHER = (
    "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
    "AND coalesce(a.poller_skip,false)=false "
    "RETURN a.alert_uid AS uid ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT $batch"
)
_BACKLOG_CYPHER = (
    "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
    "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n"
)


def batch_cypher() -> str:
    return _BATCH_CYPHER


def poison_props(retries, cap) -> dict:
    """毒告警:retry 次数 +1;达到 cap → 同时打 poller_skip 不再重捞。返回要 SET 的属性 dict。"""
    n = int(retries or 0) + 1
    props = {"poller_retries": n}
    if n >= cap:
        props["poller_skip"] = True
    return props


def _default_process(pl, uid, mode):
    from ..cli import run_investigation          # 惰性:本模块 3.10 可 import,不硬拉 cli/openjiuwen
    return run_investigation(pl, uid, mode=mode)


class Poller:
    def __init__(self, pl, *, interval=10.0, concurrency=2, batch=50, retry_cap=3,
                 process_fn=None, mode="recipe", logger=None):
        self.pl = pl
        self.interval = float(interval)
        self.concurrency = int(concurrency)
        self.batch = int(batch)
        self.retry_cap = int(retry_cap)
        self._process = process_fn or _default_process   # callable(pl, uid, mode)
        self.mode = mode
        self._log = logger or (lambda msg: print(msg, flush=True))
        self._stop = threading.Event()
        self.stats = {"done": 0, "failed": 0, "skipped": 0}

    # ---- I/O 小件(mock graph 可测)----
    def fetch_batch(self) -> list:
        rows = self.pl.graph.run_cypher(_BATCH_CYPHER, batch=self.batch)
        return [r["uid"] for r in rows]

    def backlog_count(self) -> int:
        rows = self.pl.graph.run_cypher(_BACKLOG_CYPHER)
        return rows[0]["n"] if rows else 0

    def _mark_poison(self, uid) -> None:
        node = self.pl.graph.get_alert(uid) or {}
        props = poison_props(node.get("poller_retries"), self.retry_cap)
        self.pl.graph.run_cypher(
            "MATCH (a:Alert {alert_uid:$uid}) SET a += $props", uid=uid, props=props)
        if props.get("poller_skip"):
            self.stats["skipped"] += 1
            self._log(f"  [skip] {uid} 连续失败 {props['poller_retries']} 次 → 标 poller_skip,不再重捞")

    def process_one(self, uid) -> None:
        if self._stop.is_set():
            return                                  # 优雅退出:已 stop,排队未起的直接跳过(下次再捞)
        try:
            self._process(self.pl, uid, self.mode)
            self.stats["done"] += 1
        except Exception as e:                      # 单条研判失败不拖垮整条队列
            self.stats["failed"] += 1
            try:
                self._mark_poison(uid)
            except Exception as me:                 # 连标记都失败:只记日志,别让循环崩
                self._log(f"  [err] 标记毒告警 {uid} 失败:{me}")
            self._log(f"  [err] 研判 {uid} 失败:{str(e)[:200]}")

    # ---- 生命周期 ----
    def request_stop(self, *args) -> None:
        self._stop.set()

    def should_stop(self) -> bool:
        return self._stop.is_set()

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.request_stop)
            except (ValueError, OSError):
                pass                                # 非主线程等场景装不上,忽略

    def run(self) -> None:
        """主循环:取批 → 2 并发研判 → 排空则 sleep 轮询。stop 后不取新批、在跑的收尾。"""
        self._log(f"# poller 启动  并发={self.concurrency} 批={self.batch} "
                  f"轮询间隔={self.interval}s 毒告警上限={self.retry_cap} 模式={self.mode}")
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while not self._stop.is_set():
                uids = self.fetch_batch()
                if not uids:
                    backlog = 0
                    self._log(f"# 队列排空(已判 {self.stats['done']} 失败 {self.stats['failed']} "
                              f"跳过 {self.stats['skipped']}),{self.interval}s 后再轮询")
                    if self._stop.wait(self.interval):   # sleep,可被 stop 立即打断
                        break
                    continue
                self._log(f"# 取批 {len(uids)} 条(积压 {self.backlog_count()});research 中…")
                for f in [pool.submit(self.process_one, u) for u in uids]:
                    f.result()                      # process_one 自己吞异常,这里不会抛
        self._log(f"# poller 退出  累计 已判 {self.stats['done']} 失败 {self.stats['failed']} "
                  f"跳过 {self.stats['skipped']}")
