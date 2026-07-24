"""poller 生产入口:每 worker 线程独立 pipeline(线程安全)→ 研判 + auto 处置 → Poller.run。

★并发安全:openGauss psycopg2 连接非线程安全 → **每 worker 线程建自己的 pipeline**(独立 Neo4j/openGauss/qwen
连接);经验数据仍共享(同一 openGauss 库 + 同一 Neo4j 图)。主循环(fetch/poison)只碰 Neo4j(线程安全)。
control_pl 先建好(顺带建表)→ worker 并发建 pipeline 时表已在,不撞 CREATE。
"""
import threading

from .poller import Poller

__all__ = ["run_poller", "make_processor"]


def make_processor(cfg, appliance_client, built_pls, lock, logger=None):
    """poller 的 per-alert 处理器。manual:只研判(组处置=proposed 待处置);
    auto:研判后自动 approve/执行(护栏对 DC/CA 仍拒、留待处置)。每 worker 首次调用建本线程 pipeline。"""
    log = logger or (lambda m: print(m, flush=True))
    tls = threading.local()

    def process(control_pl, uid, mode):
        from ..cli import build_pipeline, run_investigation
        pl = getattr(tls, "pl", None)
        if pl is None:
            pl = build_pipeline(cfg)                 # ★本 worker 线程独立 pipeline
            tls.pl = pl
            with lock:
                built_pls.append(pl)
        run_investigation(pl, uid, mode=mode)        # 研判 + 组处置(TP→proposed 待处置)
        if cfg.response_mode == "auto":
            from ..response.auto import auto_respond
            res = auto_respond(pl.graph, appliance_client, uid)   # 自动 approve/执行 → 已处置
            if res:
                log(f"  [auto] {uid} 处置 {len(res)} 计划:"
                    f"{[(r['plan_id'][:8], r.get('executed')) for r in res]}")
    return process


def run_poller(cfg, *, mode="recipe", max_alerts=None, once=False, logger=None):
    """建 control pipeline + poller,常驻消化未研判告警。返回统计。"""
    from ..cli import build_pipeline
    from ..response.appliance_client import ApplianceClient
    log = logger or (lambda m: print(m, flush=True))
    control_pl = build_pipeline(cfg)                 # 主循环 fetch/poison 用(只碰 Neo4j);顺带建表
    client = ApplianceClient(cfg.response_url, cfg.response_token)
    built, lock = [], threading.Lock()
    proc = make_processor(cfg, client, built, lock, logger=log)
    poller = Poller(control_pl, interval=cfg.poller_interval, concurrency=cfg.poller_concurrency,
                    batch=cfg.poller_batch, retry_cap=cfg.poller_retry_cap,
                    process_fn=proc, mode=mode, max_alerts=max_alerts, once=once, logger=log)
    poller.install_signal_handlers()
    log(f"# 处置模式={cfg.response_mode}(manual=只生成待处置不执行 / auto=自动执行)  "
        f"appliance={'on' if client.enabled else 'off'}  cascade={'on' if cfg.cascade_enabled else 'off'}")
    try:
        poller.run()
    finally:
        for pl in built + [control_pl]:
            try:
                pl.close()
            except Exception:
                pass
    return poller.stats
