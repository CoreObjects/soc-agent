"""poller 生产入口:一套**共享 pipeline** → 研判 + auto 处置 → Poller.run。

★并发安全(可上高并发,如 64):共享一套 pipeline —— graph(neo4j 驱动线程安全)、llm(QwenClient/httpx
并发安全)、router/investigators/composer 无状态;经验/案例库套 `_Locked`(cli._open_stores)一把锁串行
(读写毫秒级、LLM 不在锁内,竞争可忽略)。不再每 worker 建一套(那样 N 并发=N 个 neo4j 驱动+N 个 openGauss
连接,会撞连接上限)。manual:只研判(组处置=proposed 待处置);auto:再自动 approve/执行。
"""
from .poller import Poller

__all__ = ["run_poller", "make_processor"]


def make_processor(cfg, appliance_client, logger=None, mode_getter=None):
    """poller 的 per-alert 处理器(所有 worker 共用同一个 pipeline pl)。

    mode_getter():返回当前 response_mode(manual/auto)。默认回退静态 cfg.response_mode;
    run_poller 注入一个读"按批刷新的持久 :Config"的 getter,让 UI 切换运行时生效(见 run_poller)。
    """
    log = logger or (lambda m: print(m, flush=True))
    get_mode = mode_getter or (lambda: cfg.response_mode)

    def process(pl, uid, mode):
        from ..cli import run_investigation
        run_investigation(pl, uid, mode=mode)        # 研判 + 组处置(TP→proposed 待处置)
        if get_mode() == "auto":
            from ..response.auto import auto_respond
            res = auto_respond(pl.graph, appliance_client, uid)   # 自动 approve/执行 → 已处置
            if res:
                log(f"  [auto] {uid} 处置 {len(res)} 计划:"
                    f"{[(r['plan_id'][:8], r.get('executed')) for r in res]}")
    return process


def run_poller(cfg, *, mode="recipe", max_alerts=None, once=False, logger=None):
    """建一套共享 pipeline + poller,常驻消化未研判告警。返回统计。"""
    from ..cli import build_pipeline
    from ..response.appliance_client import ApplianceClient
    from ..response.auto import read_response_mode
    log = logger or (lambda m: print(m, flush=True))
    pl = build_pipeline(cfg)                         # ★一套共享 pipeline(线程安全:graph/llm + 加锁的经验库)
    client = ApplianceClient(cfg.response_url, cfg.response_token)
    # ★收紧2:response_mode 按批刷(读一次 :Config 缓存整批),不每条读 —— 64 并发下省往返。
    mode_state = {"mode": cfg.response_mode}

    def _refresh_mode():
        mode_state["mode"] = read_response_mode(pl.graph, cfg.response_mode)

    proc = make_processor(cfg, client, logger=log, mode_getter=lambda: mode_state["mode"])
    poller = Poller(pl, interval=cfg.poller_interval, concurrency=cfg.poller_concurrency,
                    batch=cfg.poller_batch, retry_cap=cfg.poller_retry_cap,
                    process_fn=proc, mode=mode, max_alerts=max_alerts, once=once, logger=log,
                    before_batch=_refresh_mode)
    poller.install_signal_handlers()
    log(f"# 处置模式={cfg.response_mode}(manual=只生成待处置不执行 / auto=自动执行)  并发={cfg.poller_concurrency}  "
        f"appliance={'on' if client.enabled else 'off'}  cascade={'on' if cfg.cascade_enabled else 'off'}")
    try:
        poller.run()
    finally:
        pl.close()
    return poller.stats
