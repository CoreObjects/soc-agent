"""python -m soc_agent.runtime —— 启动告警轮询研判(存量按时间序消化 + 常驻轮询)。

用法:
  python -m soc_agent.runtime                 # 常驻:消化存量 → 轮询新告警
  python -m soc_agent.runtime --once          # 消化完存量即退(不常驻)
  python -m soc_agent.runtime --max 20        # 处理满 20 条就停(小样本验证)
处置模式(manual/auto)与并发/间隔由 .env(SOC_RESPONSE_MODE / POLLER_*)控制。
"""
import argparse
import sys

from ..config import Config
from .service import run_poller


def main(argv=None):
    ap = argparse.ArgumentParser(prog="soc-poller", description="告警轮询研判")
    ap.add_argument("--dotenv", default=".env")
    ap.add_argument("--mode", choices=["recipe", "auto"], default="recipe",
                    help="研判模式:recipe(确定性取证+定性,稳)/ auto(LLM 自主规划)")
    ap.add_argument("--max", type=int, default=None, help="处理满这么多条就停(小样本验证)")
    ap.add_argument("--once", action="store_true", help="消化完存量即退,不常驻轮询")
    args = ap.parse_args(argv)

    cfg = Config.from_env(dotenv_path=args.dotenv)
    stats = run_poller(cfg, mode=args.mode, max_alerts=args.max, once=args.once)
    print(f"# 汇总:已判 {stats['done']}  失败 {stats['failed']}  跳过(毒告警)={stats['skipped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
