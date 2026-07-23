"""server2 浅层 cascade selftest:每类抽样 → **只跑浅层**(不写台账)→ 打印决策 + 量 deferral。

给 Claude 看:浅层对真告警判了啥(终局FP / 升级)、理由;统计升级率(deferral);
浅层判 FP 的列出来眼验召回(该不该被终局判良性)。可反复跑、不污染台账/经验。
用法(经 wrapper): bash scripts/cascade-selftest.sh [每类条数=1] [类数上限=12] [--order recent|severity|first]
IP 一律打码;GOAD 靶场实体名(主机/账号/域)为公开信息保留。
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_agent.cascade.run import run_shallow                                   # noqa: E402
from soc_agent.config import Config                                            # noqa: E402

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_ORDER = {"recent": "coalesce(a.arrival_ms,0) DESC",
          "severity": "coalesce(a.severity,0) DESC, coalesce(a.arrival_ms,0) DESC", "first": None}


def _mask(s):
    return _IPV4.sub(lambda m: f"x.x.x.{m.group(4)}", str(s or ""))


def main():
    argv = sys.argv[1:]
    order = "recent"
    if "--order" in argv:
        i = argv.index("--order"); order = argv[i + 1]; del argv[i:i + 2]
    if order not in _ORDER:
        order = "recent"
    per = int(argv[0]) if len(argv) > 0 else 1
    maxt = int(argv[1]) if len(argv) > 1 else 12

    root = Path(__file__).resolve().parents[1]
    cfg = Config.from_env(dotenv_path=str(root / ".env"))
    from soc_agent.cli import build_pipeline
    pl = build_pipeline(cfg)
    try:
        ob = f"WITH t, a ORDER BY {_ORDER[order]} " if _ORDER[order] else ""
        rows = pl.graph.run_cypher(
            "MATCH (a:Alert) UNWIND coalesce(a.technique_ids,['(none)']) AS t "
            + ob + "WITH t, count(a) AS n, collect(a.alert_uid)[0..$k] AS uids "
            "RETURN t AS tech, n, uids ORDER BY n DESC LIMIT $m", k=per, m=maxt)
        picks = [(r["tech"], r["n"], u) for r in rows for u in r["uids"]]
        print(f"# 浅层 cascade selftest  取样={order}  待判 {len(picks)} 条  "
              f"(只跑浅层、不写台账;IP 打码)\n")

        n_term = n_esc = 0
        terms = []
        for i, (tech, cnt, uid) in enumerate(picks, 1):
            try:
                r = run_shallow(pl, uid)
            except Exception as e:
                print(f"[{i}] {str(tech):16} uid={uid}  !! 异常:{_mask(e)[:200]}")
                continue
            sh, route = r["shallow"], r["route"]
            n_term += route == "terminal_fp"
            n_esc += route != "terminal_fp"
            fd = "+floor" if r["force_deep"] else ""
            print(f"[{i}] {str(tech):16} 该类{cnt:>6}  uid={uid}")
            print(f"     浅层: needs_deep={sh.get('needs_deep')} verdict={sh.get('verdict')} "
                  f"conf={sh.get('confidence')}  → 路由={route}{fd}")
            print(f"     理由: {_mask(sh.get('rationale'))[:240]}")
            if route == "terminal_fp":
                node = pl.graph.get_alert(uid) or {}
                terms.append((uid, tech, node.get("rule_description")))

        tot = n_term + n_esc
        rate = (n_esc / tot * 100) if tot else 0
        print(f"\n# 汇总: 共{tot}  终局FP={n_term}  升级={n_esc}  deferral(升级率)={rate:.0f}%")
        if terms:
            print("\n# 浅层判 FP 的(★眼验召回:这些该不该被浅层终局判良性?有真攻击=漏判):")
            for uid, tech, rd in terms:
                print(f"  - {str(tech):16} {uid}  {_mask(rd)[:120]}")
    finally:
        pl.close()
    print("\n# selftest 完成")


if __name__ == "__main__":
    main()
