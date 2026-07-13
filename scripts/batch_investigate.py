"""server2 批量自测:每类技战术各抽 1 条告警 → 打印【原始告警 + 触发上下文 + 研判全过程】。

给 Claude 判断用:一次把各类告警的路由(选哪个 skill)、取证证据、判定&处置都摊开。
默认**不写回图**(自测可反复跑,不往经验层堆重复 Verdict);要落库用 run_investigation.sh。

用法(经 wrapper 自动建 venv):bash scripts/selftest.sh [每类条数=1] [技术类数上限=10]
直接:  .venv/bin/python scripts/batch_investigate.py [per_tech] [max_tech] [--mode recipe|auto] [--write]
输出:IP 一律打码(只留末段供关联);GOAD 靶场实体名(主机/账号/域)为公开信息予以保留。
"""
import json
import re
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_agent.config import Config                                              # noqa: E402
from soc_agent.models import Alert                                              # noqa: E402

_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _mask_ips(s):
    """把 IPv4 前三段打码,保留末段(仍能区分/关联不同源)——避免真实内网地址进公开仓。"""
    return _IPV4.sub(lambda m: f"x.x.x.{m.group(4)}", s or "")


def _dump(obj):
    return _mask_ips(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def main():
    argv = sys.argv[1:]
    mode = "recipe"
    write = False
    if "--write" in argv:
        write = True
        argv.remove("--write")
    if "--mode" in argv:
        i = argv.index("--mode")
        mode = argv[i + 1]
        del argv[i:i + 2]
    per_tech = int(argv[0]) if len(argv) > 0 else 1
    max_tech = int(argv[1]) if len(argv) > 1 else 10

    root = Path(__file__).resolve().parents[1]
    cfg = Config.from_env(dotenv_path=str(root / ".env"))

    from soc_agent.cli import build, choose_investigator, render_result, render_trace
    graph, router, agent_inv, recipe_inv = build(cfg)
    try:
        # 每类技战术抽 per_tech 个样例 uid,按该类告警量降序取前 max_tech 类
        rows = graph.run_cypher(
            "MATCH (a:Alert) UNWIND coalesce(a.technique_ids,['(none)']) AS t "
            "WITH t, count(*) AS n, collect(a.alert_uid)[0..$k] AS uids "
            "RETURN t AS tech, n, uids ORDER BY n DESC LIMIT $m",
            k=per_tech, m=max_tech)
        picks = [(r["tech"], r["n"], u) for r in rows for u in r["uids"]]

        print(f"# 批量自测  技战术 {len(rows)} 类 / 待研判 {len(picks)} 条  "
              f"模式={mode}  写回图={'是' if write else '否(自测不落库)'}  (IP 已打码)\n")
        print("待研判清单:")
        for tech, n, u in picks:
            print(f"  {str(tech):18} 该类共{n:>7}  uid={u}")
        print()

        for idx, (tech, n, uid) in enumerate(picks, 1):
            print("=" * 76)
            print(f"## [{idx}/{len(picks)}] technique={tech}   该类共 {n} 条   uid={uid}")
            print("=" * 76)
            node = graph.get_alert(uid)
            if node is None:
                print("!! 图里无此 uid,跳过\n")
                continue
            alert = Alert.from_node(node)
            seed = graph.seed(alert)

            print("### ① 原始告警节点(:Alert)")
            print(_dump(node))
            print("\n### ② 触发上下文(seed:触发事件 / 主语 / 宾语 / 次要实体)")
            print(_dump(seed))

            skill = router.route(alert)                                # ★LLM 按 description 选 skill
            inv, picked = choose_investigator(skill, mode, agent_inv, recipe_inv)
            print(f"\n### ③ 研判   [skill] {skill.name if skill else '(none)'}   [模式] {picked}")
            try:
                result = inv.investigate(alert, seed=seed, skill=skill)
                if write:
                    graph.write_result(uid, result)
                print(_mask_ips(render_trace(result)))
                print()
                print(_mask_ips(render_result(result)))
            except Exception:
                print("!! 研判异常:\n" + _mask_ips(traceback.format_exc()))
            print()
    finally:
        graph.close()
    print("# 批量自测完成")


if __name__ == "__main__":
    main()
