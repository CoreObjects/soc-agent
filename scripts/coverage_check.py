"""WP9 读侧真机闸门:拿**真图里的 `:Coverage` 事实**跑一遍所有 skill,看谁会报覆盖盲区。

这是**误报侧**的闸门,不是功能演示:
  GOAD 遥测齐全(14 类活动有数据,只缺 log.clear / group.member_add / module.load,
  而没有任何 skill 声明需要这三类)⇒ **一条覆盖盲区都不该冒出来**。
  真冒出来就是误报 —— 而误报的方向恰恰最危险:每条告警都被加一句"我看不到",
  研判会整体偏向"证据不足",还会把这句话喂进 LLM 提示词里带偏结论。

顺带把"入图侧写的 → 读侧读到的"这条往返验通:签名对得上、活动数对得上。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_agent.config import Config                      # noqa: E402
from soc_agent.forensics import Forensics                # noqa: E402
from soc_agent.graph import coverage as C                # noqa: E402
from soc_agent.graph.client import Neo4jGraph            # noqa: E402
from soc_agent.skills_runtime import SkillRegistry       # noqa: E402


def main() -> int:
    cfg = Config.from_env()
    graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        p = C.load(graph)
        print(f"--- ① 读侧看到的覆盖度画像 ---")
        print(f"  known = {p.known};活动 {len(p.facts)} 类"
              f"(有数据 {sum(1 for a in p.facts if p.has(a))} / "
              f"无数据 {sum(1 for a in p.facts if not p.has(a))})")
        if not p.known:
            print("  ❌ 一条 :Coverage 都没读到 —— 先在入图仓跑 `bash scripts/coverage.sh --execute`。")
            print("     ★注意此时读侧的正确行为是**什么都不报**(不知道≠什么都缺),不是报一堆盲区。")
            return 2
        print("  没有数据的活动:" + (", ".join(sorted(a for a in p.facts if not p.has(a))) or "(无)"))
        print()

        print("--- ② 每个 skill 声明需要什么 / 这套部署给不给得起 ---")
        reg = SkillRegistry(cfg.skills_dir)
        blind, ok, undeclared = [], [], []
        for s in sorted(reg.all(), key=lambda x: x.name):
            if not s.needs:
                undeclared.append(s.name)
                continue
            gaps = p.missing(s.needs)
            mark = "★缺" if gaps else "  全有"
            print(f"  {mark} {s.name:<24} needs={','.join(s.needs)}"
                  + (f"   ⇒ 缺 {gaps}" if gaps else ""))
            (blind if gaps else ok).append(s.name)
        if undeclared:
            print(f"  (未声明 needs,本层不管:{', '.join(sorted(undeclared))})")
        print()

        print("--- ③ 真正跑一遍 annotate(与研判流水线同一条代码路径)---")
        fired = []
        for s in reg.all():
            out = C.annotate(Forensics(), s, p)
            metas = [f for f in out.findings
                     if f.finding_id == "_coverage.absent"
                     and (f.attrs or {}).get("scope") == "deployment"]
            if metas:
                fired.append((s.name, [m.attrs.get("need") for m in metas], out.blind_spots))
        for name, needs, bs in fired:
            print(f"  {name}: 报了 {needs}")
            print(f"      blind_spots -> {bs}")
        if not fired:
            print("  (无 skill 报出部署级覆盖盲区)")
        print()

        print("--- ④ 判定 ---")
        # GOAD 的三类缺失(log.clear / group.member_add / module.load)没有任何 skill 声明需要,
        # 所以期望是 0。这条断言的价值在于:它一旦不为 0,要么是 needs 写宽了、要么是采集真的掉了,
        # 两种都必须当场知道,而不是等它去污染研判结论。
        if fired:
            print(f"  ❌ 有 {len(fired)} 个 skill 报了覆盖盲区,而 GOAD 遥测是齐全的 —— 这是**误报**。")
            print("     查两处:① SKILL.md 的 needs 是不是写宽了(声明了 recipe 其实不依赖的遥测);")
            print("             ② 采集是不是真的掉了某一类(看 ① 里没有数据的活动)。")
            return 1
        print("  ✅ 遥测齐全的环境上,一条覆盖盲区都没冒出来(误报侧闸门通过)。")
        print("     ★这只证明了不误报;**能报**由单测里的「只有认证+告警的租户」场景守。")
        return 0
    finally:
        graph.close()


if __name__ == "__main__":
    sys.exit(main())
