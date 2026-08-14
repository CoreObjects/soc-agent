"""安全代理名单声明式化的**真机等价闸门**(WP10)。★只读。

计划把这一项标成 WP10 里风险最高的:`security_agent` 驱动 white 极性 finding
(能把结论直接翻成 FP),而且还是处置层 NEVER-TOUCH 硬拒的判据。
所以验收写的是「在 GOAD 租户上必须与现有 8 条正则**逐条等价**」。

★为什么单测不够、非得上真机:
  单测里的语料是我**自己想出来的**字符串。真正会翻结论的是图里**实际存在**的那些
  image 值 —— 带盘符、带版本号目录、带 8.3 短名、大小写混杂、Linux 路径混在一起。
  拿自造语料证等价,证的是"我想到的情况没问题",不是"现网没问题"。
  这跟本项目反复栽的那类跟头是同一个:**别从自己构造的视图推断现网**。

做法:把图里所有 distinct 的进程 image / 源 image / 写入者 image 全捞出来,
      每一条同时喂给「冻结的旧实现」和「新的声明式实现」,逐条比**返回的名字串**
      (不是比命中与否 —— 名字进指纹 canon,改名即静默作废)。
"""
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent import sec_agents                    # noqa: E402
from soc_agent.config import Config                 # noqa: E402
from soc_agent.graph.client import Neo4jGraph       # noqa: E402

# 改动前那 8 条硬编码正则的**原样副本** —— 基准,不许跟着 BUILTIN 一起改
FROZEN = [
    (re.compile(r"wazuh-agent|ossec-agent", re.I), "Wazuh/OSSEC HIDS 代理"),
    (re.compile(r"MsMpEng\.exe|NisSrv\.exe|MpDefenderCoreService", re.I), "Microsoft Defender"),
    (re.compile(r"Sysmon6?4?\.exe", re.I), "Sysmon 传感器"),
    (re.compile(r"winlogbeat|filebeat|elastic-agent", re.I), "Elastic/Beats 采集器"),
    (re.compile(r"MsSense\.exe|SenseIR\.exe", re.I), "Microsoft Defender for Endpoint"),
    (re.compile(r"CSFalcon", re.I), "CrowdStrike Falcon"),
    (re.compile(r"xagt\.exe", re.I), "Trellix/FireEye"),
    (re.compile(r"SentinelAgent|SentinelServiceHost", re.I), "SentinelOne"),
]


def frozen_impl(image):
    if not image:
        return None
    for rx, name in FROZEN:
        if rx.search(image):
            return name
    return None


# ★不写死属性名。写死一次就错了一次:`src_image`/`writer_image`/`parent_image` 全是
#   **查询里的别名**,图上其实只有 `Process.image`。而查一个不存在的属性 Neo4j 不报错、
#   只静默返回零行 ⇒ 语料悄悄变小、等价照样"通过"。所以从图的 schema 里**发现**。
_FALLBACK = [("Process", "image")]


def discover(g):
    """列出图里所有名字含 image 的 (标签, 属性)。失败则退回已知的 Process.image 并说明。"""
    try:
        rows = g.run_cypher(
            "CALL db.schema.nodeTypeProperties() YIELD nodeLabels, propertyName "
            "WHERE toLower(propertyName) CONTAINS 'image' "
            "RETURN DISTINCT nodeLabels AS labels, propertyName AS prop")
    except Exception as e:                                  # noqa: BLE001
        print(f"  ⚠ db.schema.nodeTypeProperties() 不可用({type(e).__name__}: {e})"
              f" —— 退回已知的 {_FALLBACK}")
        return list(_FALLBACK), True
    pairs = []
    for r in rows:
        for lab in (r.get("labels") or []):
            pairs.append((lab, r.get("prop")))
    if not pairs:
        print(f"  ⚠ schema 里没发现任何含 image 的属性 —— 退回 {_FALLBACK}")
        return list(_FALLBACK), True
    return sorted(set(pairs)), False


def main() -> int:
    cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
    if not cfg.neo4j_uri:
        print("❌ NEO4J_URI 为空。")
        return 2
    print(f"图: {cfg.neo4j_uri}  库={cfg.neo4j_database}")

    reg = sec_agents.effective()
    print(reg.describe())
    print()

    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        print("--- 从图 schema 发现的 image 类属性(不写死,免得静默少捞)---")
        pairs, degraded = discover(g)
        for lab, prop in pairs:
            print(f"  {lab}.{prop}")
        print()

        seen, per_src = set(), []
        for lab, prop in pairs:
            q = (f"MATCH (n:`{lab}`) WHERE n.`{prop}` IS NOT NULL "
                 f"RETURN DISTINCT n.`{prop}` AS s")
            try:
                rows = g.run_cypher(q)
            except Exception as e:                          # noqa: BLE001
                print(f"  ⚠ {lab}.{prop}: 查询失败({type(e).__name__}: {e})—— 该来源未纳入比对")
                per_src.append((f"{lab}.{prop}", None))
                continue
            vals = {r.get("s") for r in rows if r.get("s")}
            per_src.append((f"{lab}.{prop}", len(vals)))
            seen |= vals
        print("--- 从图里捞到的 distinct image 值 ---")
        for label, n in per_src:
            print(f"  {label}: {'查询失败' if n is None else n}")
        if degraded:
            print("  (★属性发现降级过,上面这份来源清单可能不全)")
        print(f"  合计去重后: {len(seen)}")
        if not seen:
            # ★零语料的"全部一致"什么都不证明 —— 明确判证据不足,不给假绿灯
            print("\n⚠ 图里一条 image 都没捞到 —— 零语料的等价是空的,不作数。")
            return 3
        print()

        mismatch, hits = [], {}
        for s in sorted(seen):
            old, new = frozen_impl(s), reg.match(s)
            if old != new:
                mismatch.append((s, old, new))
            if old:
                hits.setdefault(old, []).append(s)

        print("--- 命中分布(旧实现;用来确认语料里**确实有**代理进程,否则等价是空跑)---")
        if not hits:
            print("  (一条都没命中)★这份语料对本闸门没有区分力:全都不命中时,"
                  "把名单删空也会「等价」。")
        for name, ss in sorted(hits.items()):
            print(f"  {name}: {len(ss)} 条,例:{ss[0]}")
        print()

        if mismatch:
            print(f"❌ 不等价:{len(mismatch)} 条 image 上新旧结论不同 —— 这会直接改研判结论:")
            for s, old, new in mismatch[:30]:
                print(f"   {s}\n     旧: {old!r}   新: {new!r}")
            return 1
        print(f"✅ 逐条等价:{len(seen)} 条真实 image 上,新旧实现返回的**名字串**完全一致。")
        if not hits:
            return 3
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
