"""端到端研判流程演示:挑一条可疑进程告警,把**每一步**的输入/动作/产出全打印出来。

★ 本脚本**不复制流水线逻辑**。
  最容易犯的错是「为了插日志,把 run_pipeline 的步骤在演示脚本里重写一遍」——
  那样演示的就是**我写的流程**,不是生产实际跑的流程,而且它会随生产改动悄悄漂移,
  演示却一直显示得很好看。所以这里的做法是:**把真实函数包一层,再调用真实入口**
  (`run_investigation`)。打印出来的每一步,都是生产这一刻真正执行的那一步。
  哪天流水线加了一步而这里没包,输出就会少一段 —— 缺了看得见,比错了看不见强。

写入安全:默认**演示模式**,三个写入点(写图台账 / 存回归语料 / 经验沉淀)只打印
「本应写入什么」而不真写,避免为做一次演示污染生产台账与经验库。要真写加 `--write`。

用法:
  python scripts/demo_pipeline.py                    # 自动挑一条可疑进程告警(演示模式)
  python scripts/demo_pipeline.py --alert-uid <uid>
  python scripts/demo_pipeline.py --write            # 真写台账/语料/经验
"""
import argparse
import json
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent import cli as C                                    # noqa: E402
from soc_agent.config import Config                               # noqa: E402

W = 100
_step_no = [0]


def rule(ch="-"):
    print(ch * W)


def step(title, doc):
    _step_no[0] += 1
    print()
    rule("=")
    print(f"【第 {_step_no[0]} 步】{title}")
    print(f"  作用:{doc}")
    rule("=")


def kv(label, value, indent=2):
    print(f"{' ' * indent}{label}:{value}")


def block(label, text, indent=4):
    print(f"{' ' * (indent - 2)}{label}:")
    for ln in (str(text).splitlines() or [""]):
        print(" " * indent + ln)


def brief(v, n=200):
    """压成一行可读文本。超长就**明说截断了多少**,不留一个看不懂的碎片。"""
    if v is None:
        return "(无)"
    s = json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) else str(v)
    s = " ".join(s.split())
    return s if len(s) <= n else f"{s[:n]}…(全长 {len(s)} 字符,此处截断)"


# ---------------------------------------------------------------- 渲染(只读)

def show_alert(a):
    kv("告警ID", a.alert_uid)
    kv("来源/传感器", f"{a.source} / {a.sensor}")
    kv("规则", f"{a.rule_id} —— {a.rule_description}")
    kv("严重度", a.severity)
    kv("发生时间", a.time)
    kv("原始告警", brief(a.raw, 300))


def show_seed(seed):
    if not isinstance(seed, dict):
        kv("seed", brief(seed))
        return
    kv("包含的键", ", ".join(seed.keys()) or "(空)")
    ev = seed.get("event") or {}
    if ev:
        print("    触发事件(这条告警由哪次行为触发):")
        for k in ("event_code", "activity", "event_time", "image", "command_line",
                  "parent_image", "user", "outcome"):
            if ev.get(k) not in (None, ""):
                print(f"      {k:<14}= {brief(ev.get(k), 160)}")
    for k, v in seed.items():
        if k != "event":
            print(f"    {k:<16}= {brief(v, 160)}")


_POLARITY = {"red": "红·攻击迹象", "white": "白·良性证伪", "neutral": "中性·事实"}


def show_forensics(f):
    kv("发现(finding)条数", len(f.findings))
    for i, fd in enumerate(f.findings, 1):
        print(f"    {i:>2}. [{_POLARITY.get(fd.polarity, fd.polarity)}] {fd.finding_id}")
        if fd.attrs:
            print(f"        属性 {brief(fd.attrs, 240)}")
    kv("绑定的实体", brief(f.bindings, 240))
    kv("上下文条目", ", ".join(f.context.keys()) or "(无)")
    kv("已知盲区", brief(f.blind_spots, 300))


def show_report(r):
    kv("经验层决策", r.decision)
    kv("命中良性发现集(白)", len(r.benign_fp_hits or []))
    kv("命中威胁发现集(红)", len(r.threat_fp_hits or []))
    kv("命中威胁规则", len(r.threat_rule_hits or []))
    kv("规则实际开火", len(r.threat_fires or []))
    if r.chosen is not None:
        kv("选中的经验", brief(getattr(r.chosen, "exp_id", r.chosen), 200))
    if getattr(r, "recalled", None):
        kv("召回历史台账", f"{len(r.recalled)} 条(作为已知信息喂给大模型)")


def show_result(res):
    v = res.verdict
    kv("研判路径", res.path)
    kv("使用的 skill", res.skill)
    kv("耗时", f"{res.latency_ms} ms")
    if v is None:
        kv("结论", "(无 verdict)")
    else:
        kv("结论", f"{v.verdict}   倾向={v.lean}   置信={v.confidence}")
        block("摘要", v.summary or "(无)")
        block("依据", v.rationale or "(无)")
        kv("缺失证据", brief(v.missing_evidence, 240))
        kv("研判者", v.agent)
    kv("ATT&CK 技战术", brief(res.techniques, 200))
    if res.dispositions:
        print("    处置建议(仅建议;真执行须人工审批):")
        for d in res.dispositions:
            print(f"      · {brief(d, 220)}")
    else:
        kv("处置建议", "(无 —— 非真阳,或未组装剧本)")


# ---------------------------------------------------------------- 探针

def tap(title, doc, fn, show_out=None):
    """包住**真实函数**:进出各打印一次。不改变它的行为,也不复制它的逻辑。"""
    def wrapped(*a, **kw):
        step(title, doc)
        t0 = time.time()
        out = fn(*a, **kw)
        print(f"  -- 产出(耗时 {int((time.time() - t0) * 1000)} ms)--")
        (show_out or (lambda o: kv("返回", brief(o, 300))))(out)
        return out
    return wrapped


_PICK_BY_SKILL = """
MATCH (a:Alert)-[:HAS_FINDING]->(f:Finding {skill:'suspicious_process'})
RETURN DISTINCT a.alert_uid AS uid, a.rule_description AS descr,
       a.severity AS sev, a.arrival_ms AS t
ORDER BY sev DESC, t DESC LIMIT 10
"""
# 兜底:台账里还没有这条 skill 干过活的记录时,按「触发事件是进程创建」挑
_PICK_BY_ACTIVITY = """
MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)
WHERE coalesce(e.activity = 'process.spawn', false) OR coalesce(e.event_code = '1', false)
RETURN DISTINCT a.alert_uid AS uid, a.rule_description AS descr,
       a.severity AS sev, a.arrival_ms AS t
ORDER BY sev DESC, t DESC LIMIT 10
"""


def pick_alert(pl):
    step("挑一条可疑进程告警",
         "从图里选一条进程类告警作为演示对象。优先选台账里 suspicious_process 这条 skill "
         "真干过活的告警(保证走到要展示的那条取证路径);没有则退而选触发事件是进程创建的。")
    for name, q in (("台账里用过 suspicious_process 的", _PICK_BY_SKILL),
                    ("触发事件是进程创建的", _PICK_BY_ACTIVITY)):
        rows = pl.graph.run_cypher(q)
        print(f"  候选来源:{name} → {len(rows)} 条")
        for i, r in enumerate(rows[:10], 1):
            print(f"    {i:>2}. sev={r.get('sev')}  {r.get('uid')}")
            print(f"        {brief(r.get('descr'), 150)}")
        if rows:
            print(f"  -- 选定:{rows[0]['uid']}(严重度最高、到达最新的一条)")
            return rows[0]["uid"]
    print("  ★图里没有任何进程类告警 —— 无法演示。")
    return None


def install_taps(pl, *, write):
    """把流水线各步包上探针。★包的是真实函数,不是复制品。"""
    pl.graph.seed = tap(
        "取 seed(反查触发事件与相关实体)",
        "拿告警回溯它的触发事件,以及事件牵扯到的进程/账号/主机等实体。"
        "这是后续所有取证的起点,也是知识图谱相对于纯日志的第一处增益。",
        pl.graph.seed, show_out=show_seed)

    pl.router.route = tap(
        "路由:选取证方法论(skill)",
        "由模型判断这条告警该用哪套取证方法论。skill 是「该查什么、怎么判」的活模块,"
        "按四层(身份/主机/网络/应用)组织,每层另有通用兜底。",
        pl.router.route,
        show_out=lambda s: kv("选中 skill", f"{getattr(s, 'name', None)}"
                                            f"   ({brief(getattr(s, 'description', ''), 160)})"))

    C.collect_forensics = tap(
        "确定性取证(recipe)",
        "★这一步不问大模型:用写死的图查询把证据取出来 —— 进程血缘、命令行、落地文件、"
        "外连、账号基线……产出结构化 finding(红=攻击迹象 / 白=良性证伪 / 中性=事实)。"
        "证据确定性,是后面经验能复用、模型不编造的前提。",
        C.collect_forensics, show_out=show_forensics)

    C.consult = tap(
        "经验层比对(第二类经验)",
        "拿刚产出的 finding 集比对已沉淀的行为指纹与威胁规则:"
        "**威胁指纹与威胁规则都命中 → 自动判真阳;纯良性且无威胁 → 自动判误报;"
        "其余落大模型**。这是省算力的关键 —— 见过的情形秒出结论,不必每条都请大模型。",
        C.consult, show_out=show_report)

    for nm, doc in (("_reuse_tp", "命中威胁经验,直接产出真阳结论(不调用大模型)"),
                    ("_reuse_fp", "命中良性经验,直接产出误报结论(不调用大模型)")):
        setattr(C, nm, tap(f"经验复用:{nm}", doc, getattr(C, nm), show_out=show_result))

    C._recall_hit_ledgers = tap(
        "召回命中经验的历史台账",
        "把「这条经验当初是从哪些告警学来的」一并取出,作为**已知信息**喂给大模型,"
        "让它知道历史上同类情形是怎么判的、依据是什么。",
        C._recall_hit_ledgers, show_out=lambda r: kv("召回条数", len(r or [])))

    _orig_choose = C.choose_investigator

    def _choose(*a, **kw):
        step("选研判器",
             "取证已完成,这一步决定由谁下结论:recipe 模式=确定性证据 + 大模型定性"
             "(默认,稳);auto 模式=大模型自主规划查询(对比用)。")
        inv, picked = _orig_choose(*a, **kw)
        kv("模式", picked)
        kv("研判器", type(inv).__name__)
        inv.investigate = tap(
            "大模型研判(深度通道)",
            "把告警原文、取证证据、经验命中情况一并交给大模型,要它给出结论、置信度、"
            "依据与缺失证据。**事实由确定性查询提供,模型只负责定性** —— 它没有机会编造证据。",
            inv.investigate, show_out=show_result)
        return inv, picked

    C.choose_investigator = _choose

    C._compose_dispositions = tap(
        "组装处置剧本",
        "结论为真阳时,由 composer 把靶场开放的**基础处置原语**组装成计划(禁用账号/隔离主机/"
        "杀进程…)。★agent 不碰机器权限,只出计划;计划先过 NEVER-TOUCH 护栏,再经人工审批才执行。",
        C._compose_dispositions,
        show_out=lambda _: kv("处置", "已写入 result.dispositions(见最终结果)"))

    def _stub(title, doc, describe):
        def f(*a, **kw):
            step(title, doc)
            describe(*a, **kw)
            print("  -- 演示模式:**未真正写入**(加 --write 才写)")
        return f

    if write:
        pl.graph.write_result = tap(
            "写图台账(第三类经验)",
            "把本次结论落到图上,每条告警一个 verdict_id,供以后召回、审计与回归。",
            pl.graph.write_result)
        C.snapshot_case = tap(
            "存回归语料",
            "把 finding 快照 + 结论存起来。经验入库前要拿它当考卷,防止学歪。", C.snapshot_case)
        C.sediment = tap(
            "经验沉淀(蒸馏 → 考试 → 入库)",
            "只有走了大模型这条(未命中经验)才沉淀:把本次判断蒸馏成行为指纹/威胁规则,"
            "**先过回归考试**再入库,并记下学它时的覆盖度签名。", C.sediment)
    else:
        pl.graph.write_result = _stub(
            "写图台账(第三类经验)", "把本次结论落到图上,每条告警一个 verdict_id。",
            lambda uid, res, *a, **k: (kv("将写入告警", uid),
                                       kv("结论", getattr(res.verdict, "verdict", None))))
        C.snapshot_case = _stub(
            "存回归语料", "finding 快照 + 结论,用作经验入库前的考卷。",
            lambda store, skill, res, *a, **k: kv("将存入", f"skill={skill}"))
        C.sediment = _stub(
            "经验沉淀(蒸馏 → 考试 → 入库)",
            "只有走大模型这条才沉淀:蒸馏成指纹/规则,先过回归考试再入库。",
            lambda *a, **k: kv("将沉淀", "本次结论 → 行为指纹 / 威胁规则(需先过考试)"))


def main() -> int:
    ap = argparse.ArgumentParser(description="端到端研判流程演示(每步打印输入/动作/产出)")
    ap.add_argument("--alert-uid", help="指定要演示的告警;不给则自动挑一条可疑进程告警")
    ap.add_argument("--mode", choices=["recipe", "auto"], default="recipe")
    ap.add_argument("--write", action="store_true", help="真写台账/语料/经验(默认只打印不写)")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=args.dotenv)
    rule("=")
    print("AI SOC 自动研判 —— 端到端流程演示")
    rule("=")
    kv("知识图谱", cfg.neo4j_uri)
    kv("大模型", f"{cfg.llm_model} @ {cfg.llm_api_base}")
    kv("经验库", f"openGauss {cfg.og_host}:{cfg.og_port}/{cfg.og_database}")
    kv("运行模式", "★演示模式(不写台账、不写经验)" if not args.write else "真实写入")
    kv("研判模式", args.mode)
    print()
    print("  流程总览:告警 → seed 回溯 → 选 skill → 确定性取证 → 经验比对")
    print("            → 命中则秒出结论 / 未命中则大模型研判 → 组处置 → 写台账 → 沉淀经验")

    pl = C.build_pipeline(cfg)
    try:
        uid = args.alert_uid or pick_alert(pl)
        if not uid:
            return 3
        install_taps(pl, write=args.write)

        step("取告警节点", "按 alert_uid 从图里取出这条告警的全部字段(含原始告警 JSON)。")
        node = pl.graph.get_alert(uid)
        if node is None:
            print(f"  ★图里没有 alert_uid={uid}")
            return 2
        from soc_agent.models import Alert
        show_alert(Alert.from_node(node))

        t0 = time.time()
        result, report, picked = C.run_investigation(pl, uid, mode=args.mode)
        total = int((time.time() - t0) * 1000)

        print()
        rule("=")
        print("最终结果")
        rule("=")
        show_result(result)
        kv("经验层决策", report.decision)
        kv("实际走的通道", picked)
        kv("端到端耗时", f"{total} ms")
        print()
        print("  小结:确定性取证保证证据不是编的;经验层让重复情形不必再问大模型;")
        print("        大模型只在没见过的情形上定性;处置只出计划,人审之后才动手。")
        rule("=")
        return 0
    finally:
        pl.close()


if __name__ == "__main__":
    sys.exit(main())
