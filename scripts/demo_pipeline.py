"""端到端研判流程演示:把**每一步**的输入/动作/产出完整打印出来,一个字不省。

★ 三条硬规矩(都是为了让人看了敢信):

  1. **不复制流水线逻辑**。最容易犯的错是「为了插日志,把 run_pipeline 在演示脚本里
     重写一遍」—— 那样演示的是我写的流程,不是生产跑的流程,而且会随生产改动悄悄漂移,
     演示却一直显示得很好看。这里的做法是**把真实函数包一层,再调用真实入口**
     (`run_investigation`):打印出来的每一步,都是生产这一刻真正执行的那一步。
     哪天流水线加了一步而这里没包,输出会少一段 —— 缺了看得见,比错了看不见强。

  2. **不截断**。有多长打多长:告警原文、seed、取证上下文、**送进大模型的完整提示词**、
     **大模型的完整返回**、蒸馏出的经验全文。截断过的东西没法核对,看起来就像编的。

  3. **不省步骤**。大模型的每一次调用(选 skill / 研判 / 蒸馏)都单独打印提示词与返回,
     由 `QwenClient.chat` 这一个入口统一捕获 —— 漏不掉任何一次。

写入安全:默认不写生产(图台账 / 回归语料 / 经验库),只打印「本应写入什么」。
  但**蒸馏和考试是真跑的**,只是落到一个用完即弃的临时经验库 —— 领导能看到
  「这次研判学到了什么」,而生产经验库不被一次演示污染。要真写加 `--write`。

默认**不抄任何近路**:三处短路(签名库复用 / 浅层直接终局 / 经验层复用)都照常执行并把
  **真实结论原样打印**,随后显式声明「演示强制继续」,把这条告警当成没见过的走完整条漏斗。
  只强制不标注的话,看的人会以为生产每条都请大模型 —— 那会把成本预期带偏。
  要看生产实际的抄近路行为:`--reuse`。

默认**打开浅层**(`--cascade on`):浅层由 `SOC_CASCADE_ENABLED` 控制、生产可能是关的,
  但它是三级漏斗的第一级,汇报要看完整流程就得展示。头部会同时打印
  「本次用的」与「.env 里配的」,不一致时明确标注是演示口径。

用法:
  python scripts/demo_pipeline.py                    # 完整三级漏斗(默认)
  python scripts/demo_pipeline.py --reuse            # 允许各级短路(生产实际行为)
  python scripts/demo_pipeline.py --cascade env      # 浅层按 .env 实际配置
  python scripts/demo_pipeline.py --alert-uid <uid>
  python scripts/demo_pipeline.py --write            # 真写台账/语料/经验库
"""
import argparse
import dataclasses
import json
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from soc_agent import cli as C                                        # noqa: E402
from soc_agent.cascade import run as CAS                              # noqa: E402
from soc_agent.config import Config                                   # noqa: E402
from soc_agent.experience.store import InMemoryExperienceStore        # noqa: E402
from soc_agent.llm.qwen import QwenClient                             # noqa: E402

W = 100
_step_no = [0]
_llm_calls = [0]


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


def full(v):
    """完整文本化。★不截断 —— 截断过的东西没法核对,看起来就像编的。"""
    if v is None:
        return "(无)"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, indent=2, default=str)
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return json.dumps(dataclasses.asdict(v), ensure_ascii=False, indent=2, default=str)
    return str(v)


def block(label, value, indent=4):
    print(f"{' ' * (indent - 2)}{label}:")
    for ln in full(value).splitlines() or [""]:
        print(" " * indent + ln)


# ---------------------------------------------------------------- 渲染(只读、完整)

def show_alert(a):
    kv("告警ID", a.alert_uid)
    kv("来源/传感器", f"{a.source} / {a.sensor}")
    kv("规则", f"{a.rule_id} —— {a.rule_description}")
    kv("严重度", a.severity)
    kv("发生时间", a.time)
    kv("ATT&CK", a.technique_ids)
    kv("原始告警引用", a.raw_ref)
    block("原始告警全文(入图时无损保存的那一份)", a.raw)


def show_seed(seed):
    if not isinstance(seed, dict):
        block("seed", seed)
        return
    kv("包含的键", ", ".join(seed.keys()) or "(空)")
    for k, v in seed.items():
        block(f"seed[{k}]", v)


_POLARITY = {"red": "红·攻击迹象", "white": "白·良性证伪", "neutral": "中性·事实"}


def show_forensics(f):
    kv("发现(finding)条数", len(f.findings))
    for i, fd in enumerate(f.findings, 1):
        print(f"    {i:>2}. [{_POLARITY.get(fd.polarity, fd.polarity)}] {fd.finding_id}")
        block("属性", fd.attrs, indent=8)
        if fd.evidence_ref:
            print(f"        证据引用:{fd.evidence_ref}")
    block("绑定的实体(bindings)", f.bindings)
    print("    上下文(context)—— 取证查到的原始证据,逐条完整列出:")
    for k, v in (f.context or {}).items():
        block(f"context[{k}]", v, indent=8)
    block("已知盲区(blind_spots)", f.blind_spots)


def show_report(r):
    kv("经验层决策", r.decision)
    block("命中的良性发现集(白)", r.benign_fp_hits)
    block("命中的威胁发现集(红)", r.threat_fp_hits)
    block("命中的威胁规则", r.threat_rule_hits)
    block("规则实际开火", r.threat_fires)
    block("选中的经验", getattr(r.chosen, "__dict__", r.chosen))
    block("召回的历史台账(作为已知信息喂给大模型)", getattr(r, "recalled", None))


def show_result(res):
    v = res.verdict
    kv("研判路径", res.path)
    kv("使用的 skill", res.skill)
    kv("耗时", f"{res.latency_ms} ms")
    if v is None:
        kv("结论", "(无 verdict)")
    else:
        kv("结论", f"{v.verdict}   倾向={v.lean}   置信={v.confidence}")
        block("摘要", v.summary)
        block("依据", v.rationale)
        block("证据引用", v.evidence_refs)
        block("缺失证据", v.missing_evidence)
        kv("研判者", v.agent)
        kv("verdict_id", v.verdict_id)
    block("ATT&CK 技战术", res.techniques)
    block("处置建议(仅建议;真执行须人工审批)", res.dispositions)
    block("剧本(playbook)", res.playbook)
    block("时间线", res.timeline)
    block("研判留痕(trace)", res.trace)


# ---------------------------------------------------------------- 探针

def tap(title, doc, fn, show_out=None):
    """包住**真实函数**:进出各打印一次。不改变行为,也不复制逻辑。"""
    def wrapped(*a, **kw):
        step(title, doc)
        t0 = time.time()
        out = fn(*a, **kw)
        print(f"  -- 产出(耗时 {int((time.time() - t0) * 1000)} ms)--")
        (show_out or (lambda o: block("返回", o)))(out)
        return out
    return wrapped


def install_llm_tap():
    """★捕获**每一次**大模型调用的完整提示词与完整返回。

    包在 `QwenClient.chat` 这一个入口上 —— 选 skill、深度研判、经验蒸馏全都走它,
    所以漏不掉任何一次。提示词一字不改、一字不省地打出来:
    别人要核对「模型到底看到了什么、我们有没有把答案偷偷塞给它」,只能靠这个。
    """
    orig = QwenClient.chat

    def chat(self, messages, tools=None, tool_choice=None):
        _llm_calls[0] += 1
        n = _llm_calls[0]
        print()
        rule(">")
        print(f">>> 送入大模型的完整提示词(第 {n} 次调用)  model={self.model}")
        rule(">")
        for i, m in enumerate(messages, 1):
            print(f"  --- message[{i}]  role={m.get('role')} ---")
            for ln in str(m.get("content", "")).splitlines() or [""]:
                print("    " + ln)
        if tools:
            block("可用工具(function calling)", tools, indent=4)
            kv("tool_choice", tool_choice, indent=2)
        t0 = time.time()
        resp = orig(self, messages, tools=tools, tool_choice=tool_choice)
        ms = int((time.time() - t0) * 1000)
        rule("<")
        print(f"<<< 大模型完整返回(第 {n} 次调用,耗时 {ms} ms)")
        rule("<")
        block("返回", getattr(resp, "__dict__", resp), indent=4)
        print()
        return resp

    QwenClient.chat = chat


_PICK_BY_SKILL = """
MATCH (a:Alert)-[:HAS_FINDING]->(f:Finding {skill:'suspicious_process'})
RETURN DISTINCT a.alert_uid AS uid, a.rule_description AS descr,
       a.severity AS sev, a.arrival_ms AS t
ORDER BY sev DESC, t DESC LIMIT 10
"""
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
        for i, r in enumerate(rows, 1):
            print(f"    {i:>2}. sev={r.get('sev')}  {r.get('uid')}")
            print(f"        {r.get('descr')}")
        if rows:
            print(f"  -- 选定:{rows[0]['uid']}(严重度最高、到达最新的一条)")
            return rows[0]["uid"]
    print("  ★图里没有任何进程类告警 —— 无法演示。")
    return None


def install_taps(pl, *, write, allow_reuse):
    """把流水线各步包上探针。★包的是真实函数,不是复制品。"""
    pl.graph.seed = tap(
        "取 seed(反查触发事件与相关实体)",
        "拿告警回溯它的触发事件,以及事件牵扯到的进程/账号/主机等实体。"
        "这是后续所有取证的起点,也是知识图谱相对于纯日志的第一处增益。",
        pl.graph.seed, show_out=show_seed)

    pl.router.route = tap(
        "路由:选取证方法论(skill)",
        "由大模型判断这条告警该用哪套取证方法论(提示词与返回见下方完整记录)。"
        "skill 是「该查什么、怎么判」的活模块,按四层(身份/主机/网络/应用)组织,每层另有通用兜底。",
        pl.router.route,
        show_out=lambda s: (kv("选中 skill", getattr(s, "name", None)),
                            block("该 skill 的方法论描述", getattr(s, "description", None))))

    C.collect_forensics = tap(
        "确定性取证(recipe)",
        "★这一步不问大模型:用写死的图查询把证据取出来 —— 进程血缘、命令行、落地文件、"
        "外连、账号基线……产出结构化 finding(红=攻击迹象 / 白=良性证伪 / 中性=事实)。"
        "证据确定性,是后面经验能复用、模型不编造的前提。",
        C.collect_forensics, show_out=show_forensics)

    _orig_consult = C.consult

    def _consult(*a, **kw):
        step("经验层比对(第二类经验)",
             "拿刚产出的 finding 集比对已沉淀的行为指纹与威胁规则:"
             "**威胁指纹与威胁规则都命中 → 自动判真阳;纯良性且无威胁 → 自动判误报;"
             "其余落大模型**。这是省算力的关键 —— 见过的情形秒出结论,不必每条都请大模型。")
        t0 = time.time()
        rep = _orig_consult(*a, **kw)
        print(f"  -- 产出(耗时 {int((time.time() - t0) * 1000)} ms)--")
        show_report(rep)
        if not allow_reuse and rep.decision != "FALLTHROUGH":
            print()
            print("  " + "!" * 60)
            print(f"  ★演示强制:经验层的真实结论是 {rep.decision}(生产会到此为止、秒出结论)。")
            print("    本次演示要展示完整流程,因此**把这条告警当成没见过的**:")
            print("    清空命中项、改判 FALLTHROUGH,继续走深度研判。")
            print("    ——这是演示口径,不是生产行为;生产的省算力能力恰恰体现在上面那个真实结论里。")
            print("  " + "!" * 60)
            rep.decision = "FALLTHROUGH"
            rep.chosen = None
            rep.benign_fp_hits = []
            rep.threat_fp_hits = []
            rep.threat_rule_hits = []
            rep.threat_fires = []
        return rep

    C.consult = _consult

    for nm, doc in (("_reuse_tp", "命中威胁经验,直接产出真阳结论(不调用大模型)"),
                    ("_reuse_fp", "命中良性经验,直接产出误报结论(不调用大模型)")):
        setattr(C, nm, tap(f"经验复用:{nm}", doc, getattr(C, nm), show_out=show_result))

    C._recall_hit_ledgers = tap(
        "召回命中经验的历史台账",
        "把「这条经验当初是从哪些告警学来的」一并取出,作为**已知信息**喂给大模型。"
        "(本次按「陌生告警」演示,已清空命中项,所以这里应当为空 —— 这正是它该有的表现。)",
        C._recall_hit_ledgers, show_out=lambda r: block("召回结果", r))

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
            "依据与缺失证据。**事实由确定性查询提供,模型只负责定性** —— 完整提示词见下方,"
            "可以逐字核对我们有没有把答案偷偷塞给它。",
            inv.investigate, show_out=show_result)
        return inv, picked

    C.choose_investigator = _choose

    C._compose_dispositions = tap(
        "组装处置剧本",
        "结论为真阳时,由 composer 把靶场开放的**基础处置原语**组装成计划(禁用账号/隔离主机/"
        "杀进程…)。★agent 不碰机器权限,只出计划;计划先过 NEVER-TOUCH 护栏,再经人工审批才执行。",
        C._compose_dispositions,
        show_out=lambda _: kv("处置", "已写入 result.dispositions(见最终结果)"))

    # ---- 浅层(cascade 第一级):签名库 → 硬底线 → 浅层 LLM 分诊 ----
    _orig_sig = CAS.sig_consult

    def _sig(*a, **kw):
        step("① 签名库前置(零大模型)",
             "三级漏斗的第一级:拿告警自身的 payload 特征去查已沉淀的签名库。"
             "命中误报签名 → 直接复用结论、**一次大模型都不调**;命中攻击签名 → 不短路、强制升级。"
             "这一级存在的意义就是省算力:重复的噪声不该每条都惊动模型。")
        hit = _orig_sig(*a, **kw)
        block("签名库命中", getattr(hit, "__dict__", hit))
        if hit is not None and not allow_reuse:
            print("  ★演示强制:命中了也不复用,当作没见过,继续往下走(演示口径,非生产行为)。")
            return None
        return hit

    CAS.sig_consult = _sig

    _orig_floor = CAS.force_deep

    def _floor(*a, **kw):
        step("② 硬底线 floor(确定性强制升级)",
             "在浅层判断之前的确定性兜底:某些「漏了就是灾难」的类型可以在这里无条件升级到深度。"
             "★当前是**空底线**(恒 False)—— 2026-07-23 有意退成这样:原本按高危技战术前缀强制升级,"
             "但那些(Kerberoast/DCSync/ADCS)恰恰是浅层凭签名就能直判的,强制升级反而挡住了这条快路。"
             "升不升全交浅层 LLM 判断,钩子保留以便日后按需补。")
        v = _orig_floor(*a, **kw)
        kv("是否强制升级", v)
        return v

    CAS.force_deep = _floor

    _orig_shallow = CAS.shallow_triage

    def _shallow(llm, alert):
        step("③ 浅层 LLM 分诊(轻量,不取证、不查图)",
             "只把告警自身(含原文)喂给模型,让它判两件事:needs_deep(要不要深度取证)与 verdict。"
             "★决策口径是**不对称**的:只有判成 false_positive 才允许在此终局;"
             "判 true_positive 或 suspicious 一律升级 —— 宁可多花算力,不可漏报。"
             "完整提示词与返回见下方。")
        out = _orig_shallow(llm, alert)
        print("  -- 产出 --")
        block("浅层分诊结果", out)
        if not allow_reuse and not out.get("needs_deep"):
            print("  ★演示强制:浅层本可在此终局,但演示要展示完整漏斗,故改判需要升级"
                  "(演示口径,非生产行为)。")
            out = dict(out, needs_deep=True)
        kv("→ 路由", "升级到深度研判" if out.get("needs_deep") else "浅层终局")
        return out

    CAS.shallow_triage = _shallow

    def _no_sig_learn(*a, **kw):
        step("浅层终局后的签名蒸馏", "浅层判定误报终局时,从 payload 蒸出签名入库,下次同类零大模型。")
        print("  -- 演示模式:**未写入签名库**(加 --write 才写)")

    if not write:
        CAS._sig_learn = _no_sig_learn

    # ---- 写入点 ----
    def _stub(title, doc, describe):
        def f(*a, **kw):
            step(title, doc)
            describe(*a, **kw)
            print("  -- 演示模式:**未真正写入**(加 --write 才写)")
        return f

    _orig_sediment = C.sediment

    def _sediment_demo(llm, skill, result, exp_store, case_store, **kw):
        step("经验沉淀(蒸馏 → 考试 → 入库)",
             "只有走了大模型这条(未命中经验)才沉淀:把本次判断**蒸馏**成行为指纹/威胁规则,"
             "拿历史语料**考试**,过关才入库,并记下学它时的覆盖度签名。"
             "★本次蒸馏与考试是**真跑的**(提示词与返回见下方),只是入库落到一个用完即弃的"
             "临时库 —— 生产经验库不被一次演示污染。")
        throwaway = InMemoryExperienceStore()
        t0 = time.time()
        exp, report = _orig_sediment(llm, skill, result, throwaway, case_store, **kw)
        print(f"  -- 产出(耗时 {int((time.time() - t0) * 1000)} ms)--")
        block("蒸馏出的经验(本次学到的东西)", getattr(exp, "__dict__", exp))
        block("考试报告(拿历史语料回归,防止学歪)", getattr(report, "__dict__", report))
        block("临时库里现有的经验条目", [getattr(e, "__dict__", e) for e in throwaway.all()])
        print("  -- 演示模式:以上**未写入生产经验库**(加 --write 才写)")
        return exp, report

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
            "蒸馏成行为指纹/威胁规则,先过回归考试再入库,并记下学它时的覆盖度签名。",
            C.sediment, show_out=lambda o: block("(经验, 考试报告)", o))
    else:
        pl.graph.write_result = _stub(
            "写图台账(第三类经验)", "把本次结论落到图上,每条告警一个 verdict_id。",
            lambda uid, res, *a, **k: (kv("将写入告警", uid), block("将写入的结论", res.verdict)))
        C.snapshot_case = _stub(
            "存回归语料", "finding 快照 + 结论,用作经验入库前的考卷。",
            lambda store, skill, res, *a, **k: (kv("将存入 skill", skill),
                                                block("将存入的 findings", res.findings)))
        C.sediment = _sediment_demo


def main() -> int:
    ap = argparse.ArgumentParser(description="端到端研判流程演示(每步完整打印,不截断)")
    ap.add_argument("--alert-uid", help="指定要演示的告警;不给则自动挑一条可疑进程告警")
    ap.add_argument("--mode", choices=["recipe", "auto"], default="recipe")
    ap.add_argument("--reuse", action="store_true",
                    help="允许经验复用(生产实际行为);默认关闭=把告警当没见过的,完整走深度通道")
    ap.add_argument("--write", action="store_true", help="真写台账/语料/经验库(默认只打印不写)")
    ap.add_argument("--cascade", choices=["on", "off", "env"], default="on",
                    help="三级漏斗的浅层(签名库+浅层LLM分诊)。on=演示完整漏斗(默认);"
                         "env=按 .env 里的 SOC_CASCADE_ENABLED;off=只走深度")
    ap.add_argument("--dotenv", default=os.path.join(_ROOT, ".env"))
    args = ap.parse_args()

    cfg = Config.from_env(dotenv_path=args.dotenv)
    rule("=")
    print("AI SOC 自动研判 —— 端到端流程演示(完整记录,不截断)")
    rule("=")
    kv("知识图谱", cfg.neo4j_uri)
    kv("大模型", f"{cfg.llm_model} @ {cfg.llm_api_base}")
    kv("经验库", f"openGauss {cfg.og_host}:{cfg.og_port}/{cfg.og_database}")
    kv("写入", "★演示模式(不写图台账、不写经验库;蒸馏与考试真跑,落临时库)"
       if not args.write else "真实写入")
    kv("经验复用", "★关闭 —— 把这条告警当成没见过的,完整走深度通道"
       if not args.reuse else "开启(生产实际行为)")
    kv("研判模式", args.mode)
    env_cascade = bool(getattr(cfg, "cascade_enabled", False))
    use_cascade = env_cascade if args.cascade == "env" else (args.cascade == "on")
    kv("浅层(cascade)", f"本次={'开' if use_cascade else '关'}   "
                        f".env 里的 SOC_CASCADE_ENABLED={'开' if env_cascade else '关'}"
       + ("   ★两者不一致:本次为展示完整漏斗而打开(演示口径)" if use_cascade != env_cascade else ""))
    print()
    print("  流程总览(三级漏斗):")
    print("    第一级 浅层  告警 → ①签名库前置(零大模型) → ②硬底线 floor → ③浅层LLM分诊")
    print("                  └ 只有判成误报才在此终局;判攻击/可疑一律升级(宁可多花算力,不可漏报)")
    print("    第二级 深度  seed 回溯 → 选 skill(大模型) → 确定性取证 → 经验层比对")
    print("                  └ 经验命中则秒出结论;未命中才请大模型")
    print("    第三级 收尾  召回历史台账 → 大模型研判 → 组处置剧本 → 写台账 → 蒸馏+考试沉淀经验")
    print("  说明:大模型每一次调用的**完整提示词与完整返回**都会原样打印,可逐字核对。")

    install_llm_tap()
    pl = C.build_pipeline(cfg)
    pl.cascade_enabled = use_cascade      # ★run_investigation 就是据这个字段二选一
    try:
        uid = args.alert_uid or pick_alert(pl)
        if not uid:
            return 3
        install_taps(pl, write=args.write, allow_reuse=args.reuse)

        step("取告警节点", "按 alert_uid 从图里取出这条告警的全部字段(含入图时无损保存的原始告警)。")
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
        kv("经验层决策(演示口径)", report.decision)
        kv("实际走的通道", picked)
        kv("大模型调用次数", _llm_calls[0])
        kv("端到端耗时", f"{total} ms")
        print()
        print("  小结:证据由确定性图查询取得,模型只负责定性 —— 它没有机会编造事实;")
        print("        经验层让见过的情形不必再问模型(本次为演示完整流程而刻意绕开);")
        print("        处置只出计划,过护栏、经人审之后才动手;")
        print("        本次研判的结论会被蒸馏成新经验,过考试后入库 —— 这就是自进化那一环。")
        rule("=")
        return 0
    finally:
        pl.close()


if __name__ == "__main__":
    sys.exit(main())
