"""CLI 入口:研判单条告警(慢通道)。

流程:取 :Alert → seed(反查触发事件→涉及实体,骨架保底)→ 自主研判 → 写回经验层。
真客户端(Neo4j/qwen)在 server2 上跑;流程编排本机可测。
"""
import argparse
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from .composer import Composer
from .composer.plan import PrimitiveStepTemplate, dispositions_from_plan
from .config import Config
from .disposition import policy_from_graph
from .experience.cases import InMemoryCaseStore, snapshot_case
from .experience.consult import consult
from .experience.exam import sediment
from .experience.store import ExperienceCache, InMemoryExperienceStore
from .forensics import Forensics
from .graph import coverage
from .graph.client import Neo4jGraph
from .llm.qwen import QwenClient
from .models import Alert, InvestigationResult, Verdict
from .orchestrator import AgentInvestigator, RecipeInvestigator, SkillRouter
from .response import default_interface
from .schema import graph_schema
from .skills_runtime import SkillRegistry
from .tools import default_toolbox

__all__ = ["investigate_alert", "render_result", "render_trace", "AlertNotFound", "main",
           "Pipeline", "build_pipeline", "run_pipeline", "run_investigation", "collect_forensics"]

_REPO_ROOT = Path(__file__).resolve().parents[1]


class AlertNotFound(Exception):
    pass


def investigate_alert(graph, investigator, alert_uid, skill=None, case_store=None):
    """取告警 → seed → 研判(用预选 skill)→ 写回图 → 存案例快照。返回 InvestigationResult。"""
    node = graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    seed = graph.seed(alert)
    result = investigator.investigate(alert, seed=seed, skill=skill)
    graph.write_result(alert_uid, result)
    if case_store is not None:                       # 存回归考试语料(findings 快照 + verdict)
        snapshot_case(case_store, skill.name if skill else None, result)
    return result


def render_result(result) -> str:
    v = result.verdict
    lines = [
        f"# 研判结果  alert={result.alert_uid}  path={result.path}  skill={result.skill}",
    ]
    if v is not None:
        vline = f"verdict   : {v.verdict}"
        if v.lean:
            vline += f"  [倾向 {v.lean}]"
        lines += [
            f"{vline}  (confidence={v.confidence})",
            f"summary   : {v.summary}",
            f"rationale : {v.rationale}",
        ]
        if v.evidence_refs:
            lines.append(f"evidence  : {v.evidence_refs}")
        if v.missing_evidence:
            lines.append(f"missing   : {v.missing_evidence}")
        lines.append(f"agent     : {v.agent}")
    for d in result.dispositions or []:
        lines.append(f"处置(建议): {d.action} -> {d.target}  risk={d.risk}  status={d.status}")
    if not result.dispositions:
        lines.append("处置(建议): 无")
    return "\n".join(lines)


def render_trace(result) -> str:
    """研判留痕:每步实况(run_cypher 查询/行数、未调工具的文本、0取证打回)。不打行数据。"""
    lines = [f"# 研判留痕({len(result.trace or [])} 步)"]
    for i, step in enumerate(result.trace or [], 1):
        tool = step.get("tool")
        if tool == "run_cypher":
            args = step.get("args") or {}
            res = step.get("result") or {}
            q = " ".join((args.get("query") or "").split())
            if isinstance(res, dict) and "error" in res:
                lines.append(f"[{i}] run_cypher ✗ {res['error']}")
            else:
                rows = res.get("rows") if isinstance(res, dict) else None
                lines.append(f"[{i}] run_cypher → {len(rows or [])} 行")
            lines.append(f"     q: {q[:240]}")
        elif tool == "recipe_step":
            lines.append(f"[{i}] recipe取证「{step.get('step')}」→ {step.get('rows')} 行")
        elif tool == "llm_input":
            lines.append(f"[{i}] ▶ 喂大模型的 user prompt({len(step.get('content') or '')} 字符;全文见 §③)")
        elif tool == "no_tool_call":
            lines.append(f"[{i}] ⚠ 未调工具,只吐文本: {(step.get('content') or '')[:240]}")
        elif tool == "finalize_too_early":
            lines.append(f"[{i}] ⚠ 0取证就想 finalize,打回(第{step.get('nudge')}次)")
        elif tool == "guardrail":
            lines.append(f"[{i}] 🛡 处置护栏 {step.get('decision')}: {step.get('action')} -> "
                         f"{step.get('target')}  因:{step.get('reason')}")
        else:
            lines.append(f"[{i}] {tool}: {step.get('args')}")
    return "\n".join(lines)


def build(config: Config):
    """装配真客户端 + LLM skill 路由 + 两种研判器(recipe 确定性 / auto 自主)。"""
    graph = Neo4jGraph(config.neo4j_uri, config.neo4j_user, config.neo4j_password, config.neo4j_database)
    llm = QwenClient(base_url=config.llm_api_base, model=config.llm_model, api_key=config.llm_api_key,
                     timeout=config.llm_timeout)
    schema = graph_schema()
    registry = SkillRegistry(config.skills_dir)
    policy = policy_from_graph(graph)      # 处置护栏:图里 DC/CA 主机自动进 NEVER-TOUCH(补图第二弹的收现)
    router = SkillRouter(llm=llm, registry=registry, agent_name=config.llm_model)
    agent_inv = AgentInvestigator(
        llm=llm, toolbox=default_toolbox(graph), schema=schema, registry=registry,
        agent_name=config.llm_model, max_iterations=config.max_iterations, policy=policy)
    recipe_inv = RecipeInvestigator(
        llm=llm, graph=graph, schema=schema, registry=registry, agent_name=config.llm_model, policy=policy)
    return graph, router, agent_inv, recipe_inv


def choose_investigator(skill, mode, agent_inv, recipe_inv):
    """选定 skill 后:mode=auto → 自主;否则 skill 有 recipe 走 recipe,没有退自主。"""
    if mode != "auto" and skill is not None and skill.recipe is not None:
        return recipe_inv, "recipe"
    return agent_inv, ("auto" if mode == "auto" else "auto(无 recipe)")


# ============ 流水线:取证 → 经验研判短路 / LLM 研判 → 处置 → 回流沉淀 ============
def collect_forensics(graph, alert, seed, skill):
    """取证阶段:有 recipe 跑出结构化 Forensics;无 recipe(agent skill)→ 空 Forensics(必落 LLM)。

    ★取证之后统一叠一层**部署级覆盖盲区**(WP9):这个 skill 赖以判别的整类遥测
      这套部署压根没有时,明说"我看不到",而不是交出一份空 findings 被读成"没发现异常"。
      放在这里而不是每个 recipe 里,是因为它与 skill 的判别逻辑无关、对所有 skill 一样。
    """
    if skill is not None and skill.recipe is not None:
        fo = Forensics.coerce(skill.recipe(graph, alert, seed))
        return coverage.annotate(fo, skill, coverage.get(graph))
    return Forensics()


@dataclass
class Pipeline:
    """一条流水线所需的全部装配件(build_pipeline 造,run_pipeline 用)。"""
    graph: object
    router: object
    agent_inv: object
    recipe_inv: object
    composer: object
    llm: object
    policy: object
    iface: object
    exp_store: object          # ExperienceCache(包 openGauss 或 InMemory)
    case_store: object         # CaseStore
    agent_name: str
    cascade_enabled: bool = False       # 浅度研判 cascade(openJiuwen)总开关
    llm_base: str = ""                  # 浅层 LLMComponent 接的 OpenAI 兼容端点(=qwen vLLM)
    llm_model: str = ""
    llm_key: str = ""
    llm_timeout: int = 600              # 单次 LLM 超时(秒);同时用来抬 openJiuwen 工作流执行超时(默认才 60,qwen 慢会超)
    payload_corpus: object = None       # 浅层判例语料库(payload 签名反例回归);openGauss 或内存
    shallow_llm: object = None           # 浅层分诊专用 client(小模型 9b);None → cascade 回退用 self.llm

    def close(self):
        self.graph.close()


class _Locked:
    """线程安全代理:方法调用经一把**共享锁**串行 —— 让共享 pipeline 下多 worker 并发安全访问经验/案例库
    (openGauss 单连接、内存 dict 都非线程安全)。经验读写毫秒级、且 LLM 调用不在锁内,锁竞争可忽略,
    因此可安全上高并发(如 64)。非方法属性(如 .store/.conn)原样透传。"""
    __slots__ = ("_t", "_lock")

    def __init__(self, target, lock):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_lock", lock)

    def __getattr__(self, name):
        attr = getattr(self._t, name)
        if callable(attr):
            lock = self._lock

            def _wrapped(*a, **k):
                with lock:
                    return attr(*a, **k)
            return _wrapped
        return attr


def _open_stores(config):
    """经验/案例库:og_enabled 且连得上 → openGauss(缓存包);否则降级内存(经验层≈永远走 LLM)。
    ★三库套 _Locked 共享一把锁(openGauss 三库共用一条连接;并发下必须串行访问)。"""
    lock = threading.RLock()
    if config.og_enabled:
        try:
            from .experience.opengauss import open_stores
            exp, case, pcorpus = open_stores(config)
            return _Locked(ExperienceCache(exp), lock), _Locked(case, lock), _Locked(pcorpus, lock)
        except Exception as e:                      # 连不上/缺 psycopg2 → 降级,不影响慢研判
            print(f"[warn] openGauss 不可用,经验层降级内存(本次不持久):{str(e)[:120]}")
    from .cascade.signature import InMemoryPayloadCaseStore
    return (_Locked(ExperienceCache(InMemoryExperienceStore()), lock),
            _Locked(InMemoryCaseStore(), lock), _Locked(InMemoryPayloadCaseStore(), lock))


def build_pipeline(config: Config) -> "Pipeline":
    """装配完整流水线(在 build 之上加 composer + 经验/案例库)。"""
    graph, router, agent_inv, recipe_inv = build(config)
    iface = default_interface()
    composer = Composer(agent_inv.llm, iface=iface, agent_name=config.llm_model)
    exp_store, case_store, payload_corpus = _open_stores(config)
    # 双模型漏斗:浅层分诊用小模型(SHALLOW_LLM_MODEL,如 9b),升级后深度仍用 llm_model(如 27b)。
    # 未配 / 与深度同模型 → 直接复用深度 client(零行为变化,不多开连接)。
    shallow_model = config.shallow_llm_model or config.llm_model
    shallow_llm = agent_inv.llm if shallow_model == config.llm_model else QwenClient(
        base_url=config.llm_api_base, model=shallow_model,
        api_key=config.llm_api_key, timeout=config.llm_timeout)
    return Pipeline(graph=graph, router=router, agent_inv=agent_inv, recipe_inv=recipe_inv,
                    composer=composer, llm=agent_inv.llm, policy=agent_inv.policy, iface=iface,
                    exp_store=exp_store, case_store=case_store, agent_name=config.llm_model,
                    cascade_enabled=config.cascade_enabled, llm_base=config.llm_api_base,
                    llm_model=config.llm_model, llm_key=config.llm_api_key,
                    llm_timeout=config.llm_timeout, payload_corpus=payload_corpus,
                    shallow_llm=shallow_llm)


def _reuse_tp(pl, alert, forensics, chosen):
    """AUTO_TP:复用威胁经验的剧本模板,按本告警实体重绑成处置。path=A。"""
    templates = [PrimitiveStepTemplate.from_dict(d) for d in (chosen.playbook or [])]
    disps = (dispositions_from_plan(templates, forensics.bindings, pl.policy, pl.iface)
             if templates else [])
    v = Verdict(verdict="true_positive", confidence=0.9,
                summary="经验复用:威胁指纹∧规则双门命中",
                rationale=f"复用威胁经验 {chosen.exp_id[:8]}(指纹+规则双门命中,已过生死线考试)",
                agent=pl.agent_name)
    return InvestigationResult(alert_uid=alert.alert_uid, path="A", verdict=v, dispositions=disps,
                               skill=chosen.skill, findings=list(forensics.findings),
                               bindings=dict(forensics.bindings),
                               reuse_verdict_id=chosen.origin_verdict_id)   # 复用→CONCLUDED 指向源判例 Verdict


def _reuse_fp(pl, alert, forensics, chosen):
    """AUTO_FP:命中误报业务指纹、无威胁信号 → 判 FP、无处置。path=A。"""
    v = Verdict(verdict="false_positive", confidence=0.9,
                summary="经验复用:误报业务指纹命中(无威胁信号)",
                rationale=f"复用误报指纹 {chosen.exp_id[:8]}(命中已知良性业务模式,无任何威胁信号)",
                agent=pl.agent_name)
    return InvestigationResult(alert_uid=alert.alert_uid, path="A", verdict=v, dispositions=[],
                               skill=chosen.skill, findings=list(forensics.findings),
                               bindings=dict(forensics.bindings),
                               reuse_verdict_id=chosen.origin_verdict_id)   # 复用→CONCLUDED 指向源判例 Verdict


def _compose_dispositions(pl, result, forensics, skill, seed):
    """LLM 判 TP 后:Composer 组处置原语成剧本模板 → 按实体重绑成 dispositions;剧本存 result 供沉淀。"""
    templates = pl.composer.compose(result, {"bindings": forensics.bindings}, skill, seed)
    if templates:
        result.dispositions = dispositions_from_plan(templates, forensics.bindings, pl.policy, pl.iface)
        result.playbook = [t.to_dict() for t in templates]


def _recall_hit_ledgers(graph, report):
    """FALLTHROUGH:对命中经验的来源告警(origin_case_id=VID),从图台账捞回原始上下文喂 LLM。

    命中的指纹/规则只是"召回",大模型要独立研判 → 得看到"命中的这条经验当初是从哪条告警蒸的、
    那次判成啥、为什么、怎么处置的"。台账永久保存,按 VID 永久可捞。捞不到/无该方法 → 优雅降级。
    """
    recall = getattr(graph, "recall_ledger", None)
    if recall is None:
        return {}
    uids, out = [], {}
    for e in (report.benign_fp_hits + report.threat_fp_hits + report.threat_rule_hits):
        u = getattr(e, "origin_case_id", None)
        if u and u not in uids:
            uids.append(u)
    for u in uids:
        try:
            led = recall(u)
        except Exception:
            led = None
        if led:
            out[u] = led
    return out


def run_pipeline(pl, alert_uid, mode="recipe"):
    """跑一条告警的完整流水线。返回 (result, report, picked)。"""
    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    seed = pl.graph.seed(alert)
    skill = pl.router.route(alert, seed)                                        # ★LLM 选 skill
    forensics = collect_forensics(pl.graph, alert, seed, skill)                # ★取证
    report = consult(skill.name if skill else None, forensics.findings, pl.exp_store,
                     coverage_sig=coverage.get(pl.graph).signature)          # ★经验比对
    if report.decision == "AUTO_TP":
        result, picked = _reuse_tp(pl, alert, forensics, report.chosen), "经验复用(AUTO_TP)"
        pl.exp_store.bump_hit(report.chosen.exp_id)
    elif report.decision == "AUTO_FP":
        result, picked = _reuse_fp(pl, alert, forensics, report.chosen), "经验复用(AUTO_FP)"
        pl.exp_store.bump_hit(report.chosen.exp_id)
    else:                                                                       # FALLTHROUGH → LLM 研判
        report.recalled = _recall_hit_ledgers(pl.graph, report)                # 命中经验来源告警的图台账 → 喂 LLM
        inv, picked = choose_investigator(skill, mode, pl.agent_inv, pl.recipe_inv)
        result = inv.investigate(alert, seed=seed, skill=skill, forensics=forensics, match_report=report)
        if result.verdict and result.verdict.verdict == "true_positive":
            _compose_dispositions(pl, result, forensics, skill, seed)          # ★处置:组剧本
    pl.graph.write_result(alert_uid, result)                                   # 写台账(第三类)
    if pl.case_store is not None:
        snapshot_case(pl.case_store, skill.name if skill else None, result)    # 存回归语料
    if report.decision == "FALLTHROUGH":                                       # ★回流:蒸馏→考试→入库
        # ★带上学它时的覆盖度签名(WP9)。缓存过的画像,不额外查图。
        sediment(pl.llm, skill, result, pl.exp_store, pl.case_store, agent_name=pl.agent_name,
                 coverage_sig=coverage.get(pl.graph).signature)
    return result, report, picked


def run_investigation(pl, alert_uid, mode="recipe"):
    """研判一条:cascade 开→浅度分诊(QwenClient)判不动才深度;关→现状深度 run_pipeline。
    返回 (result, report, picked)。浅层已弃 openJiuwen(见 docs/openjiuwen-踩坑总结.md),全 Python。"""
    if getattr(pl, "cascade_enabled", False):
        from .cascade.run import run_cascade
        return run_cascade(pl, alert_uid, mode)
    return run_pipeline(pl, alert_uid, mode)


def main(argv=None):
    ap = argparse.ArgumentParser(description="研判单条告警(慢通道)")
    ap.add_argument("alert_uid", help="要研判的 :Alert 的 alert_uid")
    ap.add_argument("--dotenv", default=str(_REPO_ROOT / ".env"), help=".env 路径(端点/口令)")
    ap.add_argument("--trace", action="store_true", help="打印研判留痕")
    ap.add_argument("--mode", choices=["recipe", "auto"], default="recipe",
                    help="recipe=确定性取证+LLM定性(默认,稳);auto=LLM 自主规划查询(对比用)")
    args = ap.parse_args(argv)

    config = Config.from_env(dotenv_path=args.dotenv)
    pl = build_pipeline(config)
    try:
        result, report, picked = run_investigation(pl, args.alert_uid, mode=args.mode)
        print(f"[skill] {result.skill or '(none)'}  [决策] {report.decision}  [模式] {picked}")
    finally:
        pl.close()
    if args.trace:
        print(render_trace(result))
        print()
    print(render_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
