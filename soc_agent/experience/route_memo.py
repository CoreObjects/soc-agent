"""路由记忆层:把"这条告警该用哪个 skill"这个被重复问了 21 万遍的问题记住。

实测(2026-08-18):一条告警的 LLM 开销里,**路由占深度模型调用的 77%** ——
`SkillRouter.route` 每条告警都要问一次 27b,而同类告警的答案几乎恒定。
它是全流水线唯一"该被记住却没被记住"的一步:经验层键在 findings 上,findings 来自取证,
取证要 skill,skill 来自路由 —— 路由是这条链的第一环,却每次重算。

**这不是硬编码映射**:`rule_id/technique → skill` 由 LLM 在运行时学、存库,换环境清表重学。
可移植性靠"没有这些字段也能工作"(回退 LLM),不靠"有也不用"。见 [[soc-signature-portability-redline]]。

## 键:宁细勿粗

缓存键的取舍是**不对称**的:
- 键太细 → 命中率低 → 多花几次 LLM → **成本问题**
- 键太粗 → 不同性质的告警撞进同一条记忆 → **复用错答案 → 正确性问题**

所以永远先用最细的键。`technique_ids` 在靶场实测只有 17 个不同值却盖了 21 万条告警,
说明它**很粗**:`T1059` 完全可能按解释器分叉(PowerShell→A / Python→B),
今天恰好一对一是数据的偶然、不是结构保证。故 `rule_id` 优先。

## 状态机:第一次 LLM 的答案不许直接被复用

```
miss             → LLM route → 存 candidate                       [不复用]
同键再来一条     → LLM route → 与 candidate 一致?
                    ├ 一致 且 **来自不同告警** → active            [此后才复用]
                    ├ 一致 但同一条告警      → 不算数
                    └ 不一致 → 覆盖 candidate,disagree+1
                                └ disagree ≥ 3 → ambiguous
active 命中      → 零 LLM
稀疏复核不一致   → override+1;≥2 → archived
archived         → 允许重学(→candidate);重学 3 轮仍震荡 → unstable
ambiguous/unstable → 终态,恒走 LLM
```

★**两次问同一个模型不是统计独立的**。candidate 门挡的是**采样抖动**(模型自己没把握、
答案会飘)——这正是低信号路由决策的主要失败模式。它挡不住系统性错判:
若模型对某类告警一贯选错,两次也会一贯选错。那属于"router 语义是否正确",是另一个问题
(要拿人工标注的 skill 真值集回归 router),不在本层射程内。

★**为什么必须能认输(ambiguous)**:早期设计写的是"不一致就覆盖 candidate、重新计数",
对一个真·歧义键(A/B 交替)这条规则**永远不收敛** —— 无限翻烙饼、每条告警照烧一次 LLM,
既不变好也不报警,是个静默死循环。

`ambiguous` 与 `unstable` 都是"别缓存",但**病因不同、修法不同**,所以分开记:
- `ambiguous`:出生就没收敛 ⇒ **键太粗、少一个区分字段** ⇒ 改 `route_key()`(代码改动)
- `unstable` :曾稳定后反复漂移 ⇒ **环境在变**(模型/skill registry/recipe/数据源)⇒ 查什么变了

★**风险**:路由错了**不会报错** —— recipe 错 ⇒ findings 错 ⇒ 指纹键在错的 findings 上
⇒ 整条链一起烂而各道闸门全绿。三道独立防线:candidate 出生闸门、稀疏复核、
`scripts/replay-reuse.sh --compare`(自动复用率不得下降)。

本模块只依赖标准库,便于离线单测;openGauss 实现见 `opengauss.py`。
"""
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

__all__ = ["RouteMemo", "RouteMemoStore", "InMemoryRouteMemoStore", "route_key",
           "advance", "should_verify", "seed_ambiguous",
           "MEMO_STATUSES", "TERMINAL_STATUSES", "VERIFY_AT",
           "CONFIRM_REQUIRED", "DISAGREE_CAP", "OVERRIDE_CAP", "RELEARN_CAP"]

MEMO_STATUSES = {"candidate", "active", "archived", "ambiguous", "unstable"}
TERMINAL_STATUSES = ("ambiguous", "unstable")      # 恒走 LLM、不再学

CONFIRM_REQUIRED = 2      # 几条**不同**告警给出同一答案才转正
DISAGREE_CAP = 3          # candidate 阶段分歧几次 → 判这个键天生有歧义
OVERRIDE_CAP = 2          # active 期复核不一致几次 → 判漂移、归档
RELEARN_CAP = 3           # 归档后重学几轮仍震荡 → unstable

# 稀疏复核点(按 hit_count)。★出生闸门已由 candidate 承担,这里只探**漂移**
# (模型升级 / skill registry 变更 / recipe 改写 / 数据源换了),所以可以很稀:
# 一条记忆命中 1 万次只复核 3 次。
VERIFY_AT = (100, 1000, 10000)


@dataclass
class RouteMemo:
    """一条路由记忆。`skill=None` 表示 LLM 明确答了"none"(与"还没学过"不同,后者是查不到行)。"""
    route_key: str
    skill: Optional[str] = None
    status: str = "candidate"
    confirm_count: int = 1            # 不同告警给出同一答案的次数(≥CONFIRM_REQUIRED → active)
    disagree_count: int = 0           # candidate 阶段的分歧次数(≥DISAGREE_CAP → ambiguous)
    hit_count: int = 0
    verify_count: int = 0
    override_count: int = 0
    relearn_count: int = 0
    origin_alert_uid: Optional[str] = None   # 建立本 candidate 的告警;确认必须来自 ≠ 它的告警
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    memo_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self):
        if self.status not in MEMO_STATUSES:
            raise ValueError(f"未知 status:{self.status!r}(允许 {sorted(MEMO_STATUSES)})")

    @property
    def reusable(self) -> bool:
        """能不能零 LLM 直接复用。★只有 active —— candidate 明确**不复用**。"""
        return self.status == "active"

    def to_dict(self) -> dict:
        return {"memo_id": self.memo_id, "route_key": self.route_key, "skill": self.skill,
                "status": self.status, "confirm_count": self.confirm_count,
                "disagree_count": self.disagree_count, "hit_count": self.hit_count,
                "verify_count": self.verify_count, "override_count": self.override_count,
                "relearn_count": self.relearn_count, "origin_alert_uid": self.origin_alert_uid,
                "created_by": self.created_by, "created_at": self.created_at,
                "updated_at": self.updated_at}

    @classmethod
    def from_dict(cls, d: dict) -> "RouteMemo":
        return cls(route_key=d["route_key"], skill=d.get("skill"),
                   status=d.get("status", "candidate"),
                   confirm_count=int(d.get("confirm_count") or 1),
                   disagree_count=int(d.get("disagree_count") or 0),
                   hit_count=int(d.get("hit_count") or 0),
                   verify_count=int(d.get("verify_count") or 0),
                   override_count=int(d.get("override_count") or 0),
                   relearn_count=int(d.get("relearn_count") or 0),
                   origin_alert_uid=d.get("origin_alert_uid"), created_by=d.get("created_by"),
                   created_at=d.get("created_at"), updated_at=d.get("updated_at"),
                   memo_id=d.get("memo_id") or uuid4().hex)


# ============ 键 ============
def _norm(v) -> str:
    """归一:去空白 + casefold。None/空 → ""(调用方据此判断"这一级键有没有")。"""
    if v is None:
        return ""
    return str(v).strip().casefold()


def _slot(v) -> str:
    """键里的一个槽位:空值占位成 "-",保证键的段数恒定、不会因缺字段而串位。"""
    return _norm(v) or "-"


def _event_code(seed) -> str:
    """触发事件的码。★优先原生 `event_code`(细),缺失退 `activity`(粗),再缺记 "-"。

    两者都是 graph_model 声明的通用字段(见 Event.props),用它们做键**不是**厂商硬编码 ——
    键的**值**由运行时学出来,换环境清表重学。
    """
    if not isinstance(seed, dict):
        return "-"
    ev = seed.get("event")
    if not isinstance(ev, dict):
        return "-"
    return _slot(ev.get("event_code") or ev.get("activity"))


def route_key(alert, seed=None) -> Optional[str]:
    """告警 → 路由记忆的键。**宁细勿粗**(见模块文档),返回 None 表示这条不建记忆、每次走 LLM。

    阶梯:
      1. 有 `rule_id`      → `r|source|sensor|rule_id`
      2. 有 `technique_ids` → `t|source|sensor|技战术(排序)|event_code`
      3. 都没有            → None

    ★第 1 级不带 event_code:`rule_id` 已经足够细,再加只会平白降低命中率。
    ★第 2 级带 event_code:`SkillRouter.route` 的 prompt 里喂了 `seed["event"]`,
      键不含它就是**键不全** —— 同技战术不同底层事件可能该走不同 skill。
    ★technique_ids 必须排序:否则同一组技战术会因顺序不同裂成多条记忆。
    """
    src, sen = _slot(getattr(alert, "source", None)), _slot(getattr(alert, "sensor", None))
    rid = _norm(getattr(alert, "rule_id", None))
    if rid:
        return f"r|{src}|{sen}|{rid}"
    techs = sorted({_norm(t) for t in (getattr(alert, "technique_ids", None) or []) if _norm(t)})
    if techs:
        return f"t|{src}|{sen}|{','.join(techs)}|{_event_code(seed)}"
    return None


# ============ 状态机(纯逻辑,与 I/O 解耦) ============
def should_verify(hit_count: int) -> bool:
    """要不要在这次命中上顺带做一次稀疏复核。传**自增之后**的 hit_count。"""
    return hit_count in VERIFY_AT


def advance(memo: Optional[RouteMemo], route_key_: str, observed_skill: Optional[str],
            alert_uid: Optional[str], *, created_by=None, now=None):
    """观察到一次新的 LLM 路由结果 → 推进状态机。返回 `(memo, action)`。

    `memo=None` = 这个键还没有记忆。`action` 是给日志/统计看的字符串,不参与控制流。
    **本函数不做 I/O**:调用方拿返回的 memo 去 upsert。
    """
    if memo is None:
        m = RouteMemo(route_key=route_key_, skill=observed_skill, status="candidate",
                      confirm_count=1, origin_alert_uid=alert_uid,
                      created_by=created_by, created_at=now, updated_at=now)
        return m, "created"

    memo.updated_at = now

    if memo.status in TERMINAL_STATUSES:            # 终态:不再学,调用方也不该走到这
        return memo, "terminal"

    if memo.status == "candidate":
        # ★确认必须来自**不同的告警**:poller 有 retry、DLQ 有 replay、Kafka 有重复消费,
        #   同一条告警跑两遍是常态。不判这一下,"两次一致"可能只是同一个样本被看了两遍,
        #   candidate 门等于形同虚设。
        #   (此判据对 CONFIRM_REQUIRED=2 是精确的;若日后调大,需要改存一个已确认 uid 集合。)
        if alert_uid is not None and alert_uid == memo.origin_alert_uid:
            return memo, "same_alert_ignored"
        if observed_skill == memo.skill:
            memo.confirm_count += 1
            if memo.confirm_count >= CONFIRM_REQUIRED:
                memo.status = "active"
                return memo, "activated"
            return memo, "confirmed"
        # 分歧:改押新答案重新计数,但分歧本身要累计 —— 累够了就承认这个键天生有歧义
        memo.disagree_count += 1
        memo.skill = observed_skill
        memo.origin_alert_uid = alert_uid
        memo.confirm_count = 1
        if memo.disagree_count >= DISAGREE_CAP:
            memo.status = "ambiguous"
            return memo, "ambiguous"
        return memo, "disagree"

    if memo.status == "active":                     # 只有稀疏复核会带着 LLM 结果走到这
        memo.verify_count += 1
        if observed_skill == memo.skill:
            return memo, "verified"
        memo.override_count += 1
        if memo.override_count >= OVERRIDE_CAP:
            memo.status = "archived"
            return memo, "archived"
        return memo, "override"

    # archived:允许重学 —— 模型升级/registry 变更/recipe 改写都会让一个键
    # 从"不可缓存"变回"可缓存",永久判死刑等于永远多花钱。但重学要封顶:
    # 反复 archive→重学→再 archive 的震荡,本身是在说"这个键少了一个区分字段"。
    if memo.relearn_count >= RELEARN_CAP:
        memo.status = "unstable"
        return memo, "unstable"
    memo.relearn_count += 1
    memo.status = "candidate"
    memo.skill = observed_skill
    memo.confirm_count = 1
    memo.disagree_count = 0
    memo.override_count = 0
    memo.origin_alert_uid = alert_uid
    return memo, "relearn"


def seed_ambiguous(store, route_keys, *, created_by=None, now=None) -> int:
    """把 Phase 0 在历史数据上定性为 `ambiguous` 的键预写进表。返回实际写入条数。

    ★**只播负例,绝不播正例。** 把历史上唯一的键直接写成 `active`,等于拿历史 router 的答案
      跳过 candidate 门 —— 而那正是 candidate 门要防的东西。播种只能**收紧**、不能放宽。
    ★已是终态的不动;candidate/active 会被收紧成 ambiguous(这是收紧,允许)。
    """
    n = 0
    for k in route_keys:
        if not k:
            continue
        cur = store.lookup(k)
        if cur is not None and cur.status in TERMINAL_STATUSES:
            continue
        if cur is None:
            cur = RouteMemo(route_key=k, skill=None, created_by=created_by,
                            created_at=now, confirm_count=0)
        cur.status = "ambiguous"
        cur.updated_at = now
        store.upsert(cur)
        n += 1
    return n


# ============ 库 ============
class RouteMemoStore:
    """路由记忆库接口(openGauss 实现同签名替换)。"""

    def lookup(self, route_key_: str) -> Optional[RouteMemo]:
        raise NotImplementedError

    def upsert(self, memo: RouteMemo) -> None:
        raise NotImplementedError

    def bump_hit(self, route_key_: str) -> int:
        """命中计数 +1,返回**自增之后**的值(调用方拿它判要不要稀疏复核)。"""
        raise NotImplementedError

    def all(self) -> list:
        raise NotImplementedError


class InMemoryRouteMemoStore(RouteMemoStore):
    """进程内路由记忆库(测试 / 未配 openGauss 时降级 —— 降级即"路由永远走 LLM",零 regression)。"""

    def __init__(self):
        self._by_key: dict = {}

    def lookup(self, route_key_: str) -> Optional[RouteMemo]:
        return self._by_key.get(route_key_)

    def upsert(self, memo: RouteMemo) -> None:
        # ★保留库里已有的 hit_count,与 openGauss 实现对齐(那边的 UPDATE 也不写这一列):
        #   命中计数只由 bump_hit 自增,upsert 拿的是 bump 之前读出来的对象,
        #   照写回去会把期间的并发命中抹掉。两个实现在这点上必须一样,
        #   否则单测量的行为和线上不是同一个。
        cur = self._by_key.get(memo.route_key)
        if cur is not None and cur is not memo:
            memo.hit_count = cur.hit_count
        self._by_key[memo.route_key] = memo

    def bump_hit(self, route_key_: str) -> int:
        m = self._by_key.get(route_key_)
        if m is None:
            return 0
        m.hit_count += 1
        return m.hit_count

    def all(self) -> list:
        return list(self._by_key.values())
