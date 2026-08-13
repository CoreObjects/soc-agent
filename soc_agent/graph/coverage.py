"""WP9 读侧:照着**测出来的覆盖度**说话,而不是照着手写散文。

问题
----
`Forensics.blind_spots` 今天是每个 recipe 各写一句散文,里面混着两种性质完全不同的东西:

  · **模型盲区** —— 本体里压根没这个概念(进程 EXE 签名、IP 信誉、票据实际用途…)。
    它对**每个客户都成立**,是方法论的一部分,就该写死在 recipe 里。
  · **覆盖盲区** —— 本体建模了,但**这套部署的数据里没有**(没装 Sysmon ⇒ 没有进程遥测)。
    它**每个客户都不同**,写死就等于对着新客户念一句既不准也不会变的话。

第二类只能测。`soc-graph-ingest` 的 `runner coverage` 负责测并写成 `:Coverage` 事实,
这里负责读它、并把结论落到 findings 与 blind_spots 上。

★最重要的一条安全性质:**"不知道" ≠ "什么都缺"**
--------------------------------------------------
图里一条 `:Coverage` 都没有时(还没测过、或刚 wipe 过),profile 是 `known=False`,
`missing()` 恒返回空 —— 什么都不改变。

如果反过来把"查不到"当成"全都缺",每条 recipe 都会开始喊自己瞎了,
研判结论会**整体**偏向"证据不足",而根因只是没人跑过测量。
这类"缺省值把系统推向错误方向"的坑,比崩溃难查得多。
"""
import time
from dataclasses import dataclass, field

from soc_agent.forensics import Finding

from .pivot import _SUBJECT_TO_PIVOT

# ---------------------------------------------------------------------------
# 遥测需求词表
#
# ★名字必须是**通用遥测类别**,不是厂商/产品名 —— 与指纹守的是同一条可移植性红线
#   (见 [[soc-signature-portability-redline]]):写 "sysmon_telemetry" 就等于把厂商
#   钉进方法论,换个 EDR 即废。这些名字是**拿去跟客户要数据的措辞**。
#
# ★怎么来的:**从活动类机械派生**(`file.write` → `file_write_telemetry`),
#   而不是另立一套手维护的平行词表 —— 平行词表必然漂,而漂了不会报错,
#   只会让某个 need 永远匹配不上、于是永远不报盲区(又一次静默失败)。
#   现有 recipe 传的 `file_write_telemetry` / `network_flow_telemetry` 正好就是这个规则。
#   只有**真正可互换**的才额外给一个分组别名。
# ---------------------------------------------------------------------------
try:                                   # 活动词表的权威在入图仓;拿不到就退到本地兜底表
    from ingest.activity_map import ACTIVITIES as _ACTIVITIES
except Exception:                      # soc-agent 独立部署时并不装 soc-graph-ingest
    _ACTIVITIES = {
        "auth.logon": "认证", "auth.ticket_request": "认证", "auth.explicit_creds": "认证",
        "directory.access": "认证", "cert.request": "认证", "group.member_add": "认证",
        "process.spawn": "进程", "process.access": "进程", "module.load": "进程",
        "script.exec": "进程", "file.write": "文件变更", "registry.set": "文件变更",
        "network.flow": "流量", "dns.query": "DNS", "http.request": "访问",
        "log.clear": "审计",
    }


def _need_name(activity: str) -> str:
    return activity.replace(".", "_") + "_telemetry"


NEED_ACTIVITIES = {_need_name(a): frozenset({a}) for a in _ACTIVITIES}
# 真正可互换的分组(任一有数据就算这类能力在):
NEED_ACTIVITIES.update({
    "process_telemetry": frozenset({"process.spawn", "process.access"}),
    "auth_telemetry": frozenset({"auth.logon", "auth.ticket_request", "auth.explicit_creds"}),
})

_LOAD = ("MATCH (c:Coverage) RETURN c.activity AS activity, c.status AS status, "
         "c.family AS family, c.events AS events, c.subjects AS subjects, "
         "c.sources AS sources, c.stale_days AS stale_days, c.arrival_on AS arrival_on, "
         "c.coverage_sig AS coverage_sig")

_TTL_SEC = 900          # 覆盖度是慢变量(测量本身是定期跑的),15 分钟足够新
_cache = {"at": 0.0, "profile": None}


@dataclass(frozen=True)
class CoverageProfile:
    """这套部署"实际有什么数据"的画像。`known=False` = 还没测过,**不代表什么都没有**。"""

    facts: dict = field(default_factory=dict)      # activity -> 属性 dict
    known: bool = False

    # ---------------------------------------------------------------- 基本问询
    @property
    def signature(self) -> str:
        """覆盖度签名 —— **读**入图侧算好写在节点上的值,**不在这里重算**。

        ★它冗余地写在每个 `:Coverage` 节点上(同一个值),看着浪费,但换来的是这边不必
          照着同一套规则再实现一遍哈希。两份"逐字一致、不许漂"的实现是本项目反复吃亏的形状。
        空串 = 还没测过,或入图侧版本旧(没写这个属性)—— 两种都意味着"不知道",别当成一个真签名。
        """
        for f in self.facts.values():
            sig = f.get("coverage_sig")
            if sig:
                return str(sig)
        return ""

    def has(self, activity) -> bool:
        f = self.facts.get(activity)
        return bool(f and f.get("status") == "present")

    def stale_days(self, activity):
        """-1 或 None = 不可知(到达戳两处都没有)。★不可知不等于新鲜,调用方别当 0 用。"""
        f = self.facts.get(activity) or {}
        return f.get("stale_days")

    def subjects(self, activity) -> set:
        """形如 {"BY:Process", "FROM:IPAddress"} —— 事件挂到哪些实体上。"""
        return set((self.facts.get(activity) or {}).get("subjects") or [])

    def pivot_kinds(self, activity) -> set:
        """这类活动上**解得出来**的 pivot 种类 —— WP7 与 WP9 的接缝。

        它回答的是"这套部署能不能给出进程主语",而 `resolve_pivot` 回答的是
        "**这一条**告警能不能"。前者是能力,后者是个例;两者都需要。
        """
        out = set()
        for tag in self.subjects(activity):
            _, _, label = tag.partition(":")
            hit = _SUBJECT_TO_PIVOT.get(label)
            if hit:
                out.add(hit[0])
        return out

    # ---------------------------------------------------------------- 缺口判定
    def missing(self, needs) -> list:
        """声明需要的遥测里,这套部署**确实一类都没有**的那些。

        ★没测过就一律返回空 —— 见模块开头"不知道 ≠ 什么都缺"。
        ★一个 need 下**任一**活动有数据就算有:进程遥测有 spawn 没 access,
          能力是残缺而不是没有,那属于 recipe 自己按轴报缺(WP7 做的事),不在这一层一刀切。
        """
        if not self.known:
            return []
        out = []
        for need in needs or ():
            acts = NEED_ACTIVITIES.get(need)
            if not acts:                       # 未知的 need 名:不猜,交给测试去卡
                continue
            if not any(self.has(a) for a in acts):
                out.append(need)
        return out

    def describe(self, need) -> str:
        acts = sorted(NEED_ACTIVITIES.get(need) or ())
        return f"{need}(实测无数据:{'/'.join(acts) or '?'})"


def load(graph) -> CoverageProfile:
    """从图里读覆盖度事实。读不到/图不可用 → `known=False` 的空画像(而不是抛)。"""
    try:
        rows = graph.run_cypher(_LOAD)
    except Exception:
        return CoverageProfile()               # 图挂了不该把研判也带崩
    facts = {r["activity"]: dict(r) for r in (rows or []) if r.get("activity")}
    return CoverageProfile(facts=facts, known=bool(facts))


def get(graph, *, ttl: float = _TTL_SEC) -> CoverageProfile:
    """带 TTL 的进程内缓存 —— 覆盖度是慢变量,不该每条告警查一次图。"""
    now = time.time()
    if _cache["profile"] is not None and now - _cache["at"] < ttl:
        return _cache["profile"]
    p = load(graph)
    _cache.update(at=now, profile=p)
    return p


def reset_cache():
    _cache.update(at=0.0, profile=None)


def annotate(forensics, skill, profile):
    """把**部署级**覆盖盲区落到取证结果上:加 `_coverage.absent` finding + 补一句 blind_spots。

    与 WP7 那条 `_coverage.absent` 的分工(靠 attrs 里的 `scope` 区分):
      · `scope="alert"` —— **这一条**告警解不出 pivot(个例,WP7 在 recipe 里产出);
      · `scope="deployment"` —— **整类遥测**这套部署压根没有(能力边界,这里产出)。
    两者都是元 finding(`_` 前缀),`distill` 会把它们排除在指纹之外 ——
    否则"瞎了 → 判 FP"会被当经验学下来,以后一瞎就自动放过。

    ★手写的 blind_spots **不删**:那里面绝大部分是**模型盲区**(本体没建模,对每个客户都成立),
      属于方法论,本来就该写死。这里只**追加**测出来的那一半。
    """
    needs = list(getattr(skill, "needs", None) or ())
    gaps = profile.missing(needs)
    if not gaps:
        return forensics
    for need in gaps:
        forensics.findings.append(Finding(
            "_coverage.absent",
            {"skill": getattr(skill, "name", None), "need": need, "scope": "deployment"},
            polarity="neutral"))
    line = "本环境缺这些遥测(实测,非推断):" + "、".join(profile.describe(n) for n in gaps)
    forensics.blind_spots = (forensics.blind_spots + " | " + line
                             if forensics.blind_spots else line)
    return forensics
