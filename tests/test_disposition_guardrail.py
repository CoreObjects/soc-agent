"""处置护栏(P5a,提议时):NEVER-TOUCH 硬拒 + 目标类型解析 + 高危 gated。

背景(真机教训):qwen 曾建议"杀 wazuh-agent + 隔离主机"(自伤)、把文件路径当 isolate_host
目标。SKILL.md 红线是软约束(靠模型听话),这里是代码级硬拦截。纯逻辑、可单测。
"""
from soc_agent.disposition import apply_guardrail
from soc_agent.models import Disposition


def _pol():
    return {"protected_hosts": ["dc01.corp.local"], "protected_accounts": ["krbtgt"]}


def test_sensor_kill_is_blocked_and_downgraded_to_escalate():
    d = Disposition(action="kill_process", target=r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe", risk="high")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "escalate"                       # 绝不杀传感器
    assert audit[0]["decision"] == "blocked"
    assert "代理" in audit[0]["reason"] or "agent" in audit[0]["reason"].lower()


def test_isolate_host_with_file_path_target_is_retargeted():
    d = Disposition(action="isolate_host", target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", risk="high")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "escalate"                       # 文件路径不是主机 → 打回人工
    assert audit[0]["decision"] == "retargeted"


def test_protected_account_disable_is_blocked():
    d = Disposition(action="disable_account", target="krbtgt", risk="high")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "escalate"
    assert audit[0]["decision"] == "blocked"


def test_protected_host_isolate_is_blocked():
    d = Disposition(action="isolate_host", target="dc01.corp.local", risk="high")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "escalate"
    assert audit[0]["decision"] == "blocked"


def test_normal_disable_account_kept_but_gated():
    d = Disposition(action="disable_account", target="eddard.stark", risk="high")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "disable_account"                # 普通账号:保留
    assert safe[0].status == "proposed"                       # 高危 → 仍仅建议(gated)
    assert audit[0]["decision"] == "gated"


def test_low_risk_monitor_is_auto():
    d = Disposition(action="monitor", target="host1.corp.local", risk="low")
    safe, audit = apply_guardrail([d], _pol())
    assert safe[0].action == "monitor"
    assert audit[0]["decision"] == "auto"


def test_block_ip_requires_ip_target():
    ok, _ = apply_guardrail([Disposition(action="block_ip", target="10.1.2.3", risk="low")], _pol())
    assert ok[0].action == "block_ip"                         # 合法 IP:保留
    bad, audit = apply_guardrail([Disposition(action="block_ip", target="not-an-ip", risk="low")], _pol())
    assert bad[0].action == "escalate"                        # 非 IP:打回
    assert audit[0]["decision"] == "retargeted"


def test_escalate_and_none_pass_through():
    ds = [Disposition(action="escalate", target="SOC team"), Disposition(action="none", target=None)]
    safe, _ = apply_guardrail(ds, _pol())
    assert [s.action for s in safe] == ["escalate", "none"]


def test_empty_and_default_policy_do_not_crash():
    assert apply_guardrail([], None) == ([], [])
    # 默认策略(不给 policy)对普通处置不误伤
    safe, _ = apply_guardrail([Disposition(action="monitor", target="h1", risk="low")])
    assert safe[0].action == "monitor"


class _FakeGraph:
    def __init__(self, hosts):
        self._hosts = hosts

    def run_cypher(self, q, **p):
        return [{"hosts": self._hosts}]


def test_policy_from_graph_auto_protects_dc_and_ca():
    # 补图第二弹的收现:护栏从图里读 DC/CA 主机名,自动进 NEVER-TOUCH(免手维护 env 名单)
    from soc_agent.disposition import policy_from_graph
    g = _FakeGraph(["kingslanding.sevenkingdoms.local", "braavos.essos.local"])
    pol = policy_from_graph(g)
    assert "kingslanding.sevenkingdoms.local" in pol["protected_hosts"]
    safe, audit = apply_guardrail(
        [Disposition(action="isolate_host", target="kingslanding.sevenkingdoms.local", risk="high")], pol)
    assert safe[0].action == "escalate" and audit[0]["decision"] == "blocked"
    assert "受保护主机" in audit[0]["reason"]


def test_policy_from_graph_survives_graph_error():
    class Boom:
        def run_cypher(self, q, **p):
            raise RuntimeError("no graph")
    from soc_agent.disposition import policy_from_graph
    pol = policy_from_graph(Boom())               # 图挂了也别崩,退回默认策略
    assert "protected_accounts" in pol


# ---- 接口文档驱动 + 修子串 bug 的回归 ----

def test_substring_host_bug_fixed_adc01_not_matched_when_protecting_dc01():
    # ★旧 bug:`dc01 in adc01`(子串)会误伤不相干的 adc01。修后按标签比,adc01 不被 dc01 保护。
    pol = {"protected_hosts": ["dc01.corp.local"], "protected_accounts": []}
    safe, audit = apply_guardrail([Disposition(action="isolate_host", target="adc01.corp.local", risk="high")], pol)
    assert safe[0].action == "isolate_host"       # adc01 ≠ dc01,不该被拦
    assert audit[0]["decision"] == "gated"


def test_protected_host_matched_by_short_or_fqdn():
    pol = {"protected_hosts": ["dc01"], "protected_accounts": []}
    # 给短名保护,目标给 FQDN,仍要命中(标签匹配)
    safe, _ = apply_guardrail([Disposition(action="isolate_host", target="dc01.corp.local", risk="high")], pol)
    assert safe[0].action == "escalate"


def test_collect_artifact_is_auto_not_gated():
    # 只读取证 → interface gating=auto → 不进人审队列
    safe, audit = apply_guardrail([Disposition(action="collect_artifact", target="host1", risk="low")], _pol())
    assert safe[0].action == "collect_artifact"
    assert audit[0]["decision"] == "auto"


def test_remove_from_group_gated_and_protected_account_blocked():
    # 多参原语:主目标=账号(sam)。普通账号 gated;受保护账号 blocked。
    safe, audit = apply_guardrail(
        [Disposition(action="remove_from_group", target="eddard.stark",
                     params={"sam": "eddard.stark", "group": "Domain Admins"}, risk="high")], _pol())
    assert safe[0].action == "remove_from_group" and audit[0]["decision"] == "gated"
    blk, aud = apply_guardrail([Disposition(action="remove_from_group", target="krbtgt", risk="high")], _pol())
    assert blk[0].action == "escalate" and aud[0]["decision"] == "blocked"


def test_domain_scoped_primitive_is_gated():
    # rotate_krbtgt 域级 → 恒 gated(接口文档里 gating=gated)
    safe, audit = apply_guardrail([Disposition(action="rotate_krbtgt", target="north.sevenkingdoms.local")], _pol())
    assert audit[0]["decision"] == "gated"


def test_unbound_target_escalates_not_hardfails():
    # 角色没绑上(如源主机取不到)→ 目标为空 → 该步降级 escalate,不硬跑失败拖垮整个计划
    safe, audit = apply_guardrail([Disposition(action="collect_artifact", target=None, target_kind="host")], _pol())
    assert safe[0].action == "escalate"
    assert audit[0]["decision"] == "retargeted" and "未解析" in audit[0]["reason"]
