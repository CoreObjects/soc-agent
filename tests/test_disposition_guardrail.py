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
