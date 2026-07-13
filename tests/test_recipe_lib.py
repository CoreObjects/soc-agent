"""recipe 共用纯函数:PowerShell EncodedCommand 解码 + 已知良性供给/自检噪声识别。

这些是把"证据薄→LLM 幻觉/误判"摁回去的关键:决定性文本(编码命令/脚本块)必须先由
确定性代码解出来、认出来,再交 LLM。纯逻辑,可单测。
"""
import base64

from soc_agent.recipe_lib import decode_chain, decode_powershell_cmd, provisioning_noise


def _enc(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


def test_decode_encodedcommand_full_flag():
    payload = "Get-Process | Out-Null"
    assert decode_powershell_cmd(f"powershell.exe -NoProfile -EncodedCommand {_enc(payload)}") == payload


def test_decode_enc_abbrev():
    payload = "Write-Host 'hi there'"
    assert decode_powershell_cmd(f"powershell -enc {_enc(payload)}") == payload


def test_decode_ignores_executionpolicy_lookalike():
    # -ExecutionPolicy 以 -e 开头,不能被误当 EncodedCommand
    assert decode_powershell_cmd("powershell -ExecutionPolicy Unrestricted -Command Write-Host hi") is None


def test_decode_no_encoded_returns_none():
    assert decode_powershell_cmd("powershell -Command Write-Host hi") is None
    assert decode_powershell_cmd("") is None
    assert decode_powershell_cmd(None) is None


def test_decode_bad_base64_does_not_crash():
    # 长度够但非法 → 不抛,返回 None 或可打印串
    out = decode_powershell_cmd("powershell -enc @@@@@@@@@@@@@@@@@@@@")
    assert out is None or isinstance(out, str)


def test_decode_chain_unwraps_nested():
    inner = "Write-AnsibleLog INFO exec_wrapper"
    mid = f"powershell -enc {_enc(inner)}"
    outer = f"powershell.exe -NoProfile -EncodedCommand {_enc(mid)}"
    assert decode_chain(outer) == [mid, inner]


def test_decode_chain_empty_when_no_encoding():
    assert decode_chain("powershell -Command foo") == []


def test_noise_detects_ansible():
    txt = "ConvertFrom-AnsibleJson ... Write-AnsibleLog ... $env:ANSIBLE_EXEC_DEBUG ... end exec_wrapper"
    assert "ansible" in (provisioning_noise(txt) or "").lower()


def test_noise_detects_ps_policy_probe():
    path = r"C:\Users\vagrant\AppData\Local\Temp\__PSScriptPolicyTest_osqirtuj.he3.ps1"
    assert "policy" in (provisioning_noise(path) or "").lower()


def test_noise_none_for_benign_normal_text():
    assert provisioning_noise("powershell -Command Get-Date") is None
    assert provisioning_noise("") is None
    assert provisioning_noise(None) is None
