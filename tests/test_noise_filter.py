"""噪声过滤器 TDD:接入层黑名单剔纯噪声,连接性事件全留,丢弃计数不静默。"""
from ingest.noise_filter import NoiseFilter, Dropset, Rule, load_dropset, DEFAULT_DROPSET_PATH


def _wl(channel, eid, **ed):
    return {"winlog": {"channel": channel, "event_id": eid, "event_data": ed}}


def test_channel_level_noise_dropped_and_counted():
    f = NoiseFilter(Dropset(channel_eventid={("Security", "4634")}, instance_rules=[]))
    assert f.should_ingest(_wl("Security", "4634")) is False   # 登出 = 纯噪声
    assert f.stats()["Security/4634"] == 1


def test_connective_event_kept():
    f = NoiseFilter(Dropset(channel_eventid={("Security", "4634")}, instance_rules=[]))
    assert f.should_ingest(_wl("Security", "4624")) is True    # 登录 = 连接性,留(含 benign)


def test_instance_rule_drops_vbox_but_keeps_real_dump():
    rule = Rule("Microsoft-Windows-Sysmon/Operational", "10", "SourceImage",
                "endswith", "VBoxService.exe", "benign_vbox_selfaccess")
    f = NoiseFilter(Dropset(set(), [rule]))
    vbox = _wl("Microsoft-Windows-Sysmon/Operational", "10",
               SourceImage="C:\\Windows\\System32\\VBoxService.exe")
    dump = _wl("Microsoft-Windows-Sysmon/Operational", "10",
               SourceImage="C:\\Windows\\System32\\rundll32.exe")
    assert f.should_ingest(vbox) is False    # VBox 良性自查 lsass,丢
    assert f.should_ingest(dump) is True     # rundll32 转储,留
    assert f.stats()["benign_vbox_selfaccess"] == 1


def test_non_winlog_doc_kept():
    # WAF 等非 winlog 文档不在噪声黑名单(它们靠 mapper 处理,不是噪声)
    f = NoiseFilter(Dropset({("Security", "4634")}, []))
    assert f.should_ingest({"transaction": {"unique_id": "x"}}) is True


def test_load_default_dropset_file():
    ds = load_dropset(DEFAULT_DROPSET_PATH)
    assert ("Security", "4634") in ds.channel_eventid          # 登出在默认黑名单
    assert ("Security", "4672") in ds.channel_eventid          # 特权分配
    assert any(r.reason == "benign_vbox_selfaccess" for r in ds.instance_rules)
