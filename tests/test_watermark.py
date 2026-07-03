"""watermark 游标 TDD:JSON state 文件 + 原子写,增量 tail 的断点。"""
import json

from ingest.watermark import JsonWatermark


def test_save_load_roundtrip(tmp_path):
    wm = JsonWatermark(tmp_path / "wm.json")
    assert wm.load("winlogbeat-*") is None            # 无文件/无索引 → None
    wm.save("winlogbeat-*", [1751440080000, "AbC_id"])
    assert wm.load("winlogbeat-*") == [1751440080000, "AbC_id"]   # sort 数组原样


def test_per_index_isolation(tmp_path):
    wm = JsonWatermark(tmp_path / "wm.json")
    wm.save("winlogbeat-*", [1, "a"])
    wm.save("soc-app-*", [2, "b"])
    assert wm.load("winlogbeat-*") == [1, "a"]
    assert wm.load("soc-app-*") == [2, "b"]


def test_docs_ingested_accumulates_and_cursor_advances(tmp_path):
    p = tmp_path / "wm.json"
    wm = JsonWatermark(p)
    wm.save("winlogbeat-*", [1, "a"], count=100)
    wm.save("winlogbeat-*", [2, "b"], count=50)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["winlogbeat-*"]["docs_ingested"] == 150
    assert wm.load("winlogbeat-*") == [2, "b"]         # 游标推进到最新


def test_atomic_write_no_tmp_leftover_valid_json(tmp_path):
    p = tmp_path / "wm.json"
    wm = JsonWatermark(p)
    wm.save("x", [1])
    assert not (tmp_path / "wm.json.tmp").exists()      # 无残留 tmp
    json.loads(p.read_text(encoding="utf-8"))           # 主文件是合法 JSON
