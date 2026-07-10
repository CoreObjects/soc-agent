"""schema 生成器:把 model/graph_model.json 变成注入 LLM 提示的 v3 schema 文本。

关键:必须把真实的 label/键/谓语/告警层/经验层写全,否则 LLM 会瞎猜
(实测不喂 schema 会生成 Host{name}/TRIGGER 之类的错 Cypher)。
"""
from pathlib import Path

from soc_agent.schema import build_schema, load_model

MODEL_PATH = Path(__file__).resolve().parents[1] / "model" / "graph_model.json"


def test_load_model_reads_v3_graph_model():
    model = load_model(MODEL_PATH)
    assert str(model["version"]).startswith("3")
    assert any(e["name"] == "Account" for e in model["entities"])


def test_load_model_default_path_finds_repo_model():
    # 不传路径也要能定位到仓库 model/graph_model.json
    model = load_model()
    assert any(e["name"] == "Account" for e in model["entities"])


def test_schema_lists_entities_with_keys():
    schema = build_schema(load_model(MODEL_PATH))
    assert "Account" in schema
    assert "sam" in schema and "domain" in schema        # Account 复合键
    assert "Process" in schema and "process_guid" in schema
    assert "Host" in schema


def test_schema_lists_event_node_and_edges():
    schema = build_schema(load_model(MODEL_PATH))
    assert "Event" in schema
    assert "BY" in schema          # 主语边
    assert "ON_HOST" in schema     # 次要边


def test_schema_lists_verbs():
    schema = build_schema(load_model(MODEL_PATH))
    for verb in ["AUTHENTICATED_TO", "REQUESTED", "ACCESSED", "SPAWNED"]:
        assert verb in schema


def test_schema_lists_alert_and_experience_layers():
    schema = build_schema(load_model(MODEL_PATH))
    assert "Alert" in schema and "alert_uid" in schema
    assert "Technique" in schema and "attack_id" in schema
    assert "TRIGGERED" in schema and "INDICATES" in schema
    assert "Verdict" in schema and "Disposition" in schema
    assert "CONCLUDED" in schema


def test_schema_is_reasonably_sized():
    schema = build_schema(load_model(MODEL_PATH))
    # 够详尽但不至于炸上下文
    assert 500 < len(schema) < 20000
