"""配置:从环境变量 / .env 读端点(真值只在 server2 的 .env,不入仓)。"""
from soc_agent.config import Config, load_dotenv


def test_load_dotenv_parses_kv(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# 注释\nNEO4J_URI=bolt://x:7687\nLLM_MODEL="qwen32b-ft"\n\nEMPTYLINE\n', encoding="utf-8")
    env = load_dotenv(f)
    assert env["NEO4J_URI"] == "bolt://x:7687"
    assert env["LLM_MODEL"] == "qwen32b-ft"        # 去引号
    assert "EMPTYLINE" not in env                   # 无 = 的行忽略


def test_load_dotenv_missing_file_returns_empty(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == {}


def test_config_from_env_defaults_and_values():
    cfg = Config.from_env(env={"NEO4J_URI": "bolt://s1:7687", "NEO4J_PASSWORD": "pw",
                               "LLM_API_BASE": "http://s2:8000/v1"})
    assert cfg.neo4j_uri == "bolt://s1:7687"
    assert cfg.neo4j_user == "neo4j"                # 默认
    assert cfg.llm_api_key == "EMPTY"               # 无 key 默认占位
    assert cfg.llm_model == "qwen32b-ft"
    assert cfg.max_iterations == 12
    assert cfg.skills_dir.endswith("skills")


def test_config_os_env_overrides_dotenv(tmp_path):
    f = tmp_path / ".env"
    f.write_text("NEO4J_URI=bolt://from-file:7687\nLLM_MODEL=file-model\n", encoding="utf-8")
    cfg = Config.from_env(env={"NEO4J_URI": "bolt://from-os:7687"}, dotenv_path=f)
    assert cfg.neo4j_uri == "bolt://from-os:7687"   # os env 覆盖文件
    assert cfg.llm_model == "file-model"            # 文件里独有的仍生效
