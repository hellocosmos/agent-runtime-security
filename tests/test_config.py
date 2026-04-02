"""정책 파일 로드 테스트"""
import json
import pytest
from asr.config import load_policy_file


class TestLoadPolicyFileJson:
    def test_load_json(self, tmp_path):
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({"version": 1, "mode": "shadow"}))
        config = load_policy_file(str(p))
        assert config["version"] == 1
        assert config["mode"] == "shadow"

    def test_load_json_full(self, tmp_path):
        policy = {
            "version": 1,
            "mode": "enforce",
            "domain_allowlist": ["api.internal.com"],
            "file_path_allowlist": ["/tmp/asr"],
            "pii_action": "block",
            "block_egress": True,
            "tool_blocklist": ["rm_rf"],
            "capability_policy": {"shell_exec": "block"},
            "default_action": "warn",
        }
        p = tmp_path / "full.json"
        p.write_text(json.dumps(policy))
        config = load_policy_file(str(p))
        assert config == policy


class TestLoadPolicyFileYaml:
    def test_load_yaml(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("version: 1\nmode: shadow\n")
        config = load_policy_file(str(p))
        assert config["version"] == 1
        assert config["mode"] == "shadow"

    def test_load_yml_extension(self, tmp_path):
        p = tmp_path / "policy.yml"
        p.write_text("version: 1\n")
        config = load_policy_file(str(p))
        assert config["version"] == 1


class TestLoadPolicyFileErrors:
    def test_unsupported_extension(self, tmp_path):
        p = tmp_path / "policy.toml"
        p.write_text("")
        with pytest.raises(ValueError, match="지원하지 않는 파일 확장자"):
            load_policy_file(str(p))

    def test_empty_file_json(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("{}")
        config = load_policy_file(str(p))
        assert config == {}

    def test_non_dict_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("[]")
        with pytest.raises(ValueError, match="최상위가 mapping"):
            load_policy_file(str(p))

    def test_non_dict_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="최상위가 mapping"):
            load_policy_file(str(p))

    def test_null_yaml(self, tmp_path):
        p = tmp_path / "null.yaml"
        p.write_text("")
        with pytest.raises(ValueError, match="최상위가 mapping"):
            load_policy_file(str(p))

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_policy_file("/nonexistent/policy.json")
