"""Tests for policy file loading."""
import json
import pytest
from asr.config import load_policy_file
from asr.guard import Guard


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
        with pytest.raises(ValueError, match="Unsupported file extension"):
            load_policy_file(str(p))

    def test_empty_file_json(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("{}")
        config = load_policy_file(str(p))
        assert config == {}

    def test_non_dict_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("[]")
        with pytest.raises(ValueError, match="top level"):
            load_policy_file(str(p))

    def test_non_dict_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="top level"):
            load_policy_file(str(p))

    def test_null_yaml(self, tmp_path):
        p = tmp_path / "null.yaml"
        p.write_text("")
        with pytest.raises(ValueError, match="top level"):
            load_policy_file(str(p))

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_policy_file("/nonexistent/policy.json")


class TestGuardFromConfig:
    def test_minimal_config(self):
        config = {"version": 1}
        guard = Guard.from_config(config)
        assert guard._mode == "enforce"
        assert guard._pii_action == "off"

    def test_full_config(self):
        config = {
            "version": 1,
            "mode": "shadow",
            "domain_allowlist": ["api.internal.com"],
            "file_path_allowlist": ["/tmp/asr"],
            "pii_action": "block",
            "block_egress": True,
            "tool_blocklist": ["rm_rf"],
            "capability_policy": {"shell_exec": "block"},
            "default_action": "warn",
        }
        guard = Guard.from_config(config)
        assert guard._mode == "shadow"
        assert guard._domain_allowlist == ["api.internal.com"]
        assert guard._pii_action == "block"
        assert guard._block_egress is True
        assert guard._tool_blocklist == ["rm_rf"]

    def test_runtime_override(self):
        config = {"version": 1, "mode": "shadow"}
        guard = Guard.from_config(config, mode="enforce")
        assert guard._mode == "enforce"

    def test_callback_override(self):
        blocked = []
        config = {"version": 1, "tool_blocklist": ["danger"]}
        guard = Guard.from_config(config, on_block=lambda d: blocked.append(d))
        guard.before_tool("danger", {})
        assert len(blocked) == 1


class TestGuardFromConfigValidation:
    def test_missing_version_defaults_to_v1(self):
        """Treat a missing version as v1 and allow valid configs."""
        guard = Guard.from_config({"mode": "enforce"})
        assert guard._mode == "enforce"

    def test_unsupported_version(self):
        with pytest.raises(ValueError, match="version"):
            Guard.from_config({"version": 99})

    def test_unknown_key(self):
        with pytest.raises(ValueError, match="Unknown policy field"):
            Guard.from_config({"version": 1, "block_gress": True})

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="mode"):
            Guard.from_config({"version": 1, "mode": "turbo"})

    def test_invalid_pii_action(self):
        with pytest.raises(ValueError, match="pii_action"):
            Guard.from_config({"version": 1, "pii_action": "delete"})

    def test_invalid_default_action(self):
        with pytest.raises(ValueError, match="default_action"):
            Guard.from_config({"version": 1, "default_action": "destroy"})

    def test_invalid_capability_policy_value(self):
        with pytest.raises(ValueError, match="capability_policy"):
            Guard.from_config({"version": 1, "capability_policy": {"shell": "destroy"}})

    def test_invalid_list_element_type(self):
        with pytest.raises(ValueError, match="domain_allowlist"):
            Guard.from_config({"version": 1, "domain_allowlist": [123, 456]})

    def test_invalid_block_egress_type(self):
        with pytest.raises(ValueError, match="block_egress"):
            Guard.from_config({"version": 1, "block_egress": "yes"})


class TestGuardFromPolicyFile:
    def test_from_json_file(self, tmp_path):
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({
            "version": 1,
            "mode": "shadow",
            "tool_blocklist": ["rm_rf"],
        }))
        guard = Guard.from_policy_file(str(p))
        assert guard._mode == "shadow"
        assert guard._tool_blocklist == ["rm_rf"]

    def test_from_yaml_file(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("version: 1\nmode: warn\npii_action: block\n")
        guard = Guard.from_policy_file(str(p))
        assert guard._mode == "warn"
        assert guard._pii_action == "block"

    def test_from_file_with_override(self, tmp_path):
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({"version": 1, "mode": "shadow"}))
        blocked = []
        guard = Guard.from_policy_file(
            str(p),
            mode="enforce",
            on_block=lambda d: blocked.append(d),
            tool_blocklist=["danger"],
        )
        assert guard._mode == "enforce"
        guard.before_tool("danger", {})
        assert len(blocked) == 1

    def test_from_file_validates(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"version": 99}))
        with pytest.raises(ValueError, match="version"):
            Guard.from_policy_file(str(p))
