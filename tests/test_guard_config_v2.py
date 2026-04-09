"""Tests for YAML v2 policy validation (tools: section)."""
import pytest
from asr.guard_config import validate_guard_config


class TestVersionHandling:
    def test_missing_version_defaults_to_v1(self):
        """Treat a missing version as v1; allow it when tools: is absent."""
        config = {"mode": "shadow"}
        validate_guard_config(config)  # should not raise

    def test_missing_version_with_tools_rejected(self):
        """Treat a missing version as v1, where tools: is not allowed."""
        config = {"mode": "shadow", "tools": {"send_email": {}}}
        with pytest.raises(ValueError, match="version: 2"):
            validate_guard_config(config)

    def test_v1_with_tools_rejected(self):
        config = {"version": 1, "tools": {"send_email": {}}}
        with pytest.raises(ValueError, match="version: 2"):
            validate_guard_config(config)

    def test_v2_without_tools_ok(self):
        config = {"version": 2, "mode": "shadow"}
        validate_guard_config(config)

    def test_v2_with_tools_ok(self):
        config = {
            "version": 2,
            "mode": "shadow",
            "tools": {
                "send_email": {
                    "capabilities": ["network_send"],
                    "domain_allowlist": ["mail.internal"],
                    "mode": "enforce",
                }
            },
        }
        validate_guard_config(config)


class TestToolsSectionValidation:
    def test_empty_tool_config_allowed(self):
        config = {"version": 2, "tools": {"send_email": {}}}
        validate_guard_config(config)

    def test_unknown_tool_key_rejected(self):
        config = {
            "version": 2,
            "tools": {"send_email": {"unknown_key": "value"}},
        }
        with pytest.raises(ValueError, match="tools.send_email.*unknown_key"):
            validate_guard_config(config)

    def test_tools_must_be_dict(self):
        config = {"version": 2, "tools": ["send_email"]}
        with pytest.raises(ValueError, match="tools.*mapping"):
            validate_guard_config(config)

    def test_tool_config_must_be_dict(self):
        config = {"version": 2, "tools": {"send_email": "bad"}}
        with pytest.raises(ValueError, match="tools.send_email.*mapping"):
            validate_guard_config(config)

    def test_capabilities_must_be_list_of_strings(self):
        config = {"version": 2, "tools": {"t": {"capabilities": "bad"}}}
        with pytest.raises(ValueError, match="tools.t.capabilities.*list of.*string"):
            validate_guard_config(config)

    def test_capabilities_items_must_be_nonempty(self):
        config = {"version": 2, "tools": {"t": {"capabilities": [""]}}}
        with pytest.raises(ValueError, match="tools.t.capabilities.*non-empty"):
            validate_guard_config(config)

    def test_tool_mode_validated(self):
        config = {"version": 2, "tools": {"t": {"mode": "invalid"}}}
        with pytest.raises(ValueError, match="tools.t.mode"):
            validate_guard_config(config)

    def test_tool_pii_action_validated(self):
        config = {"version": 2, "tools": {"t": {"pii_action": "invalid"}}}
        with pytest.raises(ValueError, match="tools.t.pii_action"):
            validate_guard_config(config)

    def test_tool_default_action_validated(self):
        config = {"version": 2, "tools": {"t": {"default_action": "invalid"}}}
        with pytest.raises(ValueError, match="tools.t.default_action"):
            validate_guard_config(config)

    def test_tool_domain_allowlist_validated(self):
        config = {"version": 2, "tools": {"t": {"domain_allowlist": "bad"}}}
        with pytest.raises(ValueError, match="tools.t.domain_allowlist"):
            validate_guard_config(config)

    def test_all_known_tool_keys_accepted(self):
        config = {
            "version": 2,
            "tools": {
                "t": {
                    "capabilities": ["network_send"],
                    "mode": "enforce",
                    "domain_allowlist": ["a.com"],
                    "file_path_allowlist": ["/tmp"],
                    "pii_action": "block",
                    "pii_profiles": ["global-core"],
                    "block_egress": True,
                    "capability_policy": {"network_send": "block"},
                    "default_action": "warn",
                }
            },
        }
        validate_guard_config(config)
