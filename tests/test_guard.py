"""Integration tests for Guard, including policy order."""
import pytest
from asr.guard import Guard, BlockedToolError
from asr.types import BeforeToolDecision, AfterToolDecision


class TestGuardBeforeTool:
    def setup_method(self):
        self.guard = Guard(
            domain_allowlist=["api.internal.com"],
            file_path_allowlist=["/tmp/asr"],
            pii_action="block",
            block_egress=True,
            tool_blocklist=["rm_rf", "eval"],
            capability_policy={"network_send": "warn", "shell_exec": "block"},
            default_action="warn",
        )

    def test_blocklist_highest_priority(self):
        d = self.guard.before_tool("rm_rf", {"path": "/tmp/asr/safe"})
        assert isinstance(d, BeforeToolDecision)
        assert d.action == "block"
        assert d.policy_id == "tool_blocklist"

    def test_egress_blocks_external_domain(self):
        d = self.guard.before_tool("http_post", {"url": "https://evil.com/steal"}, capabilities=["network_send"])
        assert d.action == "block"
        assert d.policy_id == "domain_allowlist"

    def test_egress_allows_internal_domain(self):
        """Allowed domains should pass egress and skip capability fallback."""
        d = self.guard.before_tool("http_post", {"url": "https://api.internal.com/data"}, capabilities=["network_send"])
        assert d.action in ("allow", "warn")
        assert d.policy_id != "capability_policy"

    def test_file_path_blocks_unauthorized(self):
        d = self.guard.before_tool("file_read", {"path": "/etc/passwd"})
        assert d.action == "block"
        assert d.policy_id == "file_path_allowlist"

    def test_file_path_allows_authorized(self):
        d = self.guard.before_tool("file_write", {"path": "/tmp/asr/output.txt"})
        assert d.action == "allow"

    def test_pii_blocks(self):
        d = self.guard.before_tool("send_email", {"body": "API key: sk-abc123def456ghi789jkl012mno345pqr678"})
        assert d.action == "block"
        assert d.policy_id == "pii_detection"

    def test_capability_shell_exec_blocks(self):
        """No URL, no file path, no PII → no specific policy matched → capability fallback applies"""
        d = self.guard.before_tool("run_command", {"cmd": "ls"}, capabilities=["shell_exec"])
        assert d.action == "block"
        assert d.policy_id == "capability_policy"

    def test_default_action_for_unknown_tool(self):
        d = self.guard.before_tool("totally_new_tool", {"x": "y"})
        assert d.action == "warn"
        assert d.policy_id == "default_action"

    def test_capability_is_true_fallback(self):
        """Capability is a true fallback and does not rerun after specific matches."""
        guard = Guard(
            domain_allowlist=["api.internal.com"],
            block_egress=True,
            capability_policy={"network_send": "block"},
        )
        d = guard.before_tool("http_post", {"url": "https://api.internal.com/data"}, capabilities=["network_send"])
        assert d.action in ("allow", "warn")
        assert d.policy_id != "capability_policy"

    def test_redacted_args_masks_pii(self):
        d = self.guard.before_tool("send_email", {"to": "victim@example.com", "body": "normal text"})
        assert "victim@example.com" not in str(d.redacted_args)

    def test_capabilities_in_decision(self):
        d = self.guard.before_tool("http_post", {"url": "https://evil.com"}, capabilities=["network_send"])
        assert d.capabilities == ["network_send"]


class TestGuardCallbacks:
    def test_on_block_callback(self):
        blocked = []
        guard = Guard(tool_blocklist=["dangerous"], on_block=lambda d: blocked.append(d))
        guard.before_tool("dangerous", {})
        assert len(blocked) == 1

    def test_on_warn_callback(self):
        warned = []
        guard = Guard(default_action="warn", on_warn=lambda d: warned.append(d))
        guard.before_tool("new_tool", {})
        assert len(warned) == 1


class TestGuardAfterTool:
    def test_allow_clean_result(self):
        guard = Guard(pii_action="block")
        d = guard.after_tool("search", "Normal search result text")
        assert isinstance(d, AfterToolDecision)
        assert d.action == "allow"

    def test_redact_result_with_pii_string(self):
        guard = Guard(pii_action="block")
        d = guard.after_tool("search", "Found: admin@secret.com in records")
        assert d.action == "redact_result"
        assert isinstance(d.redacted_result, str)
        assert "admin@secret.com" not in d.redacted_result

    def test_redact_result_preserves_dict(self):
        guard = Guard(pii_action="block")
        d = guard.after_tool("search", {"name": "John", "email": "admin@secret.com"})
        assert d.action == "redact_result"
        assert isinstance(d.redacted_result, dict)
        assert "admin@secret.com" not in str(d.redacted_result)

    def test_redact_result_preserves_list(self):
        guard = Guard(pii_action="block")
        d = guard.after_tool("search", ["normal", "admin@secret.com"])
        assert d.action == "redact_result"
        assert isinstance(d.redacted_result, list)

    def test_warn_pii_in_result(self):
        guard = Guard(pii_action="warn")
        d = guard.after_tool("search", "Found: admin@secret.com")
        assert d.action == "warn"

    def test_pii_off_allows_all(self):
        guard = Guard(pii_action="off")
        d = guard.after_tool("search", "Found: admin@secret.com")
        assert d.action == "allow"


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestProtectDecorator:
    def test_allowed_function_runs(self):
        guard = Guard(default_action="allow")

        @guard.protect
        def safe_function():
            return "result"

        assert safe_function() == "result"

    def test_blocked_function_raises(self):
        guard = Guard(tool_blocklist=["dangerous_action"])

        @guard.protect
        def dangerous_action():
            return "should not reach"

        with pytest.raises(BlockedToolError) as exc_info:
            dangerous_action()
        assert exc_info.value.decision.action == "block"

    def test_capabilities_passed(self):
        guard = Guard(capability_policy={"shell_exec": "block"})

        @guard.protect(capabilities=["shell_exec"])
        def run_shell():
            return "output"

        with pytest.raises(BlockedToolError):
            run_shell()

    def test_result_redaction(self):
        guard = Guard(pii_action="block")

        @guard.protect
        def search_data():
            return "Found email: admin@secret.com in database"

        result = search_data()
        assert "admin@secret.com" not in result
        assert "[EMAIL]" in result

    def test_positional_args_checked(self):
        """Positional args are inspected for PII, except recipient fields such as to."""
        guard = Guard(pii_action="block")

        @guard.protect
        def send_email(to, subject, body):
            return "sent"

        # Recipient fields such as "to" are exempt from PII blocking.
        result = send_email("victim@example.com", "test", "normal body")
        assert result == "sent"

        # PII in the body should still trigger blocking.
        with pytest.raises(BlockedToolError):
            send_email("victim@example.com", "test", "API key: sk-abc123def456ghi789jkl012mno345pqr678")

    def test_after_tool_preserves_dict_type(self):
        guard = Guard(pii_action="block")

        @guard.protect
        def search():
            return {"name": "John", "email": "admin@secret.com"}

        result = search()
        assert isinstance(result, dict)
        assert "admin@secret.com" not in str(result)

    def test_warn_does_not_block(self):
        guard = Guard(default_action="warn")

        @guard.protect
        def some_tool():
            return 42

        assert some_tool() == 42


class TestEgressEmailWiring:
    """Email sends without URLs should still go through egress policy."""

    def test_email_to_external_domain_warns(self):
        """External email destinations should return warn from egress policy."""
        guard = Guard(
            domain_allowlist=["internal.com"],
            block_egress=True,
        )
        d = guard.before_tool("send_email", {"to": "attacker@evil.com", "body": "hello"})
        assert d.action == "warn"
        assert d.policy_id == "egress_control"

    def test_email_to_allowed_domain_allows(self):
        """Allowed recipient domains should pass."""
        guard = Guard(
            domain_allowlist=["internal.com"],
            block_egress=True,
        )
        d = guard.before_tool("send_email", {"to": "user@internal.com", "body": "hello"})
        assert d.action == "allow"

    def test_email_egress_sets_matched_specific(self):
        """Email egress matches should skip capability fallback."""
        guard = Guard(
            domain_allowlist=["internal.com"],
            block_egress=True,
            capability_policy={"network_send": "block"},
        )
        d = guard.before_tool("send_email", {"to": "user@internal.com", "body": "hello"},
                              capabilities=["network_send"])
        assert d.action == "allow"
        assert d.policy_id != "capability_policy"

    def test_recipients_list_external_warns(self):
        """External domains in recipients lists should also trigger egress warnings."""
        guard = Guard(
            domain_allowlist=["internal.com"],
            block_egress=True,
        )
        d = guard.before_tool("send_email", {"recipients": ["attacker@evil.com"], "body": "hello"})
        assert d.action == "warn"
        assert d.policy_id == "egress_control"

    def test_email_send_capability_block_overrides_egress(self):
        """If email_send is blocked, generic email tools should block before egress warn/allow."""
        guard = Guard(
            domain_allowlist=["internal.com"],
            block_egress=True,
            capability_policy={"email_send": "block"},
        )
        d = guard.before_tool(
            "gmail_send",
            {"to": "attacker@evil.com", "body": "hello"},
            capabilities=["email_send"],
        )
        assert d.action == "block"
        assert d.policy_id == "capability_policy"


class TestGuardInit:
    def test_tools_parameter_accepted(self):
        guard = Guard(
            tools={"send_email": {"capabilities": ["network_send"]}},
        )
        assert guard._tools == {"send_email": {"capabilities": ["network_send"]}}

    def test_tools_default_empty(self):
        guard = Guard()
        assert guard._tools == {}

    def test_audit_parameter_accepted(self):
        from asr.audit import AuditLogger
        events = []
        audit = AuditLogger(output=events.append)
        guard = Guard(audit=audit)
        assert guard._audit is audit

    def test_audit_default_none(self):
        guard = Guard()
        assert guard._audit is None

    def test_from_config_with_tools(self):
        config = {
            "version": 2,
            "mode": "shadow",
            "tools": {
                "send_email": {
                    "capabilities": ["network_send"],
                    "mode": "enforce",
                },
            },
        }
        guard = Guard.from_config(config)
        assert guard._tools == config["tools"]
        assert guard._mode == "shadow"

    def test_from_config_v1_no_tools(self):
        config = {"version": 1, "mode": "shadow"}
        guard = Guard.from_config(config)
        assert guard._tools == {}


class TestResolveToolConfig:
    def setup_method(self):
        self.guard = Guard(
            mode="shadow",
            domain_allowlist=["global.com"],
            file_path_allowlist=["/tmp"],
            pii_action="block",
            pii_profiles=["global-core"],
            block_egress=True,
            capability_policy={"network_send": "warn", "shell_exec": "block"},
            default_action="warn",
            tools={
                "send_email": {
                    "capabilities": ["network_send"],
                    "domain_allowlist": ["mail.internal"],
                    "mode": "enforce",
                    "pii_action": "warn",
                },
                "empty_tool": {},
            },
        )

    def test_registered_tool_overrides_scalars(self):
        config = self.guard._resolve_tool_config("send_email", None)
        assert config["mode"] == "enforce"
        assert config["pii_action"] == "warn"

    def test_registered_tool_replaces_lists(self):
        config = self.guard._resolve_tool_config("send_email", None)
        assert config["domain_allowlist"] == ["mail.internal"]

    def test_registered_tool_inherits_unset(self):
        config = self.guard._resolve_tool_config("send_email", None)
        assert config["block_egress"] is True
        assert config["file_path_allowlist"] == ["/tmp"]
        assert config["default_action"] == "warn"

    def test_capabilities_from_yaml(self):
        config = self.guard._resolve_tool_config("send_email", None)
        assert config["capabilities"] == ["network_send"]

    def test_capabilities_code_overrides_yaml(self):
        config = self.guard._resolve_tool_config("send_email", ["shell_exec"])
        assert config["capabilities"] == ["shell_exec"]

    def test_unregistered_tool_uses_global(self):
        config = self.guard._resolve_tool_config("unknown_tool", None)
        assert config["mode"] == "shadow"
        assert config["domain_allowlist"] == ["global.com"]
        assert config["capabilities"] is None

    def test_empty_tool_config_inherits_all(self):
        config = self.guard._resolve_tool_config("empty_tool", None)
        assert config["mode"] == "shadow"
        assert config["domain_allowlist"] == ["global.com"]

    def test_capability_policy_shallow_merge(self):
        guard = Guard(
            capability_policy={"network_send": "warn", "shell_exec": "block"},
            tools={
                "t": {"capability_policy": {"network_send": "block"}},
            },
        )
        config = guard._resolve_tool_config("t", None)
        assert config["capability_policy"]["network_send"] == "block"
        assert config["capability_policy"]["shell_exec"] == "block"

    def test_mutable_copy_isolation(self):
        config1 = self.guard._resolve_tool_config("send_email", None)
        config2 = self.guard._resolve_tool_config("send_email", None)
        config1["domain_allowlist"].append("injected.com")
        assert "injected.com" not in config2["domain_allowlist"]
        assert "injected.com" not in self.guard._domain_allowlist

    def test_none_allowlists_produce_empty_lists(self):
        guard = Guard()
        config = guard._resolve_tool_config("any", None)
        assert config["domain_allowlist"] == []
        assert config["file_path_allowlist"] == []
        assert config["capability_policy"] == {}


class TestCapabilityAllow:
    def test_capability_allow_respected(self):
        """Allow in capability_policy should override default_action."""
        guard = Guard(
            capability_policy={"file_read": "allow"},
            default_action="warn",
        )
        d = guard.before_tool("file_read", {"query": "data"}, capabilities=["file_read"])
        assert d.action == "allow"
        assert d.policy_id == "capability_policy"


class TestNestedDictPii:
    def test_nested_dict_pii_detected(self):
        """Nested dict values should also be detected and redacted for PII."""
        guard = Guard(pii_action="block")
        d = guard.after_tool("get_user", {"user": {"email": "admin@secret.com"}})
        assert d.action == "redact_result"
        assert isinstance(d.redacted_result, dict)
        assert "admin@secret.com" not in str(d.redacted_result)


class TestGuardModeEnforce:
    """Enforce mode matches the original v0.1 behavior."""

    def test_enforce_is_default(self):
        guard = Guard(tool_blocklist=["dangerous"])
        d = guard.before_tool("dangerous", {})
        assert d.action == "block"
        assert d.original_action == "block"
        assert d.mode == "enforce"

    def test_enforce_block_stays_block(self):
        guard = Guard(mode="enforce", tool_blocklist=["dangerous"])
        d = guard.before_tool("dangerous", {})
        assert d.action == "block"
        assert d.original_action == "block"


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestGuardModeWarn:
    """Warn mode downgrades block decisions to warn."""

    def test_warn_downgrades_block_to_warn(self):
        guard = Guard(mode="warn", tool_blocklist=["dangerous"])
        d = guard.before_tool("dangerous", {})
        assert d.action == "warn"
        assert d.original_action == "block"
        assert d.mode == "warn"

    def test_warn_keeps_warn_as_warn(self):
        guard = Guard(mode="warn", default_action="warn")
        d = guard.before_tool("unknown_tool", {})
        assert d.action == "warn"
        assert d.original_action == "warn"

    def test_warn_keeps_allow_as_allow(self):
        guard = Guard(mode="warn", default_action="allow")
        d = guard.before_tool("safe_tool", {})
        assert d.action == "allow"
        assert d.original_action == "allow"

    def test_warn_no_blocked_tool_error(self):
        guard = Guard(mode="warn", tool_blocklist=["dangerous"])

        @guard.protect
        def dangerous():
            return "executed"

        result = dangerous()
        assert result == "executed"

    def test_warn_on_warn_callback_fires_for_downgraded_block(self):
        warned = []
        guard = Guard(mode="warn", tool_blocklist=["dangerous"],
                      on_warn=lambda d: warned.append(d))
        guard.before_tool("dangerous", {})
        assert len(warned) == 1
        assert warned[0].original_action == "block"

    def test_warn_on_block_callback_does_not_fire(self):
        blocked = []
        guard = Guard(mode="warn", tool_blocklist=["dangerous"],
                      on_block=lambda d: blocked.append(d))
        guard.before_tool("dangerous", {})
        assert len(blocked) == 0


@pytest.mark.filterwarnings("ignore::FutureWarning")
class TestGuardModeShadow:
    """Shadow mode allows all actions while preserving original_action."""

    def test_shadow_downgrades_block_to_allow(self):
        guard = Guard(mode="shadow", tool_blocklist=["dangerous"])
        d = guard.before_tool("dangerous", {})
        assert d.action == "allow"
        assert d.original_action == "block"
        assert d.mode == "shadow"

    def test_shadow_downgrades_warn_to_allow(self):
        guard = Guard(mode="shadow", default_action="warn")
        d = guard.before_tool("unknown_tool", {})
        assert d.action == "allow"
        assert d.original_action == "warn"

    def test_shadow_no_blocked_tool_error(self):
        guard = Guard(mode="shadow", tool_blocklist=["dangerous"])

        @guard.protect
        def dangerous():
            return "executed"

        result = dangerous()
        assert result == "executed"

    def test_shadow_no_callbacks(self):
        blocked = []
        warned = []
        guard = Guard(mode="shadow", tool_blocklist=["dangerous"],
                      on_block=lambda d: blocked.append(d),
                      on_warn=lambda d: warned.append(d))
        guard.before_tool("dangerous", {})
        assert len(blocked) == 0
        assert len(warned) == 0

    def test_shadow_after_tool_still_redacts(self):
        """PII redaction in after_tool still applies even in shadow mode."""
        guard = Guard(mode="shadow", pii_action="block")
        d = guard.after_tool("search", "Found: admin@secret.com")
        assert d.action == "redact_result"
        assert "admin@secret.com" not in str(d.redacted_result)

    def test_shadow_after_tool_mode_recorded(self):
        guard = Guard(mode="shadow", pii_action="block")
        d = guard.after_tool("search", "Found: admin@secret.com")
        assert d.mode == "shadow"
        assert d.original_action == "redact_result"


class TestProtectDeprecated:
    def test_protect_warns_future(self):
        guard = Guard(default_action="allow")
        with pytest.warns(FutureWarning, match="guard.tool"):
            @guard.protect
            def my_func():
                return "ok"

    def test_protect_still_works(self):
        guard = Guard(default_action="allow")
        with pytest.warns(FutureWarning):
            @guard.protect
            def my_func():
                return "ok"
        assert my_func() == "ok"


class TestGuardToolDecorator:
    """Tests for the unified guard.tool() decorator."""

    def test_sync_function(self):
        guard = Guard(default_action="allow")

        @guard.tool()
        def my_tool(x):
            return f"result: {x}"

        assert my_tool(x="hello") == "result: hello"

    def test_sync_function_bare(self):
        """@guard.tool without parens."""
        guard = Guard(default_action="allow")

        @guard.tool
        def my_tool(x):
            return f"result: {x}"

        assert my_tool(x="hello") == "result: hello"

    @pytest.mark.asyncio
    async def test_async_function(self):
        guard = Guard(default_action="allow")

        @guard.tool()
        async def my_tool(x):
            return f"result: {x}"

        result = await my_tool(x="hello")
        assert result == "result: hello"

    def test_blocked_raises_blocked_tool_error(self):
        guard = Guard(tool_blocklist=["dangerous"])

        @guard.tool()
        def dangerous():
            return "nope"

        with pytest.raises(BlockedToolError) as exc_info:
            dangerous()
        assert exc_info.value.decision.action == "block"

    def test_yaml_tool_lookup(self):
        """Function name maps to YAML tools: section."""
        guard = Guard(
            mode="shadow",
            domain_allowlist=["global.com"],
            block_egress=True,
            tools={
                "send_email": {
                    "domain_allowlist": ["mail.internal"],
                    "mode": "enforce",
                },
            },
        )

        @guard.tool()
        def send_email(url):
            return "sent"

        with pytest.raises(BlockedToolError) as exc_info:
            send_email(url="https://evil.com/api")
        assert exc_info.value.decision.policy_id == "domain_allowlist"

    def test_name_override(self):
        guard = Guard(
            tools={
                "email_sender": {"mode": "enforce", "domain_allowlist": ["mail.internal"], "block_egress": True},
            },
            block_egress=True,
        )

        @guard.tool(name="email_sender")
        def send_email_v2(url):
            return "sent"

        with pytest.raises(BlockedToolError):
            send_email_v2(url="https://evil.com/api")

    def test_capabilities_override(self):
        guard = Guard(
            capability_policy={"shell_exec": "block"},
            tools={"my_tool": {"capabilities": ["file_read"]}},
        )

        @guard.tool(capabilities=["shell_exec"])
        def my_tool(cmd):
            return "output"

        with pytest.raises(BlockedToolError):
            my_tool(cmd="ls")

    def test_unregistered_tool_uses_global(self):
        guard = Guard(default_action="allow")

        @guard.tool()
        def unknown_func():
            return "ok"

        assert unknown_func() == "ok"

    def test_result_redaction(self):
        guard = Guard(pii_action="block")

        @guard.tool()
        def search():
            return "Found: admin@secret.com"

        result = search()
        assert "admin@secret.com" not in result
        assert "[EMAIL]" in result

    def test_audit_logging(self):
        from asr.audit import AuditLogger
        events = []
        audit = AuditLogger(output=events.append)
        guard = Guard(default_action="allow", pii_action="off", audit=audit)

        @guard.tool()
        def my_tool(x):
            return "ok"

        my_tool(x="test")
        assert len(events) == 2
        assert events[0]["event_type"] == "guard_before"
        assert events[1]["event_type"] == "guard_after"

    def test_audit_per_tool_override(self):
        from asr.audit import AuditLogger
        global_events = []
        tool_events = []
        global_audit = AuditLogger(output=global_events.append)
        tool_audit = AuditLogger(output=tool_events.append)
        guard = Guard(default_action="allow", pii_action="off", audit=global_audit)

        @guard.tool(audit=tool_audit)
        def my_tool(x):
            return "ok"

        my_tool(x="test")
        assert len(global_events) == 0
        assert len(tool_events) == 2

    def test_blocked_error_has_context(self):
        guard = Guard(
            block_egress=True,
            domain_allowlist=["safe.com"],
            tools={
                "send_email": {
                    "domain_allowlist": ["mail.internal"],
                },
            },
        )

        @guard.tool()
        def send_email(url):
            return "sent"

        with pytest.raises(BlockedToolError) as exc_info:
            send_email(url="https://evil.com/api")
        err = exc_info.value
        assert "evil.com" in str(err)
        d = err.to_dict()
        assert "details" in d
