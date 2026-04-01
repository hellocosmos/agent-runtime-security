"""개별 정책 평가 테스트"""
from asr.policies import (
    evaluate_tool_blocklist, evaluate_egress, evaluate_file_path,
    evaluate_pii, evaluate_capability, evaluate_unknown_tool,
)


class TestToolBlocklist:
    def test_blocked_tool(self):
        result = evaluate_tool_blocklist("rm_rf", {}, blocklist=["rm_rf", "eval"])
        assert result is not None
        assert result["action"] == "block"

    def test_allowed_tool(self):
        result = evaluate_tool_blocklist("search", {}, blocklist=["rm_rf", "eval"])
        assert result is None


class TestEgress:
    def test_allowed_domain(self):
        result = evaluate_egress("http_post", {"url": "https://api.internal.com/data"},
                                domain_allowlist=["api.internal.com"], block_egress=True)
        assert result is None

    def test_blocked_domain(self):
        result = evaluate_egress("http_post", {"url": "https://evil.com/steal"},
                                domain_allowlist=["api.internal.com"], block_egress=True)
        assert result is not None and result["action"] == "block"

    def test_blocked_private_ip(self):
        result = evaluate_egress("http_post", {"url": "http://192.168.1.1/admin"},
                                domain_allowlist=[], block_egress=True)
        assert result is not None and result["action"] == "block"

    def test_blocked_localhost(self):
        result = evaluate_egress("http_post", {"url": "http://127.0.0.1:8080/api"},
                                domain_allowlist=[], block_egress=True)
        assert result is not None and result["action"] == "block"

    def test_egress_disabled(self):
        result = evaluate_egress("http_post", {"url": "https://evil.com"},
                                domain_allowlist=[], block_egress=False)
        assert result is None

    def test_no_url_in_args(self):
        """Egress는 URL 기반 전송만 검사"""
        result = evaluate_egress("send_email", {"to": "a@b.com", "body": "hello"},
                                domain_allowlist=[], block_egress=True)
        assert result is None

    def test_subdomain_allowed(self):
        result = evaluate_egress("http_post", {"url": "https://v2.api.internal.com/data"},
                                domain_allowlist=["*.api.internal.com"], block_egress=True)
        assert result is None


class TestFilePath:
    def test_allowed_path(self):
        result = evaluate_file_path("file_write", {"path": "/tmp/asr/output.txt"}, allowlist=["/tmp/asr"])
        assert result is None

    def test_blocked_path(self):
        result = evaluate_file_path("file_read", {"path": "/etc/passwd"}, allowlist=["/tmp/asr"])
        assert result is not None and result["action"] == "block"

    def test_sensitive_path_ssh(self):
        result = evaluate_file_path("file_read", {"path": "/home/user/.ssh/id_rsa"}, allowlist=["/home/user"])
        assert result is not None and result["action"] == "block"

    def test_sensitive_path_env(self):
        result = evaluate_file_path("file_read", {"path": "/app/.env"}, allowlist=["/app"])
        assert result is not None and result["action"] == "block"

    def test_path_traversal_blocked(self):
        """../로 allowlist 우회 시도 차단"""
        result = evaluate_file_path("file_read", {"path": "/tmp/asr/../../../etc/passwd"}, allowlist=["/tmp/asr"])
        assert result is not None and result["action"] == "block"

    def test_prefix_collision_blocked(self):
        """/tmp/asr_bad은 /tmp/asr의 자식이 아님"""
        result = evaluate_file_path("file_write", {"path": "/tmp/asr_bad/evil.txt"}, allowlist=["/tmp/asr"])
        assert result is not None and result["action"] == "block"

    def test_no_path_in_args(self):
        result = evaluate_file_path("search", {"query": "hello"}, allowlist=["/tmp"])
        assert result is None


class TestPiiPolicy:
    def test_block_pii(self):
        result = evaluate_pii("send_email", {"body": "email: admin@secret.com"}, pii_action="block")
        assert result is not None and result["action"] == "block"

    def test_warn_pii(self):
        result = evaluate_pii("send_email", {"body": "Contact: admin@secret.com"}, pii_action="warn")
        assert result is not None and result["action"] == "warn"

    def test_off_pii(self):
        result = evaluate_pii("send_email", {"body": "Contact: admin@secret.com"}, pii_action="off")
        assert result is None

    def test_no_pii(self):
        result = evaluate_pii("send_email", {"body": "Hello, how are you?"}, pii_action="block")
        assert result is None


class TestCapabilityPolicy:
    def test_block_capability(self):
        result = evaluate_capability(capabilities=["shell_exec"], policy={"shell_exec": "block", "network_send": "warn"})
        assert result is not None and result["action"] == "block"

    def test_warn_capability(self):
        result = evaluate_capability(capabilities=["network_send"], policy={"shell_exec": "block", "network_send": "warn"})
        assert result is not None and result["action"] == "warn"

    def test_allow_capability(self):
        result = evaluate_capability(capabilities=["file_read"], policy={"file_read": "allow"})
        assert result is not None and result["action"] == "allow"

    def test_no_capabilities(self):
        result = evaluate_capability(capabilities=None, policy={"shell_exec": "block"})
        assert result is None

    def test_unknown_capability_default_warn(self):
        result = evaluate_capability(capabilities=["unknown_cap"], policy={"shell_exec": "block"})
        assert result is not None and result["action"] == "warn"

    def test_most_restrictive_wins(self):
        result = evaluate_capability(capabilities=["file_read", "shell_exec"], policy={"file_read": "allow", "shell_exec": "block"})
        assert result is not None and result["action"] == "block"


class TestUnknownTool:
    def test_default_warn(self):
        result = evaluate_unknown_tool(default="warn")
        assert result["action"] == "warn"

    def test_default_block(self):
        result = evaluate_unknown_tool(default="block")
        assert result["action"] == "block"
