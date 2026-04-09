"""Preset 로드 + 행동 검증 테스트."""

from __future__ import annotations

from asr import Guard
from asr.api import available_policy_presets, load_policy_preset


ALL_PRESETS = [
    # 범용 (4종)
    "default",
    "internal-agent",
    "mcp-server",
    "customer-support",
    # 산업별 (8종)
    "finance",
    "healthcare",
    "devops",
    "data-pipeline",
    "hr-agent",
    "legal",
    "ecommerce",
    "research",
    # 역할별 (5종)
    "developer-agent",
    "browser-agent",
    "sales-ops-agent",
    "security-ops-agent",
    "executive-assistant",
]


def _load_guard(preset: str) -> Guard:
    return Guard.from_config(load_policy_preset(preset))


# ── 로드 테스트 ──────────────────────────────────────────────


def test_policy_presets_load_into_guard():
    for preset in ALL_PRESETS:
        config = load_policy_preset(preset)
        guard = Guard.from_config(config)

        assert config["version"] == 1
        assert guard is not None


def test_all_17_presets_exist():
    """17종 preset 파일이 모두 존재하는지 확인."""
    shipped_presets = set(available_policy_presets())
    for preset in ALL_PRESETS:
        assert preset in shipped_presets, f"Missing preset: {preset}"
    assert len(ALL_PRESETS) == 17


# ── 행동 테스트: preset 간 차별화 검증 ───────────────────────


class TestFinanceBehavior:
    def test_blocks_external_egress(self):
        """finance: 외부 도메인으로의 전송을 차단."""
        guard = _load_guard("finance")
        d = guard.before_tool("http_post", {"url": "https://evil.example/data"})
        assert d.action == "block"

    def test_blocks_blocklisted_tool(self):
        """finance: wire_transfer는 blocklist에 포함."""
        guard = _load_guard("finance")
        d = guard.before_tool("wire_transfer", {})
        assert d.action == "block"


class TestHealthcareBehavior:
    def test_blocks_external_egress(self):
        guard = _load_guard("healthcare")
        d = guard.before_tool("http_post", {"url": "https://external.example"})
        assert d.action == "block"

    def test_blocks_patient_record_delete(self):
        """healthcare: delete_patient_record는 blocklist에 포함."""
        guard = _load_guard("healthcare")
        d = guard.before_tool("delete_patient_record", {})
        assert d.action == "block"


class TestDevopsBehavior:
    def test_shell_exec_warns_not_blocks(self):
        """devops: shell_exec는 warn (block이 아님)."""
        guard = _load_guard("devops")
        d = guard.before_tool("run_script", {}, capabilities=["shell_exec"])
        assert d.action == "warn"

    def test_infra_destroy_blocks(self):
        """devops: infra_destroy capability는 block."""
        guard = _load_guard("devops")
        d = guard.before_tool("terraform_destroy", {}, capabilities=["infra_destroy"])
        assert d.action == "block"


class TestCustomerSupportBehavior:
    def test_mode_is_warn(self):
        """customer-support: warn 모드 (서비스 중단 방지)."""
        guard = _load_guard("customer-support")
        d = guard.before_tool("unknown_tool", {})
        # warn 모드에서는 block도 warn으로 다운그레이드
        assert d.action == "warn"


class TestMCPServerBehavior:
    def test_blocks_shell_exec(self):
        """mcp-server: shell_exec는 blocklist에 포함."""
        guard = _load_guard("mcp-server")
        d = guard.before_tool("shell_exec", {})
        assert d.action == "block"

    def test_blocks_unknown_domain(self):
        """mcp-server: 허용 도메인 외 전송 차단."""
        guard = _load_guard("mcp-server")
        d = guard.before_tool("http_post", {"url": "https://attacker.example/exfil"})
        assert d.action == "block"


class TestHRAgentBehavior:
    def test_blocks_salary_modification(self):
        """hr-agent: modify_salary는 blocklist에 포함."""
        guard = _load_guard("hr-agent")
        d = guard.before_tool("modify_salary", {})
        assert d.action == "block"

    def test_blocks_bulk_export(self):
        """hr-agent: bulk_export capability는 block."""
        guard = _load_guard("hr-agent")
        d = guard.before_tool("export_data", {}, capabilities=["bulk_export"])
        assert d.action == "block"


class TestLegalBehavior:
    def test_blocks_external_sharing(self):
        """legal: share_externally는 blocklist에 포함."""
        guard = _load_guard("legal")
        d = guard.before_tool("share_externally", {})
        assert d.action == "block"

    def test_blocks_evidence_deletion(self):
        """legal: filesystem_delete capability는 block (증거 보존)."""
        guard = _load_guard("legal")
        d = guard.before_tool("delete_file", {}, capabilities=["filesystem_delete"])
        assert d.action == "block"


class TestEcommerceBehavior:
    def test_blocks_bulk_refund(self):
        """ecommerce: bulk_refund는 blocklist에 포함."""
        guard = _load_guard("ecommerce")
        d = guard.before_tool("bulk_refund", {})
        assert d.action == "block"

    def test_stripe_not_blocked_by_allowlist(self):
        """ecommerce: api.stripe.com은 allowlist에 포함 → domain_allowlist로 차단되지 않음."""
        guard = _load_guard("ecommerce")
        d = guard.before_tool("charge", {"url": "https://api.stripe.com/v1/charges"})
        assert d.action == "allow"
        assert d.policy_id == "specific_policy"

    def test_unknown_domain_blocked_by_allowlist(self):
        """ecommerce: 허용 목록에 없는 도메인은 domain_allowlist로 차단."""
        guard = _load_guard("ecommerce")
        d = guard.before_tool("charge", {"url": "https://evil.example/steal"})
        assert d.action == "block"
        assert d.policy_id == "domain_allowlist"


class TestResearchBehavior:
    def test_warns_shell_exec(self):
        """research: shell_exec capability는 warn (실험 스크립트 허용)."""
        guard = _load_guard("research")
        d = guard.before_tool("run_experiment", {}, capabilities=["shell_exec"])
        assert d.action == "warn"

    def test_blocks_ip_sharing(self):
        """research: share_ip_externally는 blocklist에 포함."""
        guard = _load_guard("research")
        d = guard.before_tool("share_ip_externally", {})
        assert d.action == "block"


class TestDeveloperAgentBehavior:
    def test_warns_shell_exec(self):
        guard = _load_guard("developer-agent")
        d = guard.before_tool("run_script", {}, capabilities=["shell_exec"])
        assert d.action == "warn"

    def test_blocks_secret_access(self):
        guard = _load_guard("developer-agent")
        d = guard.before_tool("read_secret", {}, capabilities=["secret_access"])
        assert d.action == "block"

    def test_blocks_generic_email_tools(self):
        guard = _load_guard("developer-agent")
        d = guard.before_tool(
            "gmail_send",
            {"to": "someone@external.com"},
            capabilities=["email_send"],
        )
        assert d.action == "block"
        assert d.policy_id == "capability_policy"


class TestBrowserAgentBehavior:
    def test_warns_form_submit(self):
        guard = _load_guard("browser-agent")
        d = guard.before_tool("submit_form", {}, capabilities=["form_submit"])
        assert d.action == "warn"

    def test_blocks_file_upload(self):
        guard = _load_guard("browser-agent")
        d = guard.before_tool("upload_file", {}, capabilities=["file_upload"])
        assert d.action == "block"


class TestSalesOpsAgentBehavior:
    def test_warns_crm_write(self):
        guard = _load_guard("sales-ops-agent")
        d = guard.before_tool("update_crm", {}, capabilities=["crm_write"])
        assert d.action == "warn"

    def test_blocks_contact_export(self):
        guard = _load_guard("sales-ops-agent")
        d = guard.before_tool("export_contacts", {}, capabilities=["contact_export"])
        assert d.action == "block"


class TestSecurityOpsAgentBehavior:
    def test_warns_ioc_lookup(self):
        guard = _load_guard("security-ops-agent")
        d = guard.before_tool("run_triage", {}, capabilities=["ioc_lookup"])
        assert d.action == "warn"

    def test_blocks_credential_access(self):
        guard = _load_guard("security-ops-agent")
        d = guard.before_tool("dump_creds", {}, capabilities=["credential_access"])
        assert d.action == "block"


class TestExecutiveAssistantBehavior:
    def test_warns_travel_booking(self):
        guard = _load_guard("executive-assistant")
        d = guard.before_tool("book_travel", {}, capabilities=["travel_booking"])
        assert d.action == "warn"

    def test_blocks_bulk_export(self):
        guard = _load_guard("executive-assistant")
        d = guard.before_tool("export_all", {}, capabilities=["bulk_export"])
        assert d.action == "block"


class TestPresetDifferentiation:
    """preset 간 핵심 차별화 포인트 검증."""

    def test_devops_vs_mcp_shell_policy(self):
        """devops는 shell warn, mcp-server는 shell block."""
        devops = _load_guard("devops")
        mcp = _load_guard("mcp-server")

        d_devops = devops.before_tool("script", {}, capabilities=["shell_exec"])
        d_mcp = mcp.before_tool("script", {}, capabilities=["shell_exec"])

        assert d_devops.action == "warn"
        assert d_mcp.action == "block"

    def test_finance_vs_research_egress(self):
        """finance는 network_send block, research는 warn."""
        finance = _load_guard("finance")
        research = _load_guard("research")

        d_fin = finance.before_tool("post", {}, capabilities=["network_send"])
        d_res = research.before_tool("post", {}, capabilities=["network_send"])

        assert d_fin.action == "block"
        assert d_res.action == "warn"
