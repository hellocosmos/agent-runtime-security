# Preset Catalog

Detailed reference for the 17 policy presets. Use these names in the `policy_preset` field.

---

## General Presets (4)

### `default`

| Item | Value |
|------|-------|
| **Target** | Generic starting preset |
| **Mode** | `enforce` |
| **Egress** | block (`api.internal.com` allowlisted) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval` |
| **Default action** | `warn` |

The loosest preset. Good for initial testing or as the base for a custom policy.

---

### `mcp-server`

| Item | Value |
|------|-------|
| **Target** | Teams exposing internal tools through MCP |
| **Mode** | `enforce` |
| **Egress** | block (internal infrastructure plus Notion, Jira, Slack) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `subprocess_run`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `create_user`, `reset_password` (13 total) |
| **Capability block** | `network_send`, `webhook_call`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `filesystem_delete`, `database_delete`, `bulk_export` |
| **Capability warn** | `email_send`, `filesystem_write`, `database_write` |
| **File paths** | `/srv/mcp`, `/tmp/mcp-safe`, `/home/agent/workspace` |
| **Default action** | `warn` |

**Core posture:** block uncontrolled egress and hard-stop high-risk tools and capabilities.

---

### `internal-agent`

| Item | Value |
|------|-------|
| **Target** | Internal assistants for docs, scheduling, and business workflows |
| **Mode** | `enforce` |
| **Egress** | block (internal infrastructure plus work SaaS and SSO) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions` (10 total) |
| **Default action** | `warn` |

Compared with `mcp-server`, this preset is slightly looser and better aligned to employee-facing internal assistants.

---

### `customer-support`

| Item | Value |
|------|-------|
| **Target** | Customer support assistants for email, CRM, and helpdesk workflows |
| **Mode** | **`warn`** |
| **Egress** | block (mail, CRM, helpdesk, support, SMTP domains only) |
| **PII** | **`block`** |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `delete_customer`, `export_all_customers`, `bulk_delete` (12 total) |
| **Default action** | `warn` |

**Core posture:** aggressive PII protection with warn-mode rollout to avoid disrupting support operations too early.

---

## Industry Presets (8)

### `finance`

| Item | Value |
|------|-------|
| **Target** | Finance and fintech agents for payments, accounts, and trading |
| **Mode** | `enforce` |
| **Egress** | block (internal finance systems plus Stripe, PayPal, Adyen, reporting endpoints) |
| **PII** | **`block`** |
| **Blocklist** | base 9 tools plus `bulk_transfer`, `wire_transfer`, `update_account_limits`, `create_card`, `close_account` (14 total) |
| **Capability block** | `network_send`, `webhook_call`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `filesystem_delete`, `database_delete`, `bulk_export`, `account_modify` |
| **Capability warn** | `email_send`, `filesystem_write`, `database_write`, `payment_process`, `fund_transfer`, `trading_execute` |
| **Regulatory context** | PCI DSS, SOX, financial compliance |

---

### `healthcare`

| Item | Value |
|------|-------|
| **Target** | Healthcare assistants for patient records, EMR, and care workflows |
| **Mode** | `enforce` |
| **Egress** | block (EMR, PACS, HL7/FHIR, medication systems) |
| **PII** | **`block`** |
| **Blocklist** | base 9 tools plus `delete_patient_record`, `modify_prescription`, `export_patient_data`, `bulk_delete`, `merge_patient_records` (14 total) |
| **Capability warn** | `patient_data_read`, `patient_data_write`, `prescription_read`, `lab_result_access` |
| **Regulatory context** | HIPAA, HITECH |

---

### `devops`

| Item | Value |
|------|-------|
| **Target** | DevOps and CI/CD agents |
| **Mode** | `enforce` |
| **Egress** | block (GitHub, GitLab, Docker, cloud, monitoring, package registries allowlisted) |
| **PII** | `warn` |
| **Blocklist** | `eval`, `exec`, `sudo`, `delete_database`, `drop_table`, `destroy_cluster`, `delete_namespace`, `modify_iam`, `delete_bucket`, `rotate_root_key` (10 total) |
| **Capability warn** | `shell_exec`, `network_send`, `webhook_call`, `credential_access`, `secret_access`, `filesystem_write`, `filesystem_delete`, `database_write`, `bulk_export`, `deploy`, `infra_provision`, `config_change` |
| **Capability block** | `admin_action`, `permission_change`, `database_delete`, `infra_destroy` |

**Core posture:** shell access is warning-only because execution is often required, but destructive infrastructure actions stay blocked.

---

### `data-pipeline`

| Item | Value |
|------|-------|
| **Target** | ETL, analytics, and data pipeline agents |
| **Mode** | `enforce` |
| **Egress** | block (internal data systems plus BigQuery, Redshift, Snowflake) |
| **PII** | `warn` |
| **Blocklist** | base 7 tools plus `drop_database`, `truncate_all_tables`, `delete_dataset` (10 total) |
| **Capability warn** | `webhook_call`, `email_send`, `filesystem_write`, `filesystem_delete`, `database_write`, `bulk_export`, `query_execute`, `data_transform` |
| **Capability block** | `network_send`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `database_delete`, `schema_modify` |

**Core posture:** data export is warning-only because export is often a real job requirement, but uncontrolled network egress stays blocked.

---

### `hr-agent`

| Item | Value |
|------|-------|
| **Target** | HR assistants for recruiting, payroll, and employee records |
| **Mode** | `enforce` |
| **Egress** | block (internal HR systems plus Workday, BambooHR, Greenhouse, SSO) |
| **PII** | **`block`** |
| **Blocklist** | base 9 tools plus `delete_employee`, `modify_salary`, `modify_compensation`, `export_all_employees`, `bulk_delete`, `modify_access_level` (15 total) |
| **Capability warn** | `email_send`, `filesystem_write`, `database_write`, `employee_data_read`, `salary_access`, `performance_access` |

---

### `legal`

| Item | Value |
|------|-------|
| **Target** | Legal and compliance assistants |
| **Mode** | `enforce` |
| **Egress** | block (legal systems plus Westlaw, LexisNexis, DocuSign) |
| **PII** | **`block`** |
| **Blocklist** | base 9 tools plus `delete_contract`, `delete_case`, `modify_evidence`, `bulk_delete`, `export_all_contracts`, `share_externally` (15 total) |
| **Capability block** | `filesystem_delete` |

**Core posture:** file deletion is blocked to preserve legal evidence and contract records.

---

### `ecommerce`

| Item | Value |
|------|-------|
| **Target** | Ecommerce agents for orders, inventory, payments, and shipping |
| **Mode** | `enforce` |
| **Egress** | block (internal systems plus Stripe, PayPal, Toss, Inicis, carriers, marketing tools) |
| **PII** | **`block`** |
| **Blocklist** | base 9 tools plus `delete_all_orders`, `modify_price_global`, `bulk_refund`, `export_all_customers`, `modify_payment_config` (14 total) |
| **Capability warn** | `network_send`, `webhook_call`, `email_send`, `filesystem_write`, `database_write`, `order_modify`, `price_modify`, `refund_process`, `inventory_modify`, `promotion_modify` |

---

### `research`

| Item | Value |
|------|-------|
| **Target** | Research and R&D agents |
| **Mode** | `enforce` |
| **Egress** | block (academic sources, GitHub, cloud compute, package registries allowlisted) |
| **PII** | `warn` |
| **Blocklist** | `eval`, `exec`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `share_ip_externally`, `publish_unpublished`, `export_source_code` (10 total) |
| **Capability warn** | `shell_exec`, `network_send`, `webhook_call`, `email_send`, `filesystem_write`, `filesystem_delete`, `database_write`, `bulk_export`, `code_execute`, `data_download`, `model_train` |

**Core posture:** the loosest industry preset. It keeps research flexibility while still focusing on IP and exfiltration controls.

---

## Preset Comparison Summary

| Preset | Mode | PII | `shell_exec` | `bulk_export` | `network_send` |
|--------|------|-----|--------------|---------------|----------------|
| `default` | `enforce` | `warn` | block(list) | - | warn(cap) |
| `mcp-server` | `enforce` | `warn` | block(list) | block(cap) | block(cap) |
| `internal-agent` | `enforce` | `warn` | block(list) | block(cap) | block(cap) |
| `customer-support` | **`warn`** | **`block`** | block(list) | block(cap) | warn(cap) |
| `finance` | `enforce` | **`block`** | block(list) | block(cap) | block(cap) |
| `healthcare` | `enforce` | **`block`** | block(list) | block(cap) | block(cap) |
| `devops` | `enforce` | `warn` | **warn(cap)** | warn(cap) | warn(cap) |
| `data-pipeline` | `enforce` | `warn` | block(list) | **warn(cap)** | block(cap) |
| `hr-agent` | `enforce` | **`block`** | block(list) | block(cap) | block(cap) |
| `legal` | `enforce` | **`block`** | block(list) | block(cap) | block(cap) |
| `ecommerce` | `enforce` | **`block`** | block(list) | block(cap) | warn(cap) |
| `research` | `enforce` | `warn` | **warn(cap)** | **warn(cap)** | warn(cap) |

---

## Role Presets (5)

### `developer-agent`

| Item | Value |
|------|-------|
| **Target** | Coding agents, repo assistants, and build/test automation |
| **Mode** | `enforce` |
| **Egress** | block (developer tooling and package registries only) |
| **PII** | `warn` |
| **Blocklist** | `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `modify_iam`, `create_user`, `reset_password` |
| **Capability warn** | `shell_exec`, `network_send`, `webhook_call`, `filesystem_write`, `database_write`, `bulk_export` |
| **Capability block** | `email_send`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `database_delete` |

**Core posture:** allow normal developer workflows with warnings, but hard-stop secret access and privilege-changing actions.

---

### `browser-agent`

| Item | Value |
|------|-------|
| **Target** | Browser-using agents that navigate pages, fill forms, and download files |
| **Mode** | `enforce` |
| **Egress** | block (internal apps plus selected SaaS) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `extract_cookies`, `export_session`, `read_local_storage`, `capture_credentials` |
| **Capability warn** | `network_send`, `form_submit`, `file_download`, `screenshot`, `clipboard_access`, `filesystem_write` |
| **Capability block** | `webhook_call`, `email_send`, `file_upload`, `credential_access`, `secret_access`, `cookie_access`, `session_access`, `shell_exec`, `filesystem_delete`, `admin_action`, `permission_change`, `database_write`, `database_delete`, `bulk_export` |

**Core posture:** allow supervised browsing flows while blocking credential, cookie, and upload-heavy exfil paths.

---

### `sales-ops-agent`

| Item | Value |
|------|-------|
| **Target** | CRM, outbound email, pipeline management, and enrichment workflows |
| **Mode** | `enforce` |
| **Egress** | block (CRM, email, enrichment, collaboration domains only) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `export_all_contacts`, `bulk_contact_enrichment`, `delete_pipeline`, `modify_pricing_rules` |
| **Capability warn** | `network_send`, `webhook_call`, `email_send`, `database_write`, `filesystem_write`, `crm_write`, `pipeline_modify` |
| **Capability block** | `credential_access`, `secret_access`, `admin_action`, `permission_change`, `database_delete`, `bulk_export`, `shell_exec`, `filesystem_delete`, `contact_export` |

**Core posture:** keep normal CRM updates and outreach usable, but hard-stop bulk contact extraction and privileged changes.

---

### `security-ops-agent`

| Item | Value |
|------|-------|
| **Target** | SOC / SecOps agents for alert triage, IOC lookup, and incident response |
| **Mode** | `enforce` |
| **Egress** | block (SIEM, SOAR, threat intel, and internal security systems only) |
| **PII** | `warn` |
| **Blocklist** | `eval`, `exec`, `sudo`, `admin_api`, `modify_permissions`, `modify_iam`, `create_user`, `reset_password`, `credential_dump`, `export_secrets`, `delete_evidence`, `delete_logs`, `network_scan`, `port_scan`, `exploit_execute` |
| **Capability warn** | `network_send`, `webhook_call`, `email_send`, `shell_exec`, `filesystem_write`, `database_write`, `bulk_export`, `ioc_lookup`, `siem_query`, `alert_triage`, `incident_modify` |
| **Capability block** | `filesystem_delete`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `database_delete` |

**Core posture:** let analysts query and triage, but block credential dumping, evidence deletion, and active exploitation paths.

---

### `executive-assistant`

| Item | Value |
|------|-------|
| **Target** | Calendar, email drafting, document lookup, and travel-planning assistants |
| **Mode** | `enforce` |
| **Egress** | block (productivity, email, travel, collaboration, and internal domains only) |
| **PII** | `warn` |
| **Blocklist** | `shell_exec`, `eval`, `exec`, `os_command`, `sudo`, `admin_api`, `delete_database`, `drop_table`, `modify_permissions`, `bulk_share`, `export_all_contacts`, `modify_access_level` |
| **Capability warn** | `network_send`, `email_send`, `filesystem_write`, `calendar_modify`, `document_share`, `travel_booking` |
| **Capability block** | `webhook_call`, `shell_exec`, `filesystem_delete`, `credential_access`, `secret_access`, `admin_action`, `permission_change`, `database_write`, `database_delete`, `bulk_export` |

**Core posture:** preserve useful assistant workflows while blocking bulk sharing, shell execution, and sensitive data export.
