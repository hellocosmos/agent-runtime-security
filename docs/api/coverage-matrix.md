# Coverage Matrix

What the Agent Runtime Security API extension blocks, warns on, and does not try to solve yet.

---

## Coverage by Threat Type

### Action Layer — strongest coverage

| Threat | Response | How |
|--------|----------|-----|
| Unauthorized outbound data transfer | **Block** | `/decide` egress policy with `domain_allowlist` |
| High-risk tools such as shell, eval, or destructive DB actions | **Block** | `/decide` tool blocklist |
| Unauthorized file access | **Block** | `/decide` file path allowlist |
| Sensitive capabilities such as credential access or admin actions | **Block/Warn** | `/decide` capability policy |
| Tool arguments containing PII | **Block/Warn** | `/decide` PII detection |
| Tool results containing PII | **Redact** | `/redact` output redaction |
| Webhook-based exfiltration | **Detect** | `/scan` `webhook_exfil` |
| Channel-based exfiltration to Discord, Telegram, Gist, cloud upload URLs, or presigned URLs | **Detect** | `/scan` extended exfil patterns when sensitive exfil context is present |
| Credential harvesting phrases | **Detect** | `/scan` `credential_harvest` |
| Secret bundle or secret-file references | **Detect** | `/scan` `credential_bundle_dump`, `env_secret_reference` |
| Privilege-escalation phrases | **Detect** | `/scan` `privilege_escalation` |
| Consent bypass and bulk archive export prompts | **Detect** | `/scan` `consent_bypass_phrase`, `bulk_archive_export` |

### Perception Layer — strong coverage

| Threat | Response | How |
|--------|----------|-----|
| Injection hidden in CSS-hidden text | **Detect** | `/scan` `css_hidden_text` |
| Injection hidden in HTML comments | **Detect** | `/scan` `html_comment_injection` |
| Injection hidden in metadata | **Detect** | `/scan` `metadata_injection` |
| Injection hidden in markdown links | **Detect** | `/scan` `markdown_link_payload` |
| Prompt-injection keywords | **Detect** | `/scan` `prompt_injection_keywords` |
| Base64-encoded instructions | **Detect** | `/scan` `base64_encoded_instruction` |
| Invisible Unicode manipulation | **Detect** | `/scan` `invisible_unicode` |
| Role override attempts | **Detect** | `/scan` `role_override_attempt` |
| Exfiltration prompts | **Detect** | `/scan` `data_exfil_phrase` |
| Encoding-bypass attempts | **Detect** | `/scan` `encoded_bypass` |

### Injection Defense — conditional coverage

| Threat | Response | How | Constraint |
|--------|----------|-----|------------|
| SQL injection patterns | **Detect** | `/scan` `sql_injection` | Requires stronger injection indicators, not generic DML |
| NoSQL injection patterns | **Detect** | `/scan` `nosql_injection` | Limited to JSON-object style contexts |
| Shell command injection | **Detect** | `/scan` `command_injection` | |
| Directory traversal | **Detect** | `/scan` `path_traversal` | |
| SSRF | **Detect** | `/scan` `ssrf_attempt` | Focused on metadata endpoints and internal services |

### Infrastructure Signals — partial coverage

| Threat | Response | How |
|--------|----------|-----|
| JWT exposure | **Detect** | `/scan` `jwt_exposure` |
| Internal IP URL targets | **Detect** | `/scan` `internal_ip_reference` in URL contexts |
| Log injection or forging phrases | **Detect** | `/scan` `log_injection` |
| Suspicious shortened or direct-IP URLs | **Detect** | `/scan` `suspicious_url` |

---

## What The ASR API Does Not Cover Yet

| Area | Status | Why |
|------|--------|-----|
| Memory poisoning | Not covered | Runtime access to agent memory layers is outside the current scope |
| Multi-agent systemic attacks | Not covered | The system does not observe interactions across separate agents |
| Dynamic cloaking | Not covered | Static pattern checks cannot fully catch payloads that mutate at execution time |
| Persona manipulation and subtle biased phrasing | Not covered | This would require deeper semantic analysis beyond the current regex-focused layer |
| Steganographic payloads | Not covered | Image and media steganography is out of scope |
| Zero-day injection techniques | Partial | Known patterns are covered; novel attacks need pattern updates |
| Full semantic understanding of intent | Not covered | The API does not currently use LLM-based semantic classification |

---

## Coverage by Endpoint

| Endpoint | Primary role | Main coverage |
|----------|--------------|---------------|
| `/v1/scan` | Input inspection | Injection signals, bypass attempts, exfiltration prompts, suspicious URLs |
| `/v1/decide` | Pre-execution decision | Outbound transfer control, tool gating, file path control, argument-side PII exposure |
| `/v1/redact` | Output protection | PII masking across 17 profiles and multiple regional/payment formats |

---

## Alignment with DeepMind's Framework

Compared with the six attack layers described in [Google DeepMind's *AI Agent Traps*](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438):

| Layer | Coverage | Notes |
|-------|----------|-------|
| Perception | **Strong** | Hidden payload and injection pattern coverage |
| Action | **Strongest** | Policy evaluation, egress control, and result redaction |
| Reasoning | Partial | Indirect protection through prompt-injection pattern checks |
| Memory | Not covered | No direct runtime access to memory layers |
| Multi-agent | Not covered | No cross-agent visibility |
| Human oversight | Not covered | Outside the current runtime API scope |

**Bottom line:** Agent Runtime Security is strongest in the Perception and Action layers, where tools run, data moves, and damage becomes operationally real.
