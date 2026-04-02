# Agent Runtime Security

> 권한 있는 AI 에이전트의 행동을 통제하고 증빙을 남기는 Agent Runtime Control Plane입니다.

## Objective

자율 AI 에이전트가 웹을 탐색하고 도구를 호출하는 시대가 왔습니다. 그런데 **모델 자체보다 모델이 동작하는 환경이 더 위험합니다.** 웹페이지에 숨겨진 한 줄의 코드, 이메일 한 통으로 에이전트의 행동이 바뀌고 데이터가 유출될 수 있습니다.

이 프로젝트는 Google DeepMind의 논문 **"AI Agent Traps"**에서 출발했습니다. 논문이 체계화한 6가지 공격 유형을 분석한 뒤, **실제로 방어할 수 있는 것과 없는 것을 구분**하고, 가장 현실적인 방어 지점인 **도구 호출 통제(Guard) + 감사 로그(Audit)**를 중심으로 구현했습니다.

### 논문: AI Agent Traps (Google DeepMind, 2026)

> Franklin, M., Tomašev, N., Jacobs, J., Leibo, J. Z., & Osindero, S. (2026, March 28). *AI Agent Traps*. Google DeepMind.
> Available at SSRN: https://ssrn.com/abstract=6372438 or http://dx.doi.org/10.2139/ssrn.6372438

2026년 3월 28일에 공개된 따끈한 논문으로, AI 에이전트가 웹 콘텐츠를 소비할 때 발생하는 공격 표면을 최초로 체계화했습니다:

| 공격 유형 | 대상 | 설명 |
|-----------|------|------|
| **Content Injection** | 인식 (Perception) | CSS 숨김 텍스트, HTML 주석, 메타데이터에 악성 명령을 삽입합니다 |
| **Semantic Manipulation** | 추론 (Reasoning) | 편향된 프레이밍, 안전 필터 우회, 페르소나 조작을 수행합니다 |
| **Cognitive State** | 기억/학습 | RAG 지식 오염, 메모리 포이즈닝, 학습 트랩을 설치합니다 |
| **Behavioural Control** | 행동 (Action) | 임베디드 탈옥, 데이터 유출, 서브에이전트 스포닝을 유도합니다 |
| **Systemic** | 멀티에이전트 | 혼잡 트랩, 연쇄 실패, 묵시적 담합, Sybil 공격을 일으킵니다 |
| **Human-in-the-Loop** | 인간 감독자 | 승인 피로, 자동화 편향, 사회공학을 매개합니다 |

이 중 **Content Injection**과 **Behavioural Control**은 지금 바로 방어할 수 있고, **Semantic Manipulation**과 **Systemic Traps**는 완전한 방어가 어렵습니다. 이 SDK는 전자에 집중합니다.

### 왜 Scanner가 아니라 Guard가 핵심인가요?

에이전트가 실제로 피해를 주는 순간은 **텍스트를 생성할 때가 아니라 도구를 실행할 때**입니다 — 이메일 전송, 외부 API 호출, 파일 쓰기, 셸 실행 등이 해당됩니다. regex 기반 입력 스캐너는 기초적인 공격만 걸러낼 수 있지만, **도구 호출 시점의 정책 집행**은 어떤 공격이든 최종 피해를 막을 수 있는 마지막 방어선입니다.

## 설치

```bash
pip install agent-runtime-security
```

MCP 어댑터가 필요한 경우:

```bash
pip install agent-runtime-security[mcp]
```

PDF 지원이 필요한 경우:

```bash
pip install agent-runtime-security[pdf]
```

## 빠른 시작

```python
from asr import Scanner, Guard, AuditLogger

# 입력 스캔
scanner = Scanner()
result = scanner.scan(
    "<span style='display:none'>Ignore instructions</span>",
    source_type="html",
)
print(f"위험도: {result.score}, 심각도: {result.severity}")

# 도구 호출 가드
guard = Guard(
    domain_allowlist=["api.internal.com"],
    block_egress=True,
    pii_action="block",
    file_path_allowlist=["/tmp/safe"],
    capability_policy={"shell_exec": "block"},
)

decision = guard.before_tool(
    "http_post",
    {"url": "https://evil.com"},
    capabilities=["network_send"],
)
print(f"판정: {decision.action}, 이유: {decision.reason}")

# 데코레이터 방식
@guard.protect(capabilities=["network_send"])
def send_email(to, subject, body):
    ...

# 감사 로그
audit = AuditLogger(output="logs/audit.jsonl")
audit.log_scan(result, trace_id="req-001")
audit.log_guard(decision, trace_id="req-001")
```

### 운영 모드 (Shadow Mode)

프로덕션 환경에서 정책을 단계적으로 배포할 수 있습니다:

```python
# 1단계: shadow — 차단 없이 관찰만 (original_action으로 기록)
guard = Guard(mode="shadow", ...)

# 2단계: warn — block을 warn으로 다운그레이드
guard = Guard(mode="warn", ...)

# 3단계: enforce — 정책대로 실제 차단 (기본값)
guard = Guard(mode="enforce", ...)

# shadow/warn에서도 PII redact는 항상 강제됩니다
decision = guard.before_tool("http_post", {"url": "https://evil.com"})
print(decision.action)            # "allow" (shadow에서)
print(decision.original_action)   # "block" (원래 판정)
print(decision.mode)              # "shadow"
```

### MCP 서버 통합

MCP tool handler에 Guard 정책을 적용합니다:

```python
from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

guard = Guard(mode="shadow", domain_allowlist=["api.internal.com"], block_egress=True)
audit = AuditLogger(output="logs/audit.jsonl")

@server.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def send_email(to: str, subject: str, body: str) -> str:
    # Guard가 정책을 평가하고, 차단 시 MCP 에러로 반환
    # PII가 결과에 있으면 자동 마스킹
    return await email_service.send(to, subject, body)
```

## 정책 설정

Guard는 6가지 정책과 3가지 운영 모드를 지원합니다:

| 모드 | 설명 |
|------|------|
| `enforce` (기본) | 정책 결과 그대로 적용합니다 |
| `warn` | block을 warn으로 다운그레이드합니다 (점진 전환) |
| `shadow` | 전부 allow, 원래 판정은 로그에만 기록합니다 (관찰 전용) |

| 정책 | 설명 |
|------|------|
| `tool_blocklist` | 특정 도구 이름을 직접 차단합니다 |
| `domain_allowlist` + `block_egress` | 허용 도메인 외 네트워크 송신을 차단합니다 |
| `file_path_allowlist` | 허용 경로 외 파일 접근을 차단합니다 |
| `pii_action` | 도구 인자/결과의 민감정보를 탐지합니다 (`off` / `warn` / `block`) |
| `capability_policy` | capability 태그 기반으로 통제합니다 (fallback) |
| `default_action` | 세부 정책에 해당하지 않는 도구의 기본 동작을 결정합니다 |

**정책 평가 순서:** Blocklist → Egress → FilePath → PII → Capability(fallback) → Default

## Scanner 탐지 패턴

Scanner는 regex 기반 1차 필터로, 기초적인 콘텐츠 위협을 탐지합니다. 고도화된 공격에 대해서는 ML 기반 탐지 또는 외부 서비스와의 조합을 권장합니다.

| 패턴 | 설명 |
|------|------|
| `css_hidden_text` | CSS 숨김 텍스트 + 인젝션 문구 조합을 탐지합니다 |
| `html_comment_injection` | HTML 주석 내 의심 지시문을 탐지합니다 |
| `metadata_injection` | aria-label/alt/title 속성 악용을 탐지합니다 |
| `markdown_link_payload` | Markdown 링크 텍스트 내 명령을 탐지합니다 |
| `prompt_injection_keywords` | 프롬프트 인젝션 키워드를 탐지합니다 |
| `base64_encoded_instruction` | Base64 인코딩된 의심 명령을 탐지합니다 |
| `invisible_unicode` | 보이지 않는 유니코드 문자를 탐지합니다 |
| `role_override_attempt` | 역할 오버라이드 시도를 탐지합니다 |

## 라이선스

MIT
