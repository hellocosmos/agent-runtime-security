# Agent Runtime Security

> 권한 있는 AI 에이전트의 행동을 통제하고 증빙을 남기는 Agent Runtime Control Plane

## Objective

자율 AI 에이전트가 웹을 탐색하고 도구를 호출하는 시대가 왔다. 그런데 **모델 자체보다 모델이 동작하는 환경이 더 위험하다.** 웹페이지에 숨겨진 한 줄의 코드, 이메일 한 통으로 에이전트의 행동이 바뀌고 데이터가 유출될 수 있다.

이 프로젝트는 Google DeepMind의 논문 **"AI Agent Traps"**에서 출발했다. 논문이 체계화한 6가지 공격 유형을 분석한 뒤, **실제로 방어할 수 있는 것과 없는 것을 구분**하고, 가장 현실적인 방어 지점인 **도구 호출 통제(Guard) + 감사 로그(Audit)**를 중심으로 구현했다.

### 논문: AI Agent Traps (Google DeepMind, 2025)

> Franklin, M., Tomašev, N., Jacobs, J., Leibo, J. Z., & Osindero, S. (2025). *AI Agent Traps*. Google DeepMind. SSRN: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438

논문은 AI 에이전트가 웹 콘텐츠를 소비할 때 발생하는 공격 표면을 최초로 체계화했다:

| 공격 유형 | 대상 | 설명 |
|-----------|------|------|
| **Content Injection** | 인식 (Perception) | CSS 숨김 텍스트, HTML 주석, 메타데이터에 악성 명령 삽입 |
| **Semantic Manipulation** | 추론 (Reasoning) | 편향된 프레이밍, 안전 필터 우회, 페르소나 조작 |
| **Cognitive State** | 기억/학습 | RAG 지식 오염, 메모리 포이즈닝, 학습 트랩 |
| **Behavioural Control** | 행동 (Action) | 임베디드 탈옥, 데이터 유출, 서브에이전트 스포닝 |
| **Systemic** | 멀티에이전트 | 혼잡 트랩, 연쇄 실패, 묵시적 담합, Sybil 공격 |
| **Human-in-the-Loop** | 인간 감독자 | 승인 피로, 자동화 편향, 사회공학 매개 |

이 중 **Content Injection**과 **Behavioural Control**은 지금 바로 방어 가능하고, **Semantic Manipulation**과 **Systemic Traps**는 완전 방어가 어렵다. 이 SDK는 전자에 집중한다.

### 왜 Scanner가 아니라 Guard가 핵심인가

에이전트가 실제로 피해를 주는 순간은 **텍스트를 생성할 때가 아니라 도구를 실행할 때**다 — 이메일 전송, 외부 API 호출, 파일 쓰기, 셸 실행. regex 기반 입력 스캐너는 기초적인 공격만 걸러내지만, **도구 호출 시점의 정책 집행**은 어떤 공격이든 최종 피해를 막을 수 있는 마지막 방어선이다.

## 설치

```bash
pip install agent-runtime-security
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

## 정책 설정

Guard는 6가지 정책을 지원합니다:

| 정책 | 설명 |
|------|------|
| `tool_blocklist` | 특정 도구 이름 직접 차단 |
| `domain_allowlist` + `block_egress` | 허용 도메인 외 네트워크 송신 차단 |
| `file_path_allowlist` | 허용 경로 외 파일 접근 차단 |
| `pii_action` | 도구 인자/결과의 민감정보 탐지 (`off` / `warn` / `block`) |
| `capability_policy` | capability 태그 기반 통제 (fallback) |
| `default_action` | 미등록 도구 기본 동작 |

**정책 평가 순서:** Blocklist → Egress → FilePath → PII → Capability(fallback) → Default

## Scanner 탐지 패턴

| 패턴 | 설명 |
|------|------|
| `css_hidden_text` | CSS 숨김 텍스트 + 인젝션 문구 조합 |
| `html_comment_injection` | HTML 주석 내 의심 지시문 |
| `metadata_injection` | aria-label/alt/title 속성 악용 |
| `markdown_link_payload` | Markdown 링크 텍스트 내 명령 |
| `prompt_injection_keywords` | 프롬프트 인젝션 키워드 |
| `base64_encoded_instruction` | Base64 인코딩된 의심 명령 |
| `invisible_unicode` | 보이지 않는 유니코드 문자 |
| `role_override_attempt` | 역할 오버라이드 시도 |

## 라이선스

MIT
