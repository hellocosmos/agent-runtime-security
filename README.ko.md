# Agent Runtime Security

[English](./README.md) | [한국어](./README.ko.md)

> 권한 있는 AI 에이전트의 도구 실행을 통제하고 증빙을 남기는 오픈소스 런타임 보안 SDK입니다.

Agent Runtime Security는 웹 탐색, API 호출, 파일 접근, 이메일 전송, MCP 도구 호출처럼 **실제 행동을 수행하는 AI 에이전트**를 대상으로, 위험한 도구 호출을 통제하고 민감정보를 보호하며 감사 로그를 남길 수 있게 해줍니다.

브랜드 메모: `TrapDefense`는 제품/사이트 브랜드이고, `Agent Runtime Security`는 오픈소스 SDK 및 저장소 이름입니다.

이 프로젝트는 Google DeepMind의 2026년 논문 [*AI Agent Traps*](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438)에서 출발했으며, 지금 당장 현실적으로 방어 가능한 영역에 집중합니다.

- 입력 단계의 기본적인 content injection 신호 탐지
- 도구 실행 시점의 behavioral control
- 보안 검토와 운영 전환을 위한 audit evidence

모든 에이전트 보안 문제를 해결한다고 주장하지 않고, **tool-using agent의 runtime control layer**를 명확한 범위로 둡니다.

## 왜 필요한가요?

문제는 모델만이 아닙니다.

도구를 쓰는 에이전트 시스템에서 실제 피해는 보통 아래 순간에 발생합니다.

- 외부 엔드포인트로 데이터를 전송할 때
- 잘못된 파일을 읽거나 쓸 때
- 위험한 명령을 실행할 때
- tool output으로 민감정보를 반환할 때

프롬프트 필터나 콘텐츠 스캐닝은 도움이 되지만, 마지막 행동 자체를 막아주지는 못합니다. Agent Runtime Security는 **도구 실행 직전의 정책 집행**과 **실행 후 데이터 보호**에 집중합니다.

## 주요 기능

- `Guard`: 도구 호출 정책 집행
- `Scanner`: 기본적인 content injection 탐지
- `AuditLogger`: 구조화된 JSONL 보안 이벤트 로그
- `mcp_guard`: MCP tool handler 보호
- `guard_tool`: LangChain 도구 보호
- `create_guarded_tool_node`: LangGraph ToolNode 보호
- `shadow`, `warn`, `enforce` 운영 모드
- YAML / JSON 정책 파일 로딩
- 선택형 FastAPI 확장 (`/scan`, `/decide`, `/redact`)
- Python 중심의 가벼운 통합 구조

## 설치

기본 패키지:

```bash
pip install agent-runtime-security
```

MCP 연동 포함:

```bash
pip install agent-runtime-security[mcp]
```

PDF 지원 포함:

```bash
pip install agent-runtime-security[pdf]
```

YAML 정책 파일 지원 포함:

```bash
pip install agent-runtime-security[yaml]
```

LangChain 연동 포함:

```bash
pip install agent-runtime-security[langchain]
```

LangGraph 연동 포함:

```bash
pip install agent-runtime-security[langgraph]
```

HTTP API 확장 포함:

```bash
pip install agent-runtime-security[api]
```

## HTTP API 확장

이제 이 저장소 안에 `asr.api` 1st-party FastAPI 확장이 포함됩니다.

문서 안내:

- 코어 SDK 개요: 이 README
- API 설정 상세: [`docs/api-extension.md`](./docs/api-extension.md)
- MCP / LangChain / LangGraph 예제: [`examples/README.ko.md`](./examples/README.ko.md)

로컬 서버 실행:

```bash
asr-api
```

파이썬에서 앱 생성:

```python
from asr.api.main import create_app

app = create_app()
```

전체 preset 라이브러리 포함:

- 범용: `default`, `internal-agent`, `mcp-server`, `customer-support`
- 산업별: `finance`, `healthcare`, `devops`, `data-pipeline`, `hr-agent`, `legal`, `ecommerce`, `research`
- 역할별: `developer-agent`, `browser-agent`, `sales-ops-agent`, `security-ops-agent`, `executive-assistant`

코드에서 preset 확인:

```python
from asr.api import available_policy_presets, load_policy_preset

print(available_policy_presets())
print(load_policy_preset("mcp-server"))
```

주요 환경 변수:

- `ASR_AUTH_ENABLED`
- `ASR_API_KEYS_FILE`
- `ASR_API_PREFIX`
- `ASR_ROOT_PATH`
- `ASR_POLICIES_DIR`
- `ASR_DEFAULT_POLICY_PRESET`

호환성을 위해 기존 `TRAPDEFENSE_*` 환경 변수도 계속 읽습니다.

추가 API 문서:

- 개요: [`docs/api/overview.md`](./docs/api/overview.md)
- 레퍼런스: [`docs/api/api-reference.md`](./docs/api/api-reference.md)
- 배포 가이드: [`deploy/api/DEPLOYMENT.md`](./deploy/api/DEPLOYMENT.md)

로컬 인증 파일 예시:

```json
{
  "keys": [
    {
      "name": "local-dev",
      "hash": "API_KEY의 sha256 해시"
    }
  ]
}
```

`ASR_API_KEYS_FILE`를 이 파일로 지정한 뒤 아래처럼 호출할 수 있습니다.

```bash
curl -X POST http://127.0.0.1:8000/v1/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore previous instructions", "source_type": "text"}'
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
print(f"score={result.score}, severity={result.severity}")

# 도구 호출 가드
guard = Guard.from_policy_file(
    "policy.yaml",
    audit=AuditLogger(output="logs/audit.jsonl"),
)

@guard.tool()
def send_email(to, subject, body):
    return f"queued message to {to}"

decision = guard.before_tool("send_email", {"to": "user@mail.internal"})
print(f"action={decision.action}, reason={decision.reason}")
print(send_email("user@mail.internal", "hello", "world"))

# 감사 로그
audit = AuditLogger(output="logs/audit.jsonl")
audit.log_scan(result, trace_id="req-001")
audit.log_guard(decision, trace_id="req-001")
```

```yaml
# policy.yaml
version: 2
mode: shadow
pii_action: block
block_egress: true
domain_allowlist:
  - internal.com
capability_policy:
  network_send: warn
  shell_exec: block
default_action: warn

tools:
  send_email:
    capabilities: [network_send]
    domain_allowlist: [mail.internal]
    pii_action: redact
    mode: enforce
```

`guard.tool()`은 함수 이름을 기본 tool id로 사용합니다. YAML 키와 함수 이름이 다르면 `@guard.tool(name="...")`를 사용하세요.

## 운영 모드

프로덕션에서는 정책을 단계적으로 배포할 수 있습니다.

```python
# 1단계: shadow — 차단 없이 관찰만
guard = Guard(mode="shadow", ...)

# 2단계: warn — block을 warn으로 다운그레이드
guard = Guard(mode="warn", ...)

# 3단계: enforce — 정책 결과 그대로 집행
guard = Guard(mode="enforce", ...)

# shadow/warn에서도 PII redaction은 계속 적용
decision = guard.before_tool("http_post", {"url": "https://evil.com"})
print(decision.action)          # shadow에서는 "allow"
print(decision.original_action) # 원래는 "block"
print(decision.mode)            # "shadow"
```

### 모드 의미

| 모드 | 설명 |
|------|------|
| `enforce` | 정책 결과를 그대로 적용 |
| `warn` | `block`을 `warn`으로 다운그레이드 |
| `shadow` | 실제로는 허용하되 원래 판정을 기록 |

## MCP 연동

`mcp_guard`로 MCP tool handler를 보호할 수 있습니다.

```python
from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

guard = Guard(
    mode="shadow",
    domain_allowlist=["api.internal.com"],
    block_egress=True,
)
audit = AuditLogger(output="logs/audit.jsonl")

@server.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def send_email(to: str, subject: str, body: str) -> str:
    return await email_service.send(to, subject, body)
```

정책 차단 시 MCP 호환 tool error로 변환되고, 결과에 민감정보가 있으면 자동 마스킹도 가능합니다.

예제 서버는 [examples/README.ko.md](./examples/README.ko.md) 또는 [examples/README.md](./examples/README.md)를 참고하세요.

## LangChain 연동

`guard_tool`로 LangChain 도구를 보호할 수 있습니다.

```python
from langchain_core.tools import tool
from asr import Guard
from asr.adapters.langchain import guard_tool

guard = Guard(
    domain_allowlist=["api.internal.com"],
    block_egress=True,
    pii_action="redact",
)

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """이메일을 발송합니다."""
    return f"Sent to {to}"

protected = guard_tool(send_email, guard=guard, capabilities=["network_send"])
result = protected.invoke({"to": "user@api.internal.com", "subject": "hi", "body": "hello"})
```

차단 시 `ToolException`이 발생하며 (`handle_tool_error=True`로 에러 메시지 반환), 결과의 PII는 자동 마스킹됩니다.

## LangGraph 연동

`create_guarded_tool_node`로 LangGraph `ToolNode` 전체를 보호할 수 있습니다.

```python
from asr import Guard
from asr.adapters.langgraph import create_guarded_tool_node

guard = Guard.from_policy_file("policy.yaml")

tool_node = create_guarded_tool_node(
    tools=[search_tool, file_reader_tool],
    guard=guard,
    capabilities_map={"search_tool": ["network_send"]},
)
# graph.add_node("tools", tool_node)
```

전체 예제는 `examples/langchain_agent.py`와 `examples/langgraph_agent.py`를 참고하세요.

## 정책 모델

`Guard`는 6가지 정책 계층과 3가지 운영 모드를 제공합니다.

### 정책 종류

| 정책 | 설명 |
|------|------|
| `tool_blocklist` | 도구 이름 직접 차단 |
| `domain_allowlist` + `block_egress` | 허용 도메인 외 네트워크 송신 차단 |
| `file_path_allowlist` | 허용 경로 외 파일 접근 제한 |
| `pii_action` | 도구 인자/결과의 민감정보 탐지: `off`, `warn`, `block` |
| `capability_policy` | capability 태그 기반 fallback 정책 |
| `default_action` | 알 수 없는 도구의 최종 fallback 동작 |

### 평가 순서

`Blocklist -> Egress -> FilePath -> PII -> Capability (fallback) -> Default`

이 순서는 중요합니다. 구체 정책이 먼저 적용되고, capability는 마지막 fallback이어야 하기 때문입니다.

## Scanner 탐지 범위

`Scanner`는 regex 기반의 1차 필터입니다. 가볍고 빠르지만, 필요하면 더 강한 외부 탐지와 함께 써야 합니다.

지원 패턴:

| 패턴 | 설명 |
|------|------|
| `css_hidden_text` | 숨겨진 CSS 텍스트 + 인젝션 문구 |
| `html_comment_injection` | HTML 주석 내 의심 지시문 |
| `metadata_injection` | `aria-label`, `alt`, `title` 악용 |
| `markdown_link_payload` | markdown 링크 텍스트 내 숨겨진 지시문 |
| `prompt_injection_keywords` | 일반적인 프롬프트 인젝션 키워드 |
| `base64_encoded_instruction` | Base64 인코딩된 의심 명령 |
| `invisible_unicode` | 보이지 않는 유니코드 문자 기반 난독화 |
| `role_override_attempt` | `SYSTEM:` 같은 역할 오버라이드 시도 |

## 이 프로젝트가 잘하는 것

- 도구 실행 시점의 runtime control
- `shadow -> warn -> enforce` 운영 전환
- 구조화된 audit log
- Python / MCP 중심의 가벼운 통합

## 아직 범위 밖인 것

- Semantic manipulation의 완전한 탐지
- 장기 메모리 오염 방어
- 멀티에이전트 systemic risk 관리
- 완전한 멀티테넌트 control plane / dashboard

이런 부분은 향후 아키텍처 레이어가 될 수 있지만, 현재 SDK 범위에는 의도적으로 포함하지 않습니다.

## 예제 서버

MCP 예제 서버 실행:

```bash
mcp dev examples/mcp_server.py
```

예제에서 보여주는 것:

- 외부 egress 통제
- 파일 경로 제한
- 자동 PII 마스킹

자세한 내용은 [examples/README.ko.md](./examples/README.ko.md)를 참고하세요.

## 개발

editable 모드 + 개발 의존성 설치:

```bash
pip install -e ".[dev]"
```

테스트 실행:

```bash
pytest
```

고객 데모나 내부 검증은 [examples/README.ko.md](./examples/README.ko.md)의 MCP 예제 서버 흐름을 기준 시나리오로 삼는 것을 권장합니다.

## 저장소 문서 언어 정책

- 공개 GitHub 문서: 영어 우선
- 한국어 번역: [README.ko.md](./README.ko.md)
- 내부 작업 문서: 한국어 유지 가능

## 라이선스

MIT
