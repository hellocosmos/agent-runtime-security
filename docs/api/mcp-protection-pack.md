# MCP Protection Pack

MCP 서버로 사내 도구(Notion, Jira, Slack, DB, 이메일 등)를 연결한 팀을 위한 보안 패키지.

---

## 이 팩이 막는 위험

MCP 서버는 AI 에이전트에게 실제 도구를 열어줍니다. 편리하지만, 에이전트가 다음을 할 수 있다는 뜻이기도 합니다:

| 위험 | 예시 | 결과 |
|------|------|------|
| **데이터 유출** | 에이전트가 DB 조회 결과를 외부 URL로 전송 | 고객 데이터 유출 |
| **권한 밖 실행** | 에이전트가 `drop_table`, `delete_database` 호출 | 데이터 파괴 |
| **PII 노출** | 검색 결과에 주민번호, 이메일이 포함 | 개인정보 유출 |
| **프롬프트 인젝션** | 외부 문서에 숨겨진 명령이 에이전트를 조종 | 의도하지 않은 동작 |

---

## 권장 구성

### Policy Preset: `mcp-server`

```bash
curl -X POST http://127.0.0.1:8000/v1/decide \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "send_email",
    "args": {"to": "external@gmail.com", "body": "분기 매출 리포트"},
    "capabilities": ["email_send"],
    "policy_preset": "mcp-server"
  }'
```

`mcp-server` preset이 하는 일:

| 정책 | 동작 |
|------|------|
| 외부 전송 차단 | allowlist에 없는 도메인으로의 HTTP/이메일 전송 block |
| 고위험 도구 차단 | `shell_exec`, `eval`, `delete_database` 등 13개 도구 block |
| PII 마스킹 | 도구 결과에 포함된 PII를 자동 마스킹 (warn 모드) |
| 파일 접근 제한 | 허용 디렉토리 외 접근 block |
| capability 기반 통제 | `network_send`, `credential_access`, `bulk_export` 등 세분화 |

### PII Profiles: 지역에 맞게 선택

```bash
# 한국 팀
"pii_profiles": ["global-core", "kr"]

# 글로벌 팀 (결제 포함)
"pii_profiles": ["global-core", "payment"]

# 일본 팀
"pii_profiles": ["global-core", "jp"]
```

| 프로필 | 탐지 항목 |
|--------|-----------|
| `global-core` | 이메일, 전화번호, API 키, Bearer 토큰, 시크릿 |
| `kr` | 주민등록번호, 사업자등록번호, 은행 계좌번호 |
| `payment` | 신용카드 (Visa, MC, Amex, Discover, JCB, UnionPay) |

[전체 프로필 목록 →](coverage.md)

---

## 단계별 Rollout 가이드

한 번에 enforce로 켜지 마세요. 3단계로 안전하게 도입합니다.

### Phase 1: Shadow (1~2주)

```json
{
  "tool_name": "send_email",
  "args": {"to": "external@unknown.com"},
  "policy_preset": "mcp-server",
  "mode": "shadow"
}
```

- 모든 도구 호출을 **허용**하되, 정책 판정 결과를 기록
- `original_action` 필드에 실제 판정(block/warn/allow)이 남음
- **아무것도 차단하지 않음** — 운영에 영향 없음
- 이 기간에 **오탐(false positive)** 확인 → allowlist 튜닝

**확인할 것:**
- 정상 업무 도구가 block으로 판정되는 경우 → `domain_allowlist`에 추가
- 너무 많은 warn → capability_policy 조정

### Phase 2: Warn (1~2주)

```json
{
  "mode": "warn"
}
```

- block 판정이 **warn으로 다운그레이드** — 실행은 허용, 경고 로그 기록
- 팀이 경고를 리뷰하면서 정책을 미세 조정
- PII 마스킹은 warn 모드에서도 동작

### Phase 3: Enforce (운영)

```json
{
  "mode": "enforce"
}
```

- 정책 위반 시 **실제 차단**
- 이 시점에서 allowlist, blocklist, capability 정책이 안정화된 상태

---

## 통합 예시: MCP Tool Handler

```python
import httpx
from mcp.server import Server

ASR_API_KEY = "YOUR_API_KEY"
ASR_API_URL = "http://127.0.0.1:8000/v1"

server = Server("my-mcp-server")

async def check_tool(tool_name: str, args: dict, capabilities: list[str]) -> dict:
    """Agent Runtime Security API로 도구 실행 전 판정을 받는다."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/decide",
            headers={"Authorization": f"Bearer {ASR_API_KEY}"},
            json={
                "tool_name": tool_name,
                "args": args,
                "capabilities": capabilities,
                "policy_preset": "mcp-server",
            },
        )
        return resp.json()

async def redact_result(tool_name: str, result: str) -> str:
    """도구 결과에서 PII를 마스킹한다."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{ASR_API_URL}/redact",
            headers={"Authorization": f"Bearer {ASR_API_KEY}"},
            json={
                "tool_name": tool_name,
                "result": result,
                "pii_profiles": ["global-core", "kr"],
            },
        )
        data = resp.json()
        return data["data"]["redacted_result"]

@server.tool()
async def send_email(to: str, subject: str, body: str) -> str:
    # 1. 실행 전 판정
    decision = await check_tool(
        "send_email",
        {"to": to, "subject": subject, "body": body},
        ["email_send", "network_send"],
    )
    if decision["data"]["action"] == "block":
        return f"Blocked: {decision['data']['reason']}"

    # 2. 실제 실행
    result = actually_send_email(to, subject, body)

    # 3. 결과 PII 마스킹
    return await redact_result("send_email", result)
```

---

## False Positive 가이드

### "정상 도구 호출이 block됨"

| 원인 | 해결 |
|------|------|
| 허용 도메인 누락 | preset의 `domain_allowlist`에 도메인 추가. 또는 `policy` 필드로 직접 전달 |
| 필요한 capability가 block | `capability_policy`에서 해당 capability를 `warn`으로 변경 |
| 정상 도구가 blocklist에 포함 | `tool_blocklist`에서 제거 |

### "민감하지 않은 데이터가 마스킹됨"

| 원인 | 해결 |
|------|------|
| 전화번호 형식이 일반 숫자와 겹침 | `pii_profiles`를 명시적으로 지정 (전체 실행 대신) |
| 특정 프로필 불필요 | 필요한 프로필만 선택 (예: `["global-core"]`만) |

### Custom policy 직접 전달

preset이 맞지 않으면 `policy` 필드로 직접 전달:

```json
{
  "tool_name": "send_email",
  "args": {"to": "partner@allowed.com"},
  "policy": {
    "version": 1,
    "mode": "enforce",
    "block_egress": true,
    "domain_allowlist": ["allowed.com", "*.mycompany.com"],
    "tool_blocklist": ["shell_exec", "eval"],
    "pii_action": "warn",
    "default_action": "warn"
  }
}
```

---

## 이 팩에 포함된 것

| 항목 | 내용 |
|------|------|
| Policy preset | `mcp-server` (즉시 사용 가능) |
| PII profiles | `global-core` + 지역별 선택 |
| 탐지 패턴 | 22종 (API 프리미엄) |
| Rollout 가이드 | shadow → warn → enforce 3단계 |
| 통합 예시 | Python MCP 서버 코드 |
| False positive 가이드 | 일반적인 오탐과 해결 방법 |

---

질문이나 피드백: **hellocosmos@gmail.com**
