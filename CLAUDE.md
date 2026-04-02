# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 개요

Agent Runtime Security (ARS) — 권한 있는 AI 에이전트의 도구 호출을 통제하고 감사 로그를 남기는 Python SDK. Google DeepMind의 "AI Agent Traps" 논문(2026)에서 출발했으며, Guard(행동 통제)와 Audit(증빙)이 핵심 가치이고 Scanner(입력 탐지)는 regex 기반 1차 필터입니다.

## 개발 명령어

```bash
# 설치 (dev 모드)
pip install -e ".[dev]"

# 전체 테스트
pytest

# 단일 테스트 파일
pytest tests/test_guard.py -v

# 특정 테스트
pytest tests/test_guard.py::TestGuardBeforeTool::test_blocklist_highest_priority -v

# 특정 키워드로 테스트 필터
pytest -k "pii" -v
```

## 아키텍처

```
asr/
├── guard.py      ← 핵심. before_tool/after_tool 정책 평가, protect 데코레이터, shadow/warn/enforce 모드
├── audit.py      ← 핵심. JSONL 구조화 로거 (ScanEvent/GuardBefore/GuardAfter/ErrorEvent)
├── scanner.py    ← 8개 regex 패턴 기반 입력 스캐너 (1차 필터)
├── policies.py   ← 6개 정책 평가 함수 (guard.py가 순서대로 호출)
├── pii.py        ← PII 탐지/마스킹 (policies.py와 guard.py가 사용)
├── types.py      ← 공유 dataclass (Finding, ScanResult, BeforeToolDecision, AfterToolDecision)
├── mcp.py        ← MCP tool handler용 async 데코레이터 (mcp 선택 의존)
└── utils.py      ← PDF 텍스트 추출 유틸리티 (pymupdf 선택 의존)
```

### Guard 정책 평가 순서 (반드시 이 순서를 유지해야 함)

1. Tool Blocklist → 2. Egress Control → 3. File Path → 4. PII Detection → 5. Capability (fallback) → 6. Default Action

**`matched_any_specific` 패턴:** Egress/FilePath/PII 중 하나라도 "해당"된 도구는 Capability를 건너뜁니다. Capability는 세부 정책이 하나도 해당하지 않았을 때만 적용되는 진짜 fallback입니다.

**세부 정책 간 가장 제한적 판정 우선:** `block`만 즉시 반환하고, `warn`은 모아서 나중에 더 제한적인 결과가 나오면 그것을 반환합니다.

### Guard 운영 모드 (shadow/warn/enforce)

- `enforce` (기본) — 정책 결과 그대로 적용
- `warn` — block→warn 다운그레이드, 실행은 허용하되 경고 기록
- `shadow` — 전부 allow, 원래 판정은 `original_action`으로 기록

**before_tool만 mode 영향을 받고, after_tool의 PII redact는 모드와 무관하게 항상 강제합니다.** shadow는 "행동 차단 유예"이지 "데이터 보호 유예"가 아닙니다.

Decision에 `original_action`(정책 원본)과 `mode` 필드가 있으며, 콜백(`on_block`, `on_warn`)은 `effective_action` 기준으로 발화합니다.

### Guard Egress 정책 — URL + 이메일 수신자

Egress 정책은 URL뿐만 아니라 이메일 수신자 필드(`to`, `recipient`, `recipients`)도 검사합니다. `has_url(args) or has_email_destination(args)` 조건으로 egress 정책 진입 여부를 판단합니다.

### Guard after_tool 타입 보존

`after_tool()`의 redact는 원래 결과 타입을 보존합니다 (str→str, dict→dict 재귀, list→list 재귀). `str(result)`로 변환하면 안 됩니다.

### Scanner CSS 오탐 방지

CSS 숨김 텍스트를 탐지할 때, 숨김 CSS만으로 플래그하지 않고 **숨김 영역 안에 injection 문구가 있을 때만** 탐지합니다. 접근성 skip link 오탐을 방지하기 위함입니다.

### PII 면제 필드

`_PII_EXEMPT_KEYS` (`to`, `from`, `recipient`, `recipients`, `cc`, `bcc`)는 PII 스캔에서 제외됩니다. 수신자 이메일은 정상 업무 데이터입니다.

### MCP Guard 어댑터

`mcp_guard` 데코레이터는 MCP tool handler(async def)를 Guard 정책으로 보호합니다. `from asr.mcp import mcp_guard`로 사용하며, `mcp` 패키지는 선택적 의존성입니다.

- Guard는 sync 유지, `mcp_guard`만 async wrapper
- `BlockedToolError` → MCP `ToolError` (`isError=True`) 변환
- `guard.protect`보다 PII 보호가 엄격: `pii_action="warn"`에서도 `redacted_result`가 있으면 마스킹 반환
- sync 함수에 적용 시 데코레이션 시점에 `TypeError` 발생

### Audit 스키마 — mode 필드

Audit 로그에는 `decision` (기존 하위호환) + `effective_action`, `original_action`, `mode` 가 기록됩니다. after_tool 이벤트에는 `protection_type: "data_protection"`이 추가됩니다.

## 언어 및 코딩 규칙

- 응답/주석/커밋 메시지/문서: 한국어
- 변수명/함수명: 영어
- 들여쓰기: 2칸
- Python 3.11+, 외부 의존성 최소화 (표준 라이브러리 우선)
