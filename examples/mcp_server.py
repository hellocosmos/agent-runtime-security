"""ARS MCP 예제 서버 — Guard 정책 데모

실행: python examples/mcp_server.py
또는: mcp dev examples/mcp_server.py

데모 시나리오:
  1. mode: shadow (기본) — 모든 호출 허용, audit에 original_action 기록
  2. policy.yaml에서 mode: enforce로 변경 후 재실행 — 정책 실제 적용
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from asr import Guard, AuditLogger
from asr.mcp import mcp_guard

# 정책 파일에서 Guard 생성
POLICY_PATH = Path(__file__).parent / "policy.yaml"
guard = Guard.from_policy_file(str(POLICY_PATH))
audit = AuditLogger(output="stdout")

mcp = FastMCP("ARS 데모 서버")


@mcp.tool()
@mcp_guard(guard, audit=audit, capabilities=["network_send"])
async def send_email(to: str, subject: str, body: str) -> str:
    """이메일을 전송합니다 (시뮬레이션)

    egress 정책: domain_allowlist에 없는 도메인으로의 전송은 차단됩니다.
    shadow 모드에서는 허용하되 audit에 original_action=block이 기록됩니다.
    """
    return f"이메일 전송 완료: to={to}, subject={subject}"


@mcp.tool()
@mcp_guard(guard, audit=audit, capabilities=["file_read"])
async def read_file(path: str) -> str:
    """파일을 읽습니다 (시뮬레이션)

    file_path_allowlist에 포함된 경로만 허용됩니다.
    /etc/passwd 같은 민감 경로는 차단됩니다.
    """
    return f"파일 내용 (시뮬레이션): path={path}, data=sample content"


@mcp.tool()
@mcp_guard(guard, audit=audit)
async def search(query: str) -> str:
    """데이터를 검색합니다 (시뮬레이션)

    검색 결과에 PII(이메일, API 키 등)가 포함되면 자동으로 마스킹됩니다.
    pii_action=block이면 [EMAIL], [API_KEY] 등으로 치환됩니다.
    """
    # 의도적으로 PII가 포함된 시뮬레이션 결과
    return (
        f"검색 결과 ({query}):\n"
        f"  - 담당자: admin@secret.com\n"
        f"  - API 키: sk-proj-abc123def456ghi789jkl012mno345pqr678stu\n"
        f"  - 연락처: 010-1234-5678"
    )


if __name__ == "__main__":
    mcp.run()
