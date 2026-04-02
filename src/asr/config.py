"""정책 파일 로드 — JSON 기본, YAML 선택적 지원"""
from __future__ import annotations

import json
from pathlib import Path


def load_policy_file(path: str) -> dict:
    """정책 파일을 로드하여 dict로 반환

    Args:
        path: 정책 파일 경로 (.json, .yaml, .yml)

    Returns:
        정책 설정 dict

    Raises:
        ValueError: 지원하지 않는 확장자 또는 잘못된 파일 형식
        FileNotFoundError: 파일이 존재하지 않음
        ImportError: YAML 파일인데 pyyaml이 설치되지 않음
    """
    file_path = Path(path)
    suffix = file_path.suffix.lower()

    if suffix == ".json":
        data = _load_json(file_path)
    elif suffix in (".yaml", ".yml"):
        data = _load_yaml(file_path)
    else:
        raise ValueError(
            f"지원하지 않는 파일 확장자: '{suffix}'. "
            f".json, .yaml, .yml만 지원합니다"
        )

    if not isinstance(data, dict):
        raise ValueError(
            "정책 파일은 최상위가 mapping이어야 합니다. "
            f"실제 타입: {type(data).__name__}"
        )

    return data


def _load_json(path: Path) -> object:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path: Path) -> object:
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "YAML 정책 파일을 사용하려면 pyyaml이 필요합니다: "
            "pip install agent-runtime-security[yaml]"
        )
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)
