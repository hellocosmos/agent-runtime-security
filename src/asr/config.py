"""Policy-file loader with JSON by default and optional YAML support."""
from __future__ import annotations

import json
from pathlib import Path


def load_policy_file(path: str) -> dict:
    """Load a policy file and return it as a dictionary.

    Args:
        path: Policy file path (``.json``, ``.yaml``, ``.yml``).

    Returns:
        Parsed policy configuration.

    Raises:
        ValueError: Unsupported extension or invalid file shape.
        FileNotFoundError: The file does not exist.
        ImportError: The file is YAML but ``pyyaml`` is not installed.
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
