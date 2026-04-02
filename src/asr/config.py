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
            f"Unsupported file extension: '{suffix}'. "
            f"Only .json, .yaml, and .yml are supported"
        )

    if not isinstance(data, dict):
        raise ValueError(
            "Policy files must use a mapping at the top level. "
            f"Got: {type(data).__name__}"
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
            "pyyaml is required to load YAML policy files: "
            "pip install agent-runtime-security[yaml]"
        )
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)
