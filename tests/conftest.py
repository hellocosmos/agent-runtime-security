"""Shared test fixtures."""

import pathlib
import sys

import pytest

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def attack_dir(fixtures_dir):
    return fixtures_dir / "attacks"


@pytest.fixture
def benign_dir(fixtures_dir):
    return fixtures_dir / "benign"
