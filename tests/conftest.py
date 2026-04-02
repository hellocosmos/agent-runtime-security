"""Shared test fixtures."""

import pathlib

import pytest

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
