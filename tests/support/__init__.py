"""Helpers shared by the test suites."""

from pathlib import Path

# tests/support/__init__.py -> tests/support -> tests -> repository root
REPO_ROOT = Path(__file__).resolve().parents[2]
