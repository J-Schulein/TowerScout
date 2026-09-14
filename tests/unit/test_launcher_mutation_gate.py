from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher import app  # noqa: E402


def test_production_default_repair_coordinator_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = object()
    monkeypatch.setattr(app, "ExactTargetConfirmationCoordinator", lambda: coordinator)

    built = app._build_default_repair_coordinator()

    assert built is coordinator


def test_launcher_app_source_never_enables_mutation() -> None:
    source_path = LAUNCHER_ROOT / "towerscout_launcher" / "app.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    coordinator_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ExactTargetConfirmationCoordinator"
    ]

    assert coordinator_calls
    assert "mutation_enabled=True" not in source_path.read_text(encoding="utf-8")
    coordinator = app._build_default_repair_coordinator()
    assert coordinator.mutation_enabled is False
