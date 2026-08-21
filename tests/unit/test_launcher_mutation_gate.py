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
    adapter = object()
    monkeypatch.setattr(app, "NativeRepairAdapter", lambda: adapter)

    coordinator = app._build_default_repair_coordinator()

    assert coordinator.adapter is adapter
    assert coordinator.mutation_enabled is False


def test_launcher_app_source_never_enables_mutation() -> None:
    source_path = LAUNCHER_ROOT / "towerscout_launcher" / "app.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    coordinator_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "RepairCoordinator"
    ]

    assert coordinator_calls
    for call in coordinator_calls:
        mutation_keywords = [
            keyword for keyword in call.keywords if keyword.arg == "mutation_enabled"
        ]
        assert len(mutation_keywords) == 1
        value = mutation_keywords[0].value
        assert isinstance(value, ast.Constant)
        assert value.value is False
