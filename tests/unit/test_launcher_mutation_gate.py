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
from towerscout_launcher.exact_target_confirmation import (  # noqa: E402
    CONFIRMATION_TEXT,
    ExactTargetConfirmationCoordinator,
)


def test_production_default_repair_coordinator_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = object()
    monkeypatch.setattr(app, "ExactTargetConfirmationCoordinator", lambda: coordinator)

    built = app._build_default_repair_coordinator()

    assert built is coordinator


def test_launcher_app_routes_mutation_through_exact_confirmation() -> None:
    source_path = LAUNCHER_ROOT / "towerscout_launcher" / "app.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    coordinator_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ExactTargetConfirmationCoordinator"
    ]

    assert coordinator_calls
    coordinator = app._build_default_repair_coordinator()
    assert isinstance(coordinator, ExactTargetConfirmationCoordinator)
    assert coordinator.mutation_enabled is True
    assert app._USER_CONFIRMATION == CONFIRMATION_TEXT
    assert "self.repair_coordinator.prepare(provider)" in source
    assert "self.repair_coordinator.confirm(transaction, typed)" in source
    assert "self.repair_coordinator.execute(transaction)" in source
    assert "transaction.close()" in source
    assert "from .repair import" not in source
