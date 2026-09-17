from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_launcher_runtime_execution import _target  # noqa: E402
from towerscout_launcher.target_contracts import RuntimeProduct  # noqa: E402
from towerscout_launcher.windows_recovery_runtime_authority import (  # noqa: E402
    RollbackRuntimeRecoveryAuthority,
    derive_rollback_runtime_recovery_authority,
)


@pytest.mark.parametrize("product", tuple(RuntimeProduct))
def test_authority_binds_runtime_image_compose_and_all_volumes(product):
    target, _python, _key = _target(product)

    authority = derive_rollback_runtime_recovery_authority(target)

    assert authority.target_token_sha256 == target.target_token.digest_sha256
    assert len(authority.volume_evidence_sha256s) == 8
    assert len(set(authority.volume_evidence_sha256s)) == 8
    assert authority.runtime_was_running
    rendered = repr(authority)
    assert target.endpoint.canonical_endpoint not in rendered
    assert target.container.container_id not in rendered


@pytest.mark.parametrize(
    "changed",
    (
        lambda target: replace(
            target,
            compose=replace(
                target.compose,
                pre_model_sha256="a" * 64,
            ),
        ),
        lambda target: replace(
            target,
            image=replace(
                target.image,
                private_inspect_sha256="a" * 64,
            ),
            container=replace(
                target.container,
                private_inspect_sha256="b" * 64,
            ),
        ),
        lambda target: replace(
            target,
            volumes=(
                replace(
                    target.volumes[0],
                    private_inspect_sha256="a" * 64,
                ),
                *target.volumes[1:],
            ),
        ),
    ),
)
def test_authority_changes_when_recovery_identity_changes(changed):
    target, _python, _key = _target(RuntimeProduct.DOCKER)
    original = derive_rollback_runtime_recovery_authority(target)

    replacement = derive_rollback_runtime_recovery_authority(changed(target))

    assert replacement != original


def test_authority_rejects_invalid_shape_and_never_accepts_stopped_prior_state():
    with pytest.raises(ValueError):
        RollbackRuntimeRecoveryAuthority(
            1,
            "a" * 64,
            object(),  # type: ignore[arg-type]
            "b" * 64,
            tuple("c" * 64 for _index in range(8)),
            True,
        )
    with pytest.raises(ValueError):
        RollbackRuntimeRecoveryAuthority(
            1,
            "a" * 64,
            derive_rollback_runtime_recovery_authority(
                _target(RuntimeProduct.DOCKER)[0]
            ).package_root_identity,
            "b" * 64,
            tuple(f"{index:064x}" for index in range(8)),
            False,
        )
