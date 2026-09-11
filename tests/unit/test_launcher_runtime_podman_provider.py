from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_podman_provider as provider_module  # noqa: E402
from towerscout_launcher.runtime_podman_provider import (  # noqa: E402
    InstalledProviderFile,
    ManagedPodmanProviderError,
    ManagedPodmanProviderErrorCode,
    ProviderWheel,
    verify_managed_podman_compose_source_inventory,
)
from towerscout_launcher.runtime_policy import (  # noqa: E402
    DistributionPolicy,
    load_package_bound_runtime_policy,
)


def _digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _record_hash(contents: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode(
        "ascii"
    )
    return "sha256=" + encoded.rstrip("=")


def _wheel(
    name: str,
    version: str,
    files: dict[str, bytes],
    *,
    record_override: bytes | None = None,
) -> tuple[str, bytes, dict[str, bytes]]:
    stem = name.replace("-", "_")
    dist_info = f"{stem}-{version}.dist-info"
    members = {
        **files,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n",
    }
    rows = [
        (path, _record_hash(contents), str(len(contents)))
        for path, contents in sorted(members.items())
    ]
    record_path = f"{dist_info}/RECORD"
    rows.append((record_path, "", ""))
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerows(rows)
    members[record_path] = (
        record_override
        if record_override is not None
        else stream.getvalue().encode("utf-8")
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, contents in members.items():
            archive.writestr(path, contents)
    filename = f"{stem}-{version}-py3-none-any.whl"
    return filename, output.getvalue(), members


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    extra_primary: dict[str, bytes] | None = None,
) -> tuple[bytes, tuple[ProviderWheel, ...], tuple[InstalledProviderFile, ...]]:
    wheel_specs = (
        _wheel(
            "podman-compose",
            "1.5.0",
            {
                "podman_compose.py": b"VERSION = '1.5.0'\n",
                **(extra_primary or {}),
            },
        ),
        _wheel("python-dotenv", "1.1.1", {"dotenv/__init__.py": b"VALUE = 1\n"}),
        _wheel(
            "PyYAML",
            "6.0.3",
            {
                "yaml/__init__.py": b"VALUE = 2\n",
                "_yaml.cp312-win_amd64.pyd": b"synthetic-pyd",
            },
        ),
    )
    distributions = tuple(
        DistributionPolicy(
            name=name,
            version=version,
            wheel_filename=filename,
            source_url=f"https://files.pythonhosted.org/packages/test/{filename}",
            wheel_sha256=_digest(contents),
        )
        for (name, version), (filename, contents, _members) in zip(
            (
                ("podman-compose", "1.5.0"),
                ("python-dotenv", "1.1.1"),
                ("PyYAML", "6.0.3"),
            ),
            wheel_specs,
            strict=True,
        )
    )
    catalog = {
        "schema_version": 1,
        "providers": [
            {
                "id": "podman-compose-pypi-1.5.0",
                "version": "1.5.0",
                "source_url": distributions[0].source_url,
                "package_sha256": distributions[0].wheel_sha256,
                "dependencies": [
                    {
                        "name": distribution.name,
                        "version": distribution.version,
                        "artifacts": [
                            {
                                "filename": distribution.wheel_filename,
                                "source_url": distribution.source_url,
                                "sha256": distribution.wheel_sha256,
                            }
                        ],
                    }
                    for distribution in distributions[1:]
                ],
            }
        ],
    }
    catalog_bytes = json.dumps(catalog, separators=(",", ":")).encode("utf-8")
    policy = load_package_bound_runtime_policy()
    monkeypatch.setattr(
        provider_module,
        "load_package_bound_runtime_policy",
        lambda: replace(
            policy,
            podman_compose=replace(
                policy.podman_compose,
                catalog=replace(
                    policy.podman_compose.catalog,
                    content_sha256=_digest(catalog_bytes),
                ),
                distributions=distributions,
            ),
        ),
    )
    wheels = tuple(
        ProviderWheel(filename=filename, contents=contents)
        for filename, contents, _members in wheel_specs
    )
    installed = tuple(
        InstalledProviderFile(
            relative_path=(".venv\\Lib\\site-packages\\" + member.replace("/", "\\")),
            sha256=_digest(contents),
            size_bytes=len(contents),
        )
        for _filename, _wheel_bytes, members in wheel_specs
        for member, contents in members.items()
    )
    return (
        catalog_bytes,
        wheels,
        installed,
    )


def _replace_primary_wheel(
    monkeypatch: pytest.MonkeyPatch,
    catalog: bytes,
    wheels: tuple[ProviderWheel, ...],
    replacement: bytes,
) -> tuple[bytes, tuple[ProviderWheel, ...]]:
    policy = provider_module.load_package_bound_runtime_policy()
    primary = replace(
        policy.podman_compose.distributions[0],
        wheel_sha256=_digest(replacement),
    )
    document = json.loads(catalog)
    document["providers"][0]["package_sha256"] = primary.wheel_sha256
    catalog_bytes = json.dumps(document, separators=(",", ":")).encode("utf-8")
    monkeypatch.setattr(
        provider_module,
        "load_package_bound_runtime_policy",
        lambda: replace(
            policy,
            podman_compose=replace(
                policy.podman_compose,
                catalog=replace(
                    policy.podman_compose.catalog,
                    content_sha256=_digest(catalog_bytes),
                ),
                distributions=(primary, *policy.podman_compose.distributions[1:]),
            ),
        ),
    )
    return (
        catalog_bytes,
        (replace(wheels[0], contents=replacement), *wheels[1:]),
    )


def test_verifier_authenticates_catalog_wheels_and_exact_installed_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)

    evidence = verify_managed_podman_compose_source_inventory(
        catalog_bytes=catalog,
        wheels=wheels,
        installed_files=installed,
    )

    assert evidence.provider_id == "podman-compose-pypi-1.5.0"
    assert evidence.provider_version == "1.5.0"
    assert evidence.distribution_count == 3
    assert evidence.installed_file_count == len(installed)
    assert evidence.catalog_sha256 == _digest(catalog)
    assert evidence.wheel_sha256s == tuple(_digest(wheel.contents) for wheel in wheels)
    assert any(
        artifact.relative_path.endswith("podman_compose.py")
        for artifact in evidence.loadable_artifacts
    )
    assert any(
        artifact.relative_path.endswith("_yaml.cp312-win_amd64.pyd")
        for artifact in evidence.loadable_artifacts
    )
    assert "redacted" in repr(evidence).lower()
    assert "VERSION =" not in repr(evidence)


def test_checked_in_provider_catalog_matches_package_bound_runtime_policy() -> None:
    catalog = (ROOT / "scripts" / "podman-compose-providers.v1.json").read_bytes()
    policy = load_package_bound_runtime_policy()

    provider_module._catalog_matches_policy(  # noqa: SLF001
        provider_module._load_catalog(catalog),  # noqa: SLF001
        policy.podman_compose,
    )


@pytest.mark.parametrize("mode", ("missing", "changed", "extra"))
def test_verifier_rejects_installed_inventory_drift(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    changed = list(installed)
    if mode == "missing":
        changed.pop()
    elif mode == "changed":
        changed[0] = replace(changed[0], sha256="0" * 64)
    else:
        changed.append(
            InstalledProviderFile(
                relative_path=r".venv\Lib\site-packages\attacker.py",
                sha256="1" * 64,
                size_bytes=1,
            )
        )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=catalog,
            wheels=wheels,
            installed_files=tuple(changed),
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.INVENTORY_INVALID
    assert "attacker" not in str(captured.value)


def test_verifier_rejects_catalog_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    document = json.loads(catalog)
    document["providers"][0]["package_sha256"] = "0" * 64

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=json.dumps(document).encode("utf-8"),
            wheels=wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.CATALOG_INVALID


def test_verifier_rejects_semantically_compatible_but_changed_catalog_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    document = json.loads(catalog)
    document["providers"][0]["display_name"] = "changed but otherwise compatible"

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=json.dumps(document, separators=(",", ":")).encode("utf-8"),
            wheels=wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.CATALOG_INVALID


@pytest.mark.parametrize(
    "invalid_catalog",
    (None, b"x" * ((1024 * 1024) + 1)),
    ids=("non-bytes", "oversized"),
)
def test_verifier_rejects_invalid_catalog_input_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
    invalid_catalog: Any,
) -> None:
    _catalog, wheels, installed = _fixture(monkeypatch)

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=invalid_catalog,
            wheels=wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.CATALOG_INVALID
    assert str(captured.value) == (
        "The managed Podman Compose provider catalog is invalid."
    )


def test_verifier_rejects_duplicate_catalog_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    duplicate = catalog.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1'
    )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=duplicate,
            wheels=wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.CATALOG_INVALID


def test_verifier_rejects_unapproved_wheel_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    changed = (
        replace(wheels[0], contents=wheels[0].contents + b"changed"),
        *wheels[1:],
    )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=catalog,
            wheels=changed,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.WHEEL_INVALID


@pytest.mark.parametrize(
    "extra_file",
    (
        {"provider.pth": b"import attacker\n"},
        {"sitecustomize.py": b"raise SystemExit\n"},
        {"sitecustomize.pyd": b"synthetic-pyd"},
        {"sitecustomize/__init__.py": b"raise SystemExit\n"},
        {"usercustomize.py": b"raise SystemExit\n"},
        {"usercustomize.cp312-win_amd64.pyd": b"synthetic-pyd"},
        {"usercustomize/__init__.py": b"raise SystemExit\n"},
        {"module.pyc": b"compiled"},
    ),
)
def test_verifier_rejects_policy_denied_wheel_load_surfaces(
    monkeypatch: pytest.MonkeyPatch,
    extra_file: dict[str, bytes],
) -> None:
    catalog, wheels, installed = _fixture(
        monkeypatch,
        extra_primary=extra_file,
    )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=catalog,
            wheels=wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.WHEEL_INVALID


def test_verifier_rejects_unsafe_wheel_record_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    _filename, unsafe_bytes, _members = _wheel(
        "podman-compose",
        "1.5.0",
        {"../escape.py": b"escape"},
    )
    catalog, changed_wheels = _replace_primary_wheel(
        monkeypatch,
        catalog,
        wheels,
        unsafe_bytes,
    )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=catalog,
            wheels=changed_wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.WHEEL_INVALID


def test_verifier_rejects_a_wheel_member_changed_after_record_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog, wheels, installed = _fixture(monkeypatch)
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(wheels[0].contents), "r") as archive:
        for info in archive.infolist():
            members[info.filename] = archive.read(info)
    members["podman_compose.py"] = b"changed after RECORD\n"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, contents in members.items():
            archive.writestr(path, contents)
    catalog, changed_wheels = _replace_primary_wheel(
        monkeypatch,
        catalog,
        wheels,
        output.getvalue(),
    )

    with pytest.raises(ManagedPodmanProviderError) as captured:
        verify_managed_podman_compose_source_inventory(
            catalog_bytes=catalog,
            wheels=changed_wheels,
            installed_files=installed,
        )

    assert captured.value.code is ManagedPodmanProviderErrorCode.WHEEL_INVALID


def test_provider_inventory_verifier_remains_unwired() -> None:
    for relative in (
        "launcher/towerscout_launcher/app.py",
        "launcher/towerscout_launcher/discovery.py",
        "launcher/towerscout_launcher/repair.py",
        "launcher/towerscout_launcher/runtime_execution.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "runtime_podman_provider" not in source
