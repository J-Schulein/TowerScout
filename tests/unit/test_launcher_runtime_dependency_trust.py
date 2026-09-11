from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dependency_trust as trust_module  # noqa: E402
from towerscout_launcher.pe_dependencies import PeDependencyManifest  # noqa: E402
from towerscout_launcher.runtime_dependency_policy import (  # noqa: E402
    PeMachine,
    load_package_bound_runtime_dependency_policy,
)
from towerscout_launcher.runtime_dependency_trust import (  # noqa: E402
    DependencyFileObservation,
    RuntimeDependencyTrustError,
    RuntimeDependencyTrustErrorCode,
    inspect_handle_bound_pe_dependencies,
    validate_package_bound_cpython_dependency_observations,
    validate_package_bound_entrypoint_dependencies,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    capture_handle_bound_file,
)

_MANIFEST_DOMAIN = b"TowerScout.PeDependencyManifest.v1"


def _pe_bytes() -> bytes:
    image = bytearray(0x600)
    pe_offset = 0x80
    optional_offset = pe_offset + 24
    optional_size = 0xF0
    section_offset = optional_offset + optional_size
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        0x8664,
        1,
        0,
        0,
        0,
        optional_size,
        0,
    )
    struct.pack_into("<H", image, optional_offset, 0x020B)
    struct.pack_into("<I", image, optional_offset + 60, 0x200)
    struct.pack_into("<I", image, optional_offset + 108, 16)
    image[section_offset : section_offset + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", image, section_offset + 8, 0x400, 0x1000, 0x400, 0x200)
    name_offset = 0x280
    name = b"KERNEL32.dll\x00"
    image[name_offset : name_offset + len(name)] = name
    struct.pack_into("<I", image, 0x200 + 12, 0x1000 + name_offset - 0x200)
    struct.pack_into("<II", image, optional_offset + 120, 0x1000, 40)
    return bytes(image)


class _HeldFileApi:
    supported = True

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.handle = object()
        self.cursor = 0

    def open_file_for_identity(self, path: str) -> object:
        del path
        return self.handle

    def open_file_for_hydrated_identity(self, path: str) -> object:
        return self.open_file_for_identity(path)

    def query_file(self, handle: object) -> NativeFileFacts:
        assert handle is self.handle
        return NativeFileFacts(
            final_path=r"\\?\C:\Private\runtime.exe",
            volume_serial=1,
            file_id=b"1" * 16,
            attributes=0x80,
            link_count=1,
            size=len(self.content),
            creation_time=1,
            last_write_time=2,
            drive_type=3,
            file_type=1,
            reparse_tag=0,
        )

    def rewind_file(self, handle: object) -> None:
        self.seek_file(handle, 0)

    def seek_file(self, handle: object, offset: int) -> None:
        assert handle is self.handle
        self.cursor = offset

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert handle is self.handle
        value = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(value)
        return value

    def close_handle(self, handle: object) -> None:
        assert handle is self.handle


def _manifest(
    direct: tuple[str, ...] = ("kernel32.dll",),
    delay: tuple[str, ...] = (),
    forwarded: tuple[str, ...] = (),
) -> PeDependencyManifest:
    digest = hashlib.sha256()
    for value in (
        _MANIFEST_DOMAIN,
        *direct,
        b"delay",
        *delay,
        b"forwarded",
        *forwarded,
    ):
        encoded = value if isinstance(value, bytes) else value.encode("ascii")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return PeDependencyManifest(direct, delay, forwarded, digest.hexdigest())


def _fixture_policy(manifest: PeDependencyManifest | None = None):  # noqa: ANN202
    manifest = manifest or _manifest()
    policy = load_package_bound_runtime_dependency_policy()
    artifact = replace(
        policy.cpython,
        declared_system_imports=("kernel32.dll",),
        declared_api_set_imports=(),
        loadable_files=tuple(
            replace(record, dependency_manifest_sha256=manifest.evidence_sha256)
            for record in policy.cpython.loadable_files
        ),
    )
    return replace(policy, cpython=artifact)


def _observations(
    policy, manifest: PeDependencyManifest | None = None
):  # noqa: ANN001, ANN202
    manifest = manifest or _manifest()
    values = [
        DependencyFileObservation(
            path=record.path,
            sha256=record.sha256,
            machine=PeMachine.AMD64,
            signer_certificate_sha256=record.signer_certificate_sha256,
            dependency_manifest=manifest,
        )
        for record in policy.cpython.loadable_files
    ]
    values.extend(
        DependencyFileObservation(
            path=record.path,
            sha256=record.sha256,
            machine=record.machine,
            signer_certificate_sha256=None,
            dependency_manifest=None,
        )
        for record in policy.cpython.non_amd64_pe_files
    )
    return tuple(sorted(values, key=lambda item: item.path.casefold()))


def test_exact_cpython_observations_produce_bounded_redacted_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _fixture_policy()
    observations = _observations(policy)
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    evidence = validate_package_bound_cpython_dependency_observations(observations)

    assert evidence.product_id is RuntimeProductId.CPYTHON
    assert evidence.exact_version == "3.12.10"
    assert evidence.policy_sha256 == policy.content_sha256
    assert evidence.archive_sha256 == policy.cpython.archive_sha256
    assert evidence.pe_file_count == 47
    assert evidence.amd64_loadable_count == 43
    assert evidence.signer_policy_count == 5
    assert evidence.exact_native_inventory_bound
    assert evidence.static_dependency_manifests_closed
    assert evidence.dynamic_load_policy_required
    assert len(evidence.inventory_sha256) == 64
    assert len(evidence.static_import_surface_sha256) == 64
    assert "python.exe" not in repr(evidence)
    assert observations[0].sha256 not in repr(evidence)
    with pytest.raises(FrozenInstanceError):
        evidence.pe_file_count = 0  # type: ignore[misc]


def test_pe_dependencies_are_parsed_through_the_revalidated_held_handle() -> None:
    api = _HeldFileApi(_pe_bytes())

    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        manifest = inspect_handle_bound_pe_dependencies(bound)

    assert manifest.direct_imports == ("kernel32.dll",)
    assert manifest.delay_imports == ()
    assert manifest.forwarded_imports == ()


@pytest.mark.parametrize(
    "change",
    (
        lambda item: replace(item, sha256="0" * 64),
        lambda item: replace(item, signer_certificate_sha256="0" * 64),
        lambda item: replace(item, machine=PeMachine.I386),
        lambda item: replace(item, path=item.path.swapcase()),
    ),
)
def test_cpython_observations_reject_changed_approved_file_facts(
    monkeypatch: pytest.MonkeyPatch,
    change,
) -> None:  # noqa: ANN001
    policy = _fixture_policy()
    observations = list(_observations(policy))
    index = next(
        index
        for index, observation in enumerate(observations)
        if observation.machine is PeMachine.AMD64
    )
    observations[index] = change(observations[index])
    observations.sort(key=lambda item: item.path.casefold())
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_cpython_dependency_observations(tuple(observations))

    assert failure.value.code is RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH
    assert observations[index].path not in repr(failure.value)


def test_cpython_observations_reject_missing_extra_or_unsorted_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _fixture_policy()
    observations = _observations(policy)
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    variants = (
        observations[:-1],
        observations + (observations[-1],),
        tuple(reversed(observations)),
    )
    for variant in variants:
        with pytest.raises(RuntimeDependencyTrustError) as failure:
            validate_package_bound_cpython_dependency_observations(variant)
        assert failure.value.code is (
            RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH
        )


def test_unapproved_static_import_fails_after_exact_manifest_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(("kernel32.dll", "user32.dll"))
    policy = _fixture_policy(manifest)
    observations = _observations(policy, manifest)
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_cpython_dependency_observations(observations)

    assert failure.value.code is RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED


def test_unsigned_non_amd64_template_must_remain_unsigned_and_without_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _fixture_policy()
    observations = list(_observations(policy))
    index = next(
        index
        for index, observation in enumerate(observations)
        if observation.machine is not PeMachine.AMD64
    )
    observations[index] = replace(
        observations[index], signer_certificate_sha256="0" * 64
    )
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_cpython_dependency_observations(tuple(observations))

    assert failure.value.code is RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH


def test_unsigned_amd64_upstream_file_must_remain_unsigned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _fixture_policy()
    observations = list(_observations(policy))
    index = next(
        index
        for index, observation in enumerate(observations)
        if observation.machine is PeMachine.AMD64
        and observation.signer_certificate_sha256 is None
    )
    observations[index] = replace(
        observations[index], signer_certificate_sha256="0" * 64
    )
    monkeypatch.setattr(
        trust_module,
        "load_package_bound_runtime_dependency_policy",
        lambda: policy,
    )

    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_cpython_dependency_observations(tuple(observations))

    assert failure.value.code is RuntimeDependencyTrustErrorCode.INVENTORY_MISMATCH


@pytest.mark.parametrize(
    "product_id",
    (
        RuntimeProductId.DOCKER_CLI,
        RuntimeProductId.DOCKER_COMPOSE,
        RuntimeProductId.PODMAN_CLI,
    ),
)
def test_container_client_entrypoint_manifest_is_exactly_approved(
    product_id: RuntimeProductId,
) -> None:
    manifest = _manifest()

    evidence = validate_package_bound_entrypoint_dependencies(product_id, manifest)

    assert evidence.product_id is product_id
    assert evidence.dependency_manifest_sha256 == manifest.evidence_sha256
    assert evidence.static_entrypoint_imports_approved
    assert evidence.transitive_application_inventory_required
    assert len(evidence.evidence_sha256) == 64


def test_container_client_entrypoint_rejects_extra_or_wrong_class_imports() -> None:
    for manifest in (
        _manifest(("kernel32.dll", "user32.dll")),
        _manifest((), ("kernel32.dll",)),
        _manifest((), (), ("kernel32.dll",)),
    ):
        with pytest.raises(RuntimeDependencyTrustError) as failure:
            validate_package_bound_entrypoint_dependencies(
                RuntimeProductId.DOCKER_CLI, manifest
            )
        assert failure.value.code is (
            RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED
        )


def test_cpython_is_not_accepted_by_container_entrypoint_validator() -> None:
    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_entrypoint_dependencies(
            RuntimeProductId.CPYTHON, _manifest()
        )

    assert failure.value.code is RuntimeDependencyTrustErrorCode.DEPENDENCY_UNAPPROVED


def test_policy_loading_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail():  # noqa: ANN202
        raise OSError(r"C:\Users\private-person\dependency-policy.json")

    monkeypatch.setattr(
        trust_module, "load_package_bound_runtime_dependency_policy", fail
    )

    with pytest.raises(RuntimeDependencyTrustError) as failure:
        validate_package_bound_entrypoint_dependencies(
            RuntimeProductId.DOCKER_CLI, _manifest()
        )

    assert failure.value.code is RuntimeDependencyTrustErrorCode.POLICY_UNAVAILABLE
    assert "private-person" not in str(failure.value)
    assert "private-person" not in repr(failure.value)


def test_observation_rejects_invalid_facts_and_redacts_valid_facts() -> None:
    manifest = _manifest()
    observation = DependencyFileObservation(
        path="private/helper.dll",
        sha256="1" * 64,
        machine=PeMachine.AMD64,
        signer_certificate_sha256="2" * 64,
        dependency_manifest=manifest,
    )
    assert "private" not in repr(observation)
    assert "1" * 64 not in repr(observation)

    with pytest.raises(ValueError):
        DependencyFileObservation(
            path="bad\x00path.dll",
            sha256="1" * 64,
            machine=PeMachine.AMD64,
            signer_certificate_sha256="2" * 64,
            dependency_manifest=manifest,
        )


def test_validation_slice_is_inert_and_unwired() -> None:
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_dependency_trust.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "ctypes",
        "WinDLL",
        "CreateFile",
        "LoadLibrary",
    ):
        assert forbidden not in source

    for relative in (
        "app.py",
        "discovery.py",
        "repair.py",
        "runtime_execution.py",
        "coordination.py",
    ):
        consumer = (LAUNCHER_ROOT / "towerscout_launcher" / relative).read_text(
            encoding="utf-8"
        )
        assert "runtime_dependency_trust" not in consumer
