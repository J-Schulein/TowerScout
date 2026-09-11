from __future__ import annotations

import copy
import hashlib
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
POLICY_RESOURCE = (
    LAUNCHER_ROOT / "towerscout_launcher" / "runtime-dependency-policy.v1.json"
)
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_dependency_policy as policy_module  # noqa: E402
from towerscout_launcher.runtime_dependency_policy import (  # noqa: E402
    DependencySignaturePolicy,
    DependencyPolicyErrorCode,
    PeMachine,
    RuntimeDependencyPolicyError,
    load_package_bound_runtime_dependency_policy,
    parse_package_bound_runtime_dependency_policy_bytes,
    parse_runtime_dependency_policy_bytes,
)
from towerscout_launcher.runtime_policy import RuntimeProductId  # noqa: E402

EXPECTED_POLICY_SHA256 = (
    "1c699ac7d2d2592305e876431d57231ef63e5ccdaaeb033c7d3526db307a3890"
)
EXPECTED_ARCHIVE_SHA256 = (
    "8649692de846c56a7189d6dae5c322ab20deb1b5908b6f39426b62a36f39415d"
)
EXPECTED_SIGNERS = (
    "f0e4f5974299809383869188a87d305827ace5a7336e7c35ed03858d5816ee62",
    "6045e624888e299179d5ae0ceda57c9874ff6ccf889fa14b2d50f751bfb9e2f8",
    "da3b7ce37f8d5abb20c2c3c982e99312dde1debb0dd46697689dd8357a420657",
    "7698e1de0131245a5ef86a3df9bc7c4de048b4684bdd0bc7891c3643d7f8b52e",
    "b665eca200033085fae5fc06086586223b79e226ab646b723012262c004e2a96",
)


def _checked_in_bytes() -> bytes:
    return POLICY_RESOURCE.read_bytes()


def _payload() -> dict[str, object]:
    return json.loads(_checked_in_bytes().decode("utf-8"))


def _encode(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _schema_error(payload: object) -> RuntimeDependencyPolicyError:
    with pytest.raises(RuntimeDependencyPolicyError) as failure:
        parse_runtime_dependency_policy_bytes(_encode(payload))
    assert failure.value.code is DependencyPolicyErrorCode.SCHEMA_INVALID
    return failure.value


def _cpython(payload: dict[str, object]) -> dict[str, object]:
    value = payload["cpython_artifact"]
    assert isinstance(value, dict)
    return value


def _loadable(payload: dict[str, object]) -> list[dict[str, object]]:
    value = _cpython(payload)["loadable_files"]
    assert isinstance(value, list)
    return value


def _non_amd64(payload: dict[str, object]) -> list[dict[str, object]]:
    value = _cpython(payload)["non_amd64_pe_files"]
    assert isinstance(value, list)
    return value


def test_checked_in_policy_is_the_exact_reviewed_dependency_policy() -> None:
    policy = load_package_bound_runtime_dependency_policy()

    assert policy.schema_version == 1
    assert policy.policy_id == "towerscout-runtime-dependency-policy-2026-09-08"
    assert policy.operating_system == "windows"
    assert policy.architecture == "amd64"
    assert policy.content_sha256 == EXPECTED_POLICY_SHA256
    assert hashlib.sha256(_checked_in_bytes()).hexdigest() == EXPECTED_POLICY_SHA256
    assert tuple(product.product_id for product in policy.products) == (
        RuntimeProductId.DOCKER_CLI,
        RuntimeProductId.DOCKER_COMPOSE,
        RuntimeProductId.PODMAN_CLI,
    )

    for product in policy.products:
        assert product.entrypoint_imports.direct == ("kernel32.dll",)
        assert product.entrypoint_imports.delay == ()
        assert product.entrypoint_imports.forwarded == ()
        assert product.declared_system_imports == ("kernel32.dll",)
        assert product.declared_api_set_imports == ()
        assert product.declared_private_imports == ()
        assert policy.product(product.product_id) is product


def test_cpython_policy_binds_exact_archive_native_files_and_signers() -> None:
    artifact = load_package_bound_runtime_dependency_policy().cpython

    assert artifact.product_id is RuntimeProductId.CPYTHON
    assert artifact.exact_version == "3.12.10"
    assert artifact.archive_sha256 == EXPECTED_ARCHIVE_SHA256
    assert artifact.pe_file_count == 47
    assert artifact.amd64_loadable_count == 43
    assert len(artifact.loadable_files) == 43
    assert len(artifact.non_amd64_pe_files) == 4
    assert (
        sum(
            record.signature_policy
            is DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER
            for record in artifact.loadable_files
        )
        == 39
    )
    assert (
        sum(
            record.signature_policy
            is DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY
            for record in artifact.loadable_files
        )
        == 4
    )
    assert (
        tuple(signer.certificate_sha256 for signer in artifact.signers)
        == EXPECTED_SIGNERS
    )
    assert {record.machine for record in artifact.non_amd64_pe_files} == {
        PeMachine.I386,
        PeMachine.ARM64,
    }
    assert all(
        record.signature_policy == "upstream_unsigned_exact_hash_only"
        for record in artifact.non_amd64_pe_files
    )
    assert any(record.path == "python.exe" for record in artifact.loadable_files)


def test_search_policy_is_closed_to_ambient_dll_sources() -> None:
    search = load_package_bound_runtime_dependency_policy().search

    assert search.parent_dll_directory == "empty"
    assert search.path == "empty"
    assert search.working_directory == "system32"
    assert search.application_directory == "held_exact_inventory"
    assert search.system_directory == "trusted_system32"
    assert search.external_manifests == "deny"
    assert search.dll_redirection == "deny"
    assert search.user_directories == "deny"
    assert search.image_load_mitigations == (
        "no_remote",
        "no_low_label",
        "prefer_system32",
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.__setitem__("schema", 2),
        lambda value: value.__setitem__("unexpected", True),
        lambda value: value["platform"].__setitem__("architecture", "arm64"),
        lambda value: value["search_policy"].__setitem__("path", "inherit"),
        lambda value: value["products"].reverse(),
        lambda value: _cpython(value).__setitem__("exact_version", "3.12.11"),
        lambda value: _cpython(value).__setitem__("pe_file_count", 46),
        lambda value: _cpython(value).__setitem__("archive_sha256", "0" * 64),
        lambda value: _cpython(value)["signers"][0].__setitem__(
            "certificate_sha256", "0" * 64
        ),
        lambda value: _loadable(value)[0].__setitem__(
            "signer_certificate_sha256", "0" * 64
        ),
        lambda value: _loadable(value)[0].__setitem__(
            "dependency_manifest_sha256", "INVALID"
        ),
        lambda value: _loadable(value)[0].__setitem__("path", "../private.dll"),
        lambda value: _non_amd64(value)[0].__setitem__("machine", "amd64"),
        lambda value: _non_amd64(value)[0].__setitem__(
            "signature_policy", "trust_unsigned"
        ),
        lambda value: _cpython(value)["declared_private_imports"].append(
            "unlisted-private.dll"
        ),
    ),
)
def test_policy_rejects_unreviewed_or_ambiguous_semantics(
    mutate,
) -> None:  # noqa: ANN001
    payload = _payload()
    mutate(payload)

    failure = _schema_error(payload)
    assert "python.org" not in str(failure)
    assert "private.dll" not in repr(failure)


def test_case_colliding_archive_paths_are_rejected() -> None:
    payload = _payload()
    records = _loadable(payload)
    records[1]["path"] = str(records[0]["path"]).swapcase()

    _schema_error(payload)


@pytest.mark.parametrize(
    "data",
    (
        b"\xef\xbb\xbf{}",
        b'{"schema":1,"schema":1}',
        b'{"schema":1.0}',
        b"\xff",
        b"{}\x00",
        b"[1,2,3]",
    ),
)
def test_malformed_or_non_object_policy_bytes_fail_closed(data: bytes) -> None:
    with pytest.raises(RuntimeDependencyPolicyError) as failure:
        parse_runtime_dependency_policy_bytes(data)

    assert failure.value.code in {
        DependencyPolicyErrorCode.FORMAT_INVALID,
        DependencyPolicyErrorCode.SCHEMA_INVALID,
    }


def test_package_binding_rejects_even_semantically_equivalent_bytes() -> None:
    equivalent = _checked_in_bytes() + b"\n"
    assert parse_runtime_dependency_policy_bytes(equivalent).content_sha256 != (
        EXPECTED_POLICY_SHA256
    )

    with pytest.raises(RuntimeDependencyPolicyError) as failure:
        parse_package_bound_runtime_dependency_policy_bytes(equivalent)

    assert failure.value.code is DependencyPolicyErrorCode.INTEGRITY_INVALID


def test_package_loader_reports_sanitized_unavailable_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Path(r"C:\Users\private-person\policy.json")
    monkeypatch.setattr(policy_module, "_POLICY_RESOURCE", private)

    with pytest.raises(RuntimeDependencyPolicyError) as failure:
        load_package_bound_runtime_dependency_policy()

    assert failure.value.code is DependencyPolicyErrorCode.RESOURCE_UNAVAILABLE
    assert "private-person" not in str(failure.value)
    assert "private-person" not in repr(failure.value)


def test_policy_models_are_frozen_and_representations_redact_artifact_facts() -> None:
    policy = load_package_bound_runtime_dependency_policy()
    artifact = policy.cpython
    record = artifact.loadable_files[0]

    with pytest.raises(FrozenInstanceError):
        policy.policy_id = "replacement"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        record.path = "replacement.dll"  # type: ignore[misc]

    rendered = repr((policy, artifact, record, artifact.signers[0]))
    assert record.path not in rendered
    assert record.sha256 not in rendered
    assert artifact.archive_url not in rendered
    assert EXPECTED_SIGNERS[0] not in rendered


def test_parser_is_inert_and_dependency_policy_remains_unwired() -> None:
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_dependency_policy.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "ctypes",
        "urllib.request",
        "socket",
        "requests",
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
        assert "runtime_dependency_policy" not in consumer


def test_copying_payload_does_not_mutate_checked_in_policy() -> None:
    payload = _payload()
    clone = copy.deepcopy(payload)
    _cpython(clone)["exact_version"] = "0.0.0"

    assert _cpython(payload)["exact_version"] == "3.12.10"
