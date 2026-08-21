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
POLICY_RESOURCE = LAUNCHER_ROOT / "towerscout_launcher" / "runtime-policy.v1.json"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_policy as runtime_policy_module  # noqa: E402
from towerscout_launcher.runtime_policy import (  # noqa: E402
    CatalogAuthentication,
    ExpiredSignerRule,
    InstallScope,
    InvocationKind,
    PolicyErrorCode,
    ProviderKind,
    RevocationRetrieval,
    RevocationScope,
    RuntimePolicyError,
    RuntimeProductId,
    SignatureForm,
    VersionEvidenceKind,
    load_package_bound_runtime_policy,
    parse_package_bound_runtime_policy_bytes,
    parse_runtime_policy_bytes,
)

EXPECTED_PRODUCTS = {
    RuntimeProductId.DOCKER_CLI: "29.7.2",
    RuntimeProductId.DOCKER_COMPOSE: "5.3.1",
    RuntimeProductId.PODMAN_CLI: "6.0.2",
    RuntimeProductId.CPYTHON: "3.12.10",
}
EXPECTED_SIGNERS = {
    RuntimeProductId.DOCKER_CLI: (
        "a1114dec9407df1bf9e52e13917d9a4257d18f2a23198ec3d391674308c30477",
        "Docker Inc",
        "Docker Inc",
        "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "0dce683683ae70c7c647addb7e609a9a",
        "2026-06-26T00:00:00Z",
        "2027-06-25T23:59:59Z",
        "rsa",
        4096,
    ),
    RuntimeProductId.DOCKER_COMPOSE: (
        "a1114dec9407df1bf9e52e13917d9a4257d18f2a23198ec3d391674308c30477",
        "Docker Inc",
        "Docker Inc",
        "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "0dce683683ae70c7c647addb7e609a9a",
        "2026-06-26T00:00:00Z",
        "2027-06-25T23:59:59Z",
        "rsa",
        4096,
    ),
    RuntimeProductId.PODMAN_CLI: (
        "a3e52b0d4273340dc8f5a0a0152cfd73d73d46aef7c5093fe5c10e3b80c30513",
        "Red Hat, Inc",
        "Red Hat, Inc",
        "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "0a717996ccf3ffaaf1d76b14a59dc089",
        "2023-06-15T00:00:00Z",
        "2026-08-07T23:59:59Z",
        "rsa",
        4096,
    ),
    RuntimeProductId.CPYTHON: (
        "f0e4f5974299809383869188a87d305827ace5a7336e7c35ed03858d5816ee62",
        "Python Software Foundation",
        "Python Software Foundation",
        "Microsoft ID Verified CS AOC CA 01",
        "3300033fcb65b25969c57e965c000000033fcb",
        "2025-04-08T01:07:24Z",
        "2025-04-11T01:07:24Z",
        "rsa",
        3072,
    ),
}


def _docker_records(
    leaf: str, *, compose: bool = False
) -> tuple[tuple[object, ...], ...]:
    suffix = "-compose" if compose else ""
    records = []
    for scope, hive in (
        ("system", "HKEY_LOCAL_MACHINE"),
        ("user", "HKEY_CURRENT_USER"),
    ):
        records.append(
            (
                f"docker-desktop-{scope}{suffix}",
                scope,
                hive,
                "registry64",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
                (
                    ("", "DisplayName", "Docker Desktop"),
                    ("", "Publisher", "Docker Inc."),
                ),
                "registry_directory_relative",
                rf"resources\bin\{leaf}",
                "",
                "InstallLocation",
                "",
                "",
            )
        )
    return tuple(records)


EXPECTED_INSTALL_RECORDS = {
    RuntimeProductId.DOCKER_CLI: _docker_records("docker.exe"),
    RuntimeProductId.DOCKER_COMPOSE: _docker_records(
        "docker-compose.exe", compose=True
    ),
    RuntimeProductId.PODMAN_CLI: (
        (
            "podman-cli-msi-userlocal-6.0.2",
            "user",
            "HKEY_LOCAL_MACHINE",
            "registry64",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0D5BAFD9-FE6A-4267-841A-7760A8F2B03C}",
            (
                ("", "DisplayName", "Podman CLI"),
                ("", "DisplayVersion", "6.0.2"),
                ("", "Publisher", "Podman"),
            ),
            "known_folder_relative",
            r"Programs\Podman\podman.exe",
            "",
            "",
            "",
            "local_app_data",
        ),
    ),
    RuntimeProductId.CPYTHON: tuple(
        (
            f"pythoncore-3.12-{scope}",
            scope,
            hive,
            "registry64",
            r"SOFTWARE\Python\PythonCore\3.12",
            (
                ("", "DisplayName", "Python 3.12.10"),
                ("", "SysArchitecture", "64bit"),
                ("", "Version", "3.12.10"),
            ),
            "registry_file",
            "",
            "InstallPath",
            "ExecutablePath",
            "python.exe",
            "",
        )
        for scope, hive in (
            ("system", "HKEY_LOCAL_MACHINE"),
            ("user", "HKEY_CURRENT_USER"),
        )
    ),
}


def _checked_in_bytes() -> bytes:
    return POLICY_RESOURCE.read_bytes()


def _payload() -> dict[str, object]:
    return json.loads(_checked_in_bytes().decode("utf-8"))


def _encode(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _product(payload: dict[str, object], product_id: str) -> dict[str, object]:
    products = payload["products"]
    assert isinstance(products, list)
    return next(
        item
        for item in products
        if isinstance(item, dict) and item.get("id") == product_id
    )


def _record_contract(record) -> tuple[object, ...]:  # noqa: ANN001
    return (
        record.record_id,
        record.scope.value,
        record.registry.hive,
        record.registry.view,
        record.registry.key,
        tuple(
            (value.subkey, value.name, value.equals)
            for value in record.registry.required_values
        ),
        record.location.kind.value,
        record.location.relative_path,
        record.location.value_subkey,
        record.location.value_name,
        record.location.required_leaf_name,
        record.location.known_folder,
    )


def _schema_error(payload: object) -> RuntimePolicyError:
    with pytest.raises(RuntimePolicyError) as failure:
        parse_runtime_policy_bytes(_encode(payload))
    assert failure.value.code is PolicyErrorCode.SCHEMA_INVALID
    return failure.value


def test_checked_in_policy_is_exact_initial_approved_policy() -> None:
    policy = load_package_bound_runtime_policy()

    assert policy.schema_version == 1
    assert policy.policy_id == "towerscout-runtime-policy-2026-08-21"
    assert policy.platform.operating_system == "windows"
    assert policy.platform.architecture == "amd64"
    assert {
        product.product_id: product.exact_version for product in policy.products
    } == (EXPECTED_PRODUCTS)

    for product in policy.products:
        assert len(product.signers) == 1
        signer = product.signers[0]
        assert (
            signer.certificate_sha256,
            signer.subject_common_name,
            signer.subject_organization,
            signer.issuer_common_name,
            signer.serial_number,
            signer.not_before_utc,
            signer.not_after_utc,
            signer.public_key_algorithm,
            signer.minimum_public_key_bits,
        ) == EXPECTED_SIGNERS[product.product_id]
        assert product.architecture == "amd64"
        assert product.file_hash_policy == "record_and_bind"
        assert product.file_identity_policy == "held_handle_record_and_revalidate"
        assert (
            tuple(_record_contract(record) for record in product.install_records)
            == EXPECTED_INSTALL_RECORDS[product.product_id]
        )

    assert policy.authenticode.signature_form is SignatureForm.EMBEDDED_AUTHENTICODE
    assert policy.authenticode.signature_cardinality == (
        "exactly_one_across_all_certificate_table_entries_and_nested_signatures"
    )
    assert policy.authenticode.file_digest_algorithm == "sha256"
    assert policy.authenticode.signer_signature_algorithm == "rsa_pkcs1v15"
    assert policy.authenticode.require_code_signing_eku is True
    assert policy.authenticode.require_windows_chain_trust is True
    assert policy.authenticode.revocation.retrieval is RevocationRetrieval.CACHE_ONLY
    assert policy.authenticode.revocation.scope is RevocationScope.WHOLE_CHAIN
    assert policy.authenticode.revocation.applies_to == (
        "signer_chain",
        "timestamp_chain",
    )
    assert policy.authenticode.revocation.revoked == "reject"
    assert policy.authenticode.revocation.unknown == "reject"
    assert policy.authenticode.revocation.offline == "reject"
    assert policy.authenticode.expired_signer is (
        ExpiredSignerRule.REQUIRE_VALID_TRUSTED_TIMESTAMP
    )
    assert policy.authenticode.trusted_timestamp == (
        "windows_trusted_time_within_signer_validity"
    )
    assert policy.authenticode.timestamp_cardinality == (
        "zero_or_one_require_one_when_signer_expired"
    )
    assert policy.authenticode.timestamp_form == "rfc3161"
    assert policy.authenticode.timestamp_digest_algorithm == "sha256"
    assert policy.authenticode.timestamp_signature_algorithm == "rsa_pkcs1v15"
    assert policy.updates.runtime_upgrade == "reviewed_policy_update_required"
    assert policy.updates.signer_rollover == "reviewed_policy_update_required"
    assert policy.updates.installation_record_change == (
        "reviewed_policy_update_required"
    )
    assert policy.bindings.docker.runtime_product_id is RuntimeProductId.DOCKER_CLI
    assert policy.bindings.docker.compose_product_id is (
        RuntimeProductId.DOCKER_COMPOSE
    )
    assert policy.bindings.podman.runtime_product_id is RuntimeProductId.PODMAN_CLI
    assert policy.bindings.podman.compose_provider_id == "podman-compose-pypi-1.5.0"


def test_checked_in_product_metadata_and_install_records_are_closed() -> None:
    policy = load_package_bound_runtime_policy()
    products = {product.product_id: product for product in policy.products}

    docker = products[RuntimeProductId.DOCKER_CLI]
    assert docker.executable_name == "docker.exe"
    assert docker.version_evidence.kind is VersionEvidenceKind.PE_VERSION_RESOURCE
    assert docker.version_evidence.company_name == "Docker Inc"
    assert docker.version_evidence.product_name == "Docker Client"
    assert docker.version_evidence.original_filename == "docker-windows-amd64.exe"
    assert {record.scope for record in docker.install_records} == {
        InstallScope.SYSTEM,
        InstallScope.USER,
    }
    assert {record.registry.hive for record in docker.install_records} == {
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
    }
    assert all(
        record.location.relative_path == r"resources\bin\docker.exe"
        for record in docker.install_records
    )

    compose = products[RuntimeProductId.DOCKER_COMPOSE]
    assert compose.executable_name == "docker-compose.exe"
    assert compose.version_evidence.kind is (
        VersionEvidenceKind.AUTHENTICATED_COMMAND_TEXT
    )
    assert compose.version_evidence.arguments == ("version", "--short")
    assert compose.version_evidence.exact_output == "5.3.1"
    assert all(
        record.location.relative_path == r"resources\bin\docker-compose.exe"
        for record in compose.install_records
    )

    podman = products[RuntimeProductId.PODMAN_CLI]
    assert podman.executable_name == "podman.exe"
    assert podman.version_evidence.kind is (
        VersionEvidenceKind.AUTHENTICATED_COMMAND_JSON
    )
    assert podman.version_evidence.arguments == ("version", "--format", "json")
    assert podman.version_evidence.json_pointer == "/Client/Version"
    assert len(podman.install_records) == 1
    assert podman.install_records[0].location.known_folder == "local_app_data"
    assert podman.install_records[0].location.relative_path == (
        r"Programs\Podman\podman.exe"
    )

    python = products[RuntimeProductId.CPYTHON]
    assert python.executable_name == "python.exe"
    assert python.version_evidence.kind is VersionEvidenceKind.PE_VERSION_RESOURCE
    assert python.version_evidence.company_name == "Python Software Foundation"
    assert python.version_evidence.product_name == "Python"
    assert python.version_evidence.original_filename == "python.exe"
    assert {record.scope for record in python.install_records} == {
        InstallScope.SYSTEM,
        InstallScope.USER,
    }
    assert all(
        record.location.value_subkey == "InstallPath"
        and record.location.value_name == "ExecutablePath"
        for record in python.install_records
    )


def test_managed_podman_compose_policy_is_reproducible_and_direct() -> None:
    provider = load_package_bound_runtime_policy().podman_compose

    assert provider.kind is ProviderKind.TOWERSCOUT_MANAGED
    assert provider.provider_id == "podman-compose-pypi-1.5.0"
    assert provider.exact_version == "1.5.0"
    assert provider.interpreter.base_product_id is RuntimeProductId.CPYTHON
    assert provider.interpreter.relative_path == r".venv\Scripts\python.exe"
    assert provider.interpreter.require_same_authenticode_signer is True
    assert provider.interpreter.require_same_pe_product_version is True
    assert provider.interpreter.require_file_hash is True
    assert provider.interpreter.require_stable_file_identity is True
    assert provider.interpreter.require_authenticated_base_runtime_closure is True
    assert provider.interpreter.require_venv_config_base_path_match is True
    assert provider.invocation.kind is InvocationKind.PYTHON_ISOLATED_MODULE
    assert provider.invocation.arguments == ("-I", "-m", "podman_compose")
    assert provider.invocation.module == "podman_compose"
    assert provider.catalog.catalog_id == (
        "towerscout-managed-podman-compose-2026-08-21"
    )
    assert provider.catalog.authentication is (
        CatalogAuthentication.RUNTIME_POLICY_EXACT_BYTES
    )
    assert {
        (distribution.name, distribution.version, distribution.wheel_sha256)
        for distribution in provider.distributions
    } == {
        (
            "podman-compose",
            "1.5.0",
            "f0b9d35f4da1b309172adf208a5cb7a882b532a834c2202666c1988b6f147546",
        ),
        (
            "python-dotenv",
            "1.1.1",
            "31f23644fe2602f88ff55e1f5c79ba497e01224ee7737937930c448e4d0e24dc",
        ),
        (
            "PyYAML",
            "6.0.3",
            "5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b",
        ),
    }
    assert provider.endpoint_propagation.required_variables == (
        "CONTAINER_HOST",
        "CONTAINER_SSHKEY",
    )
    assert provider.endpoint_propagation.allow_provider_rediscovery is False
    assert provider.verification.require_hash_verified_installer_inputs is True
    assert provider.verification.require_fresh_reconstruction_comparison is True
    assert provider.verification.require_exact_distribution_inventory is True
    assert provider.verification.require_record_hashes is True
    assert provider.verification.require_module_hash is True
    assert provider.verification.require_generated_entrypoint_hash is True
    assert provider.verification.require_stable_file_identity is True
    assert provider.verification.receipt_is_trust_anchor is False
    assert provider.inventory.site_packages_relative_path == (
        r".venv\Lib\site-packages"
    )
    assert provider.inventory.module_relative_path == (
        r".venv\Lib\site-packages\podman_compose.py"
    )
    assert provider.inventory.generated_entrypoint_relative_path == (
        r".venv\Scripts\podman-compose.exe"
    )
    assert provider.inventory.venv_config_relative_path == r".venv\pyvenv.cfg"
    assert provider.inventory.loadable_suffixes == (
        ".py",
        ".pyc",
        ".pyd",
        ".dll",
        ".pth",
    )
    assert provider.inventory.require_exact_authenticated_install_tree is True
    assert provider.inventory.reject_unowned_loadable_files is True
    assert provider.inventory.reject_extra_distributions is True
    assert provider.inventory.reject_pth_files is True
    assert provider.allow_external is False
    assert provider.allow_docker_desktop is False
    assert provider.allow_command_wrapper is False
    assert provider.allow_podman_compose_delegation is False


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    (
        (b"\xef\xbb\xbf{}", PolicyErrorCode.FORMAT_INVALID),
        (b'{"schema_version": 1}\x00', PolicyErrorCode.FORMAT_INVALID),
        (b"\xff", PolicyErrorCode.FORMAT_INVALID),
        (
            b'{"schema_version":1,"schema_version":1}',
            PolicyErrorCode.FORMAT_INVALID,
        ),
        (b'{"schema_version":NaN}', PolicyErrorCode.FORMAT_INVALID),
        (b'{"schema_version":Infinity}', PolicyErrorCode.FORMAT_INVALID),
        (b'{"schema_version":1.0}', PolicyErrorCode.FORMAT_INVALID),
        (
            b'{"schema_version":' + (b"9" * 5000) + b"}",
            PolicyErrorCode.FORMAT_INVALID,
        ),
        (b" " * (128 * 1024 + 1), PolicyErrorCode.FORMAT_INVALID),
    ),
    ids=(
        "utf8-bom",
        "nul-byte",
        "invalid-utf8",
        "duplicate-member",
        "nan",
        "infinity",
        "float",
        "huge-integer",
        "oversized-document",
    ),
)
def test_strict_json_format_rejects_ambiguous_or_unbounded_bytes(
    payload: bytes, expected_code: PolicyErrorCode
) -> None:
    with pytest.raises(RuntimePolicyError) as failure:
        parse_runtime_policy_bytes(payload)
    assert failure.value.code is expected_code


def test_strict_json_rejects_excessive_nesting_and_string_size() -> None:
    nested = b'{"x":' + (b"[" * 24) + b"0" + (b"]" * 24) + b"}"
    with pytest.raises(RuntimePolicyError) as depth_failure:
        parse_runtime_policy_bytes(nested)
    assert depth_failure.value.code is PolicyErrorCode.FORMAT_INVALID

    oversized_string = json.dumps({"x": "a" * 4097}).encode("utf-8")
    with pytest.raises(RuntimePolicyError) as string_failure:
        parse_runtime_policy_bytes(oversized_string)
    assert string_failure.value.code is PolicyErrorCode.FORMAT_INVALID


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload.pop("policy_id"),
        lambda payload: payload.__setitem__("unexpected", True),
        lambda payload: payload.__setitem__("schema_version", True),
        lambda payload: payload.__setitem__("schema_version", 2),
        lambda payload: payload["platform"].__setitem__("unexpected", "value"),
        lambda payload: payload["updates"].__setitem__("runtime_upgrade", "automatic"),
    ),
)
def test_missing_unknown_wrong_type_and_unsupported_schema_fail_closed(
    mutation,
) -> None:  # noqa: ANN001
    payload = _payload()
    mutation(payload)
    _schema_error(payload)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("signature_form", "catalog_authenticode"),
        ("signature_form", "unsigned"),
        ("signature_cardinality", "at_least_one"),
        ("file_digest_algorithm", "sha1"),
        ("signer_signature_algorithm", "dsa"),
        ("require_code_signing_eku", False),
        ("require_windows_chain_trust", False),
        ("unhashed_pe_regions", "ignore"),
        ("expired_signer", "allow"),
        ("trusted_timestamp", "optional"),
        ("timestamp_cardinality", "one_or_more"),
        ("timestamp_form", "legacy_countersignature"),
        ("timestamp_digest_algorithm", "sha1"),
        ("timestamp_signature_algorithm", "dsa"),
    ),
)
def test_authenticode_policy_cannot_be_relaxed(
    field: str, unsafe_value: object
) -> None:
    payload = _payload()
    payload["authenticode"][field] = unsafe_value
    _schema_error(payload)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("retrieval", "online"),
        ("scope", "end_certificate"),
        ("applies_to", ["signer_chain"]),
        ("applies_to", ["signer_chain", "untrusted_timestamp_chain"]),
        ("revoked", "allow"),
        ("unknown", "allow"),
        ("offline", "allow"),
    ),
)
def test_revocation_unknown_and_offline_results_always_fail_closed(
    field: str, unsafe_value: object
) -> None:
    payload = _payload()
    payload["authenticode"]["revocation"][field] = unsafe_value
    _schema_error(payload)


@pytest.mark.parametrize(
    ("engine", "field", "unsafe_value"),
    (
        ("docker", "runtime_product_id", "podman-cli"),
        ("docker", "compose_product_id", "podman-cli"),
        ("podman", "runtime_product_id", "docker-cli"),
        ("podman", "compose_provider_id", "docker-compose"),
    ),
)
def test_engine_to_compose_bindings_are_exact_and_cannot_cross(
    engine: str, field: str, unsafe_value: str
) -> None:
    payload = _payload()
    payload["bindings"][engine][field] = unsafe_value
    _schema_error(payload)


@pytest.mark.parametrize(
    "unsafe_version",
    ("29.7", "29.7.2.0", ">=29.7.2", "29.*", "latest", " 29.7.2", "29.7.3"),
)
def test_runtime_versions_are_exact_and_policy_updates_are_explicit(
    unsafe_version: str,
) -> None:
    payload = _payload()
    _product(payload, "docker-cli")["exact_version"] = unsafe_version
    _schema_error(payload)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("file_hash_policy", "best_effort"),
        ("file_identity_policy", "path_only"),
        ("file_identity_policy", "record_without_revalidation"),
    ),
)
def test_native_products_require_hash_and_held_identity_revalidation(
    field: str, unsafe_value: str
) -> None:
    payload = _payload()
    _product(payload, "docker-cli")[field] = unsafe_value
    _schema_error(payload)


def test_product_set_is_exact_unique_and_ordered() -> None:
    for mutation in ("missing", "duplicate", "extra", "reordered"):
        payload = _payload()
        products = payload["products"]
        assert isinstance(products, list)
        if mutation == "missing":
            products.pop()
        elif mutation == "duplicate":
            products.append(copy.deepcopy(products[0]))
        elif mutation == "extra":
            extra = copy.deepcopy(products[0])
            extra["id"] = "unreviewed-runtime"
            products.append(extra)
        else:
            products[0], products[1] = products[1], products[0]
        _schema_error(payload)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("subject_organization", "docker inc"),
        ("subject_organization", "Docker Inc "),
        ("certificate_sha256", "A" * 64),
        ("certificate_sha256", "a" * 63),
        ("serial_number", "not-hex"),
        ("public_key_algorithm", "ec"),
        ("minimum_public_key_bits", True),
    ),
)
def test_publisher_and_signer_identity_cannot_drift(
    field: str, unsafe_value: object
) -> None:
    payload = _payload()
    signer = _product(payload, "docker-cli")["signers"][0]
    signer[field] = unsafe_value
    _schema_error(payload)


def test_confusable_publisher_identity_is_rejected_before_schema_use() -> None:
    payload = _payload()
    signer = _product(payload, "docker-cli")["signers"][0]
    signer["subject_organization"] = "D\u043ecker Inc"
    with pytest.raises(RuntimePolicyError) as failure:
        parse_runtime_policy_bytes(_encode(payload))
    assert failure.value.code is PolicyErrorCode.FORMAT_INVALID


def test_signer_rollover_or_ambiguous_multiple_signatures_require_policy_update() -> (
    None
):
    payload = _payload()
    product = _product(payload, "docker-cli")
    product["signers"].append(copy.deepcopy(product["signers"][0]))
    _schema_error(payload)

    payload = _payload()
    signer = _product(payload, "docker-cli")["signers"][0]
    signer["certificate_sha256"] = "b" * 64
    _schema_error(payload)


@pytest.mark.parametrize(
    "mutator",
    (
        lambda record: record["registry"].__setitem__("hive", "HKEY_CLASSES_ROOT"),
        lambda record: record["registry"].__setitem__("view", "default"),
        lambda record: record["registry"].__setitem__(
            "key", r"SOFTWARE\Attacker\Runtime"
        ),
        lambda record: record["location"].__setitem__("kind", "path_search"),
        lambda record: record["location"].__setitem__(
            "relative_path", r"..\attacker.exe"
        ),
        lambda record: record["location"].__setitem__(
            "relative_path", r"%PATH%\docker.exe"
        ),
    ),
)
def test_path_cwd_environment_and_unreviewed_install_records_are_rejected(
    mutator,
) -> None:  # noqa: ANN001
    payload = _payload()
    record = _product(payload, "docker-cli")["install_records"][0]
    mutator(record)
    _schema_error(payload)


def test_install_record_ids_and_candidates_must_be_nonempty_and_unique() -> None:
    payload = _payload()
    product = _product(payload, "docker-cli")
    product["install_records"] = []
    _schema_error(payload)

    payload = _payload()
    product = _product(payload, "docker-cli")
    product["install_records"].append(copy.deepcopy(product["install_records"][0]))
    _schema_error(payload)


@pytest.mark.parametrize(
    ("path", "unsafe_value"),
    (
        (("kind",), "external"),
        (("provider_id",), "docker-compose-standalone-5.3.1"),
        (("interpreter", "base_product_id"), "docker-cli"),
        (("interpreter", "relative_path"), r".venv\Scripts\python.cmd"),
        (("interpreter", "require_same_authenticode_signer"), False),
        (("interpreter", "require_authenticated_base_runtime_closure"), False),
        (("allow_external",), True),
        (("allow_docker_desktop",), True),
        (("allow_command_wrapper",), True),
        (("allow_podman_compose_delegation",), True),
        (("invocation", "kind"), "command_wrapper"),
        (("invocation", "arguments"), ["podman", "compose"]),
        (("endpoint_propagation", "allow_provider_rediscovery"), True),
        (("verification", "receipt_is_trust_anchor"), True),
        (("verification", "require_record_hashes"), False),
        (("verification", "require_hash_verified_installer_inputs"), False),
        (("catalog", "authentication"), "external_catalog"),
        (("catalog", "catalog_id"), "unreviewed-catalog"),
        (("inventory", "require_exact_authenticated_install_tree"), False),
        (("inventory", "reject_unowned_loadable_files"), False),
        (("inventory", "reject_pth_files"), False),
    ),
)
def test_podman_compose_cannot_fall_back_to_external_or_name_version_evidence(
    path: tuple[str, ...], unsafe_value: object
) -> None:
    payload = _payload()
    target = payload["podman_compose"]
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = unsafe_value
    _schema_error(payload)


def test_inline_catalog_rejects_external_path_and_additional_providers() -> None:
    for field, value in (
        ("path", r"scripts\podman-compose-providers.v1.json"),
        ("providers", []),
    ):
        payload = _payload()
        payload["podman_compose"]["catalog"][field] = value
        _schema_error(payload)


def test_provider_distribution_inventory_and_hashes_are_exact() -> None:
    payload = _payload()
    provider = payload["podman_compose"]
    provider["distributions"][0]["wheel_sha256"] = ""
    _schema_error(payload)

    payload = _payload()
    provider = payload["podman_compose"]
    provider["distributions"].append(copy.deepcopy(provider["distributions"][0]))
    _schema_error(payload)

    payload = _payload()
    provider = payload["podman_compose"]
    provider["distributions"][2][
        "wheel_filename"
    ] = "pyyaml-6.0.3-cp311-cp311-win_amd64.whl"
    _schema_error(payload)


def test_version_evidence_is_product_specific_and_not_version_output_only() -> None:
    payload = _payload()
    docker = _product(payload, "docker-cli")
    docker["version_evidence"] = {
        "arguments": ["--version"],
        "exact_output": "29.7.2",
        "kind": "authenticated_command_text",
    }
    _schema_error(payload)

    payload = _payload()
    podman = _product(payload, "podman-cli")
    podman["version_evidence"]["arguments"] = ["--version"]
    _schema_error(payload)


def test_policy_digest_binds_every_exact_byte_and_pinned_loader_rejects_drift() -> None:
    original = _checked_in_bytes()
    policy = parse_runtime_policy_bytes(original)
    assert policy.content_sha256 == hashlib.sha256(original).hexdigest()
    assert load_package_bound_runtime_policy().content_sha256 == policy.content_sha256

    changed = original + b" "
    parsed_changed = parse_runtime_policy_bytes(changed)
    assert parsed_changed.content_sha256 != policy.content_sha256
    with pytest.raises(RuntimePolicyError) as failure:
        parse_package_bound_runtime_policy_bytes(changed)
    assert failure.value.code is PolicyErrorCode.INTEGRITY_INVALID


def test_package_binding_rejects_oversize_before_hash_and_bounds_resource_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = b"x" * (128 * 1024 + 1)
    with pytest.raises(RuntimePolicyError) as direct_failure:
        parse_package_bound_runtime_policy_bytes(oversized)
    assert direct_failure.value.code is PolicyErrorCode.INTEGRITY_INVALID

    observed_read_sizes: list[int] = []

    class _BoundedStream:
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            observed_read_sizes.append(size)
            return b"x" * size

    class _FakeResource:
        def open(self, mode: str) -> _BoundedStream:
            assert mode == "rb"
            return _BoundedStream()

    monkeypatch.setattr(runtime_policy_module, "_POLICY_RESOURCE", _FakeResource())
    with pytest.raises(RuntimePolicyError) as loader_failure:
        load_package_bound_runtime_policy()
    assert loader_failure.value.code is PolicyErrorCode.INTEGRITY_INVALID
    assert observed_read_sizes == [128 * 1024 + 1]


def test_models_are_deeply_immutable_and_repr_is_redacted() -> None:
    policy = load_package_bound_runtime_policy()
    private_markers = (
        policy.products[0].signers[0].certificate_sha256,
        policy.products[0].install_records[0].registry.key,
        policy.podman_compose.distributions[0].source_url,
    )
    rendered = " ".join(
        (
            repr(policy),
            repr(policy.products[0]),
            repr(policy.products[0].signers[0]),
            repr(policy.podman_compose),
        )
    )
    assert all(marker not in rendered for marker in private_markers)
    assert isinstance(policy.products, tuple)
    assert isinstance(policy.products[0].signers, tuple)
    assert isinstance(policy.products[0].install_records, tuple)
    assert isinstance(policy.podman_compose.distributions, tuple)
    with pytest.raises(FrozenInstanceError):
        policy.policy_id = "attacker"  # type: ignore[misc]


def test_errors_are_sanitized_and_do_not_echo_hostile_values() -> None:
    payload = _payload()
    private_value = r"C:\Users\private\attacker.exe"
    record = _product(payload, "docker-cli")["install_records"][0]
    record["location"]["relative_path"] = private_value

    failure = _schema_error(payload)

    assert private_value not in str(failure)
    assert private_value not in repr(failure)


def test_policy_layer_is_inert_and_pyinstaller_bundles_exact_resource() -> None:
    source = (LAUNCHER_ROOT / "towerscout_launcher" / "runtime_policy.py").read_text(
        encoding="utf-8"
    )
    lowered = source.lower()
    for forbidden in (
        "subprocess",
        "shutil",
        "winreg",
        "ctypes",
        "powershell",
        "cmd.exe",
        "os.system",
        "popen",
    ):
        assert forbidden not in lowered

    spec = (LAUNCHER_ROOT / "TowerScoutLauncher.spec").read_text(encoding="utf-8")
    assert (
        'runtime_policy_path = launcher_root / "towerscout_launcher" / '
        '"runtime-policy.v1.json"'
    ) in spec
    assert 'datas=[(str(runtime_policy_path), "towerscout_launcher")]' in spec
