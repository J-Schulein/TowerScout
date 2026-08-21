"""Strict, inert parser for TowerScout's package-bound runtime policy.

This module performs no executable discovery, native trust verification, or
child execution.  It accepts only the first reviewed Windows/AMD64 policy and
returns deeply immutable models for later handle-bound resolver work.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Any, NoReturn
from urllib.parse import urlsplit

_POLICY_RESOURCE = Path(__file__).with_name("runtime-policy.v1.json")
_PACKAGE_POLICY_SHA256 = (
    "6c198c097b511d9a73c168a244c89f5932a27abd12b5870118a80c46c5356011"
)
_MAX_POLICY_BYTES = 128 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_COLLECTION_ITEMS = 64
_MAX_JSON_NODES = 4096
_MAX_JSON_STRING = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SERIAL = re.compile(r"^(?:[0-9a-f]{2}){1,32}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REGISTRY_COMPONENT = re.compile(r"^[A-Za-z0-9 ._{}()-]+$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class PolicyErrorCode(str, Enum):
    FORMAT_INVALID = "format_invalid"
    SCHEMA_INVALID = "schema_invalid"
    INTEGRITY_INVALID = "integrity_invalid"
    RESOURCE_UNAVAILABLE = "resource_unavailable"


class RuntimePolicyError(ValueError):
    """Sanitized policy failure with no untrusted value or local path."""

    _MESSAGES = {
        PolicyErrorCode.FORMAT_INVALID: "The runtime policy format is invalid.",
        PolicyErrorCode.SCHEMA_INVALID: "The runtime policy schema is invalid.",
        PolicyErrorCode.INTEGRITY_INVALID: "The runtime policy integrity check failed.",
        PolicyErrorCode.RESOURCE_UNAVAILABLE: "The package runtime policy is unavailable.",
    }

    def __init__(self, code: PolicyErrorCode) -> None:
        if type(code) is not PolicyErrorCode:
            raise ValueError("Unknown runtime-policy error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimePolicyError(code={self.code.value!r})"


class SignatureForm(str, Enum):
    EMBEDDED_AUTHENTICODE = "embedded_authenticode"


class RevocationRetrieval(str, Enum):
    CACHE_ONLY = "cache_only"


class RevocationScope(str, Enum):
    WHOLE_CHAIN = "whole_chain"


class ExpiredSignerRule(str, Enum):
    REQUIRE_VALID_TRUSTED_TIMESTAMP = "require_valid_trusted_timestamp"


class RuntimeProductId(str, Enum):
    DOCKER_CLI = "docker-cli"
    DOCKER_COMPOSE = "docker-compose"
    PODMAN_CLI = "podman-cli"
    CPYTHON = "cpython"


class ProductRole(str, Enum):
    RUNTIME = "runtime"
    COMPOSE = "compose"
    INTERPRETER = "interpreter"


class VersionEvidenceKind(str, Enum):
    PE_VERSION_RESOURCE = "pe_version_resource"
    AUTHENTICATED_COMMAND_TEXT = "authenticated_command_text"
    AUTHENTICATED_COMMAND_JSON = "authenticated_command_json"


class InstallScope(str, Enum):
    SYSTEM = "system"
    USER = "user"


class LocationKind(str, Enum):
    REGISTRY_DIRECTORY_RELATIVE = "registry_directory_relative"
    REGISTRY_FILE = "registry_file"
    KNOWN_FOLDER_RELATIVE = "known_folder_relative"


class ProviderKind(str, Enum):
    TOWERSCOUT_MANAGED = "towerscout_managed"


class CatalogAuthentication(str, Enum):
    RUNTIME_POLICY_EXACT_BYTES = "runtime_policy_exact_bytes"


class InvocationKind(str, Enum):
    PYTHON_ISOLATED_MODULE = "python_isolated_module"


@dataclass(frozen=True, slots=True)
class PlatformPolicy:
    operating_system: str
    architecture: str


@dataclass(frozen=True, slots=True)
class UpdatePolicy:
    runtime_upgrade: str
    signer_rollover: str
    installation_record_change: str


@dataclass(frozen=True, slots=True)
class DockerComposeBindingPolicy:
    runtime_product_id: RuntimeProductId
    compose_product_id: RuntimeProductId


@dataclass(frozen=True, slots=True)
class PodmanComposeBindingPolicy:
    runtime_product_id: RuntimeProductId
    compose_provider_id: str


@dataclass(frozen=True, slots=True)
class RuntimeBindingsPolicy:
    docker: DockerComposeBindingPolicy
    podman: PodmanComposeBindingPolicy


@dataclass(frozen=True, slots=True)
class RevocationPolicy:
    retrieval: RevocationRetrieval
    scope: RevocationScope
    applies_to: tuple[str, ...]
    revoked: str
    unknown: str
    offline: str


@dataclass(frozen=True, slots=True)
class AuthenticodePolicy:
    signature_form: SignatureForm
    signature_cardinality: str
    file_digest_algorithm: str
    signer_signature_algorithm: str
    require_code_signing_eku: bool
    require_windows_chain_trust: bool
    unhashed_pe_regions: str
    revocation: RevocationPolicy
    expired_signer: ExpiredSignerRule
    trusted_timestamp: str
    timestamp_cardinality: str
    timestamp_form: str
    timestamp_digest_algorithm: str
    timestamp_signature_algorithm: str


@dataclass(frozen=True, slots=True, repr=False)
class SignerCertificatePolicy:
    certificate_sha256: str = field(repr=False)
    subject_common_name: str
    subject_organization: str
    issuer_common_name: str
    serial_number: str = field(repr=False)
    not_before_utc: str
    not_after_utc: str
    public_key_algorithm: str
    minimum_public_key_bits: int

    def __repr__(self) -> str:
        return (
            "SignerCertificatePolicy("
            f"organization={self.subject_organization!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class VersionEvidencePolicy:
    kind: VersionEvidenceKind
    arguments: tuple[str, ...] = ()
    company_name: str = ""
    product_name: str = ""
    original_filename: str = ""
    file_version: str = ""
    product_version: str = ""
    exact_output: str = ""
    json_pointer: str = ""

    def __repr__(self) -> str:
        return f"VersionEvidencePolicy(kind={self.kind.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class RegistryValuePolicy:
    subkey: str
    name: str
    equals: str = field(repr=False)

    def __repr__(self) -> str:
        return f"RegistryValuePolicy(name={self.name!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RegistryRecordPolicy:
    hive: str
    view: str
    key: str = field(repr=False)
    required_values: tuple[RegistryValuePolicy, ...] = field(repr=False)

    def __repr__(self) -> str:
        return f"RegistryRecordPolicy(hive={self.hive!r}, view={self.view!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ExecutableLocationPolicy:
    kind: LocationKind
    relative_path: str = field(default="", repr=False)
    value_subkey: str = field(default="", repr=False)
    value_name: str = field(default="", repr=False)
    required_leaf_name: str = field(default="", repr=False)
    known_folder: str = field(default="", repr=False)

    def __repr__(self) -> str:
        return f"ExecutableLocationPolicy(kind={self.kind.value!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class InstallRecordPolicy:
    record_id: str
    scope: InstallScope
    registry: RegistryRecordPolicy = field(repr=False)
    location: ExecutableLocationPolicy = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"InstallRecordPolicy(id={self.record_id!r}, "
            f"scope={self.scope.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProductPolicy:
    product_id: RuntimeProductId
    role: ProductRole
    executable_name: str
    architecture: str
    exact_version: str
    version_evidence: VersionEvidencePolicy = field(repr=False)
    signers: tuple[SignerCertificatePolicy, ...] = field(repr=False)
    install_records: tuple[InstallRecordPolicy, ...] = field(repr=False)
    file_hash_policy: str
    file_identity_policy: str

    def __repr__(self) -> str:
        return (
            f"ProductPolicy(id={self.product_id.value!r}, "
            f"version={self.exact_version!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CatalogPolicy:
    catalog_id: str
    authentication: CatalogAuthentication

    def __repr__(self) -> str:
        return f"CatalogPolicy(id={self.catalog_id!r})"


@dataclass(frozen=True, slots=True, repr=False)
class DistributionPolicy:
    name: str
    version: str
    wheel_filename: str
    source_url: str = field(repr=False)
    wheel_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"DistributionPolicy(name={self.name!r}, version={self.version!r}, "
            "<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class ProviderInvocationPolicy:
    kind: InvocationKind
    arguments: tuple[str, ...]
    module: str


@dataclass(frozen=True, slots=True, repr=False)
class ManagedInterpreterPolicy:
    relative_path: str = field(repr=False)
    base_product_id: RuntimeProductId
    relationship: str
    require_same_authenticode_signer: bool
    require_same_pe_product_version: bool
    require_file_hash: bool
    require_stable_file_identity: bool
    require_authenticated_base_runtime_closure: bool
    require_venv_config_base_path_match: bool

    def __repr__(self) -> str:
        return (
            "ManagedInterpreterPolicy("
            f"base_product_id={self.base_product_id.value!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True)
class EndpointPropagationPolicy:
    mechanism: str
    required_variables: tuple[str, ...]
    allow_provider_rediscovery: bool


@dataclass(frozen=True, slots=True)
class ProviderVerificationPolicy:
    require_hash_verified_installer_inputs: bool
    require_fresh_reconstruction_comparison: bool
    require_exact_distribution_inventory: bool
    require_record_hashes: bool
    require_module_hash: bool
    require_generated_entrypoint_hash: bool
    require_stable_file_identity: bool
    receipt_is_trust_anchor: bool


@dataclass(frozen=True, slots=True, repr=False)
class ProviderInventoryPolicy:
    site_packages_relative_path: str = field(repr=False)
    module_relative_path: str = field(repr=False)
    generated_entrypoint_relative_path: str = field(repr=False)
    venv_config_relative_path: str = field(repr=False)
    record_validation: str
    loadable_suffixes: tuple[str, ...]
    require_exact_authenticated_install_tree: bool
    reject_unowned_loadable_files: bool
    reject_extra_distributions: bool
    reject_pth_files: bool
    reject_sitecustomize: bool
    reject_usercustomize: bool

    def __repr__(self) -> str:
        return "ProviderInventoryPolicy(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PodmanComposePolicy:
    kind: ProviderKind
    provider_id: str
    exact_version: str
    managed_install_root: str = field(repr=False)
    catalog: CatalogPolicy = field(repr=False)
    interpreter: ManagedInterpreterPolicy = field(repr=False)
    invocation: ProviderInvocationPolicy
    endpoint_propagation: EndpointPropagationPolicy
    distributions: tuple[DistributionPolicy, ...] = field(repr=False)
    inventory: ProviderInventoryPolicy = field(repr=False)
    verification: ProviderVerificationPolicy
    allow_external: bool
    allow_docker_desktop: bool
    allow_command_wrapper: bool
    allow_podman_compose_delegation: bool

    def __repr__(self) -> str:
        return (
            f"PodmanComposePolicy(id={self.provider_id!r}, "
            f"version={self.exact_version!r}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimePolicy:
    schema_version: int
    policy_id: str
    platform: PlatformPolicy
    updates: UpdatePolicy
    bindings: RuntimeBindingsPolicy
    authenticode: AuthenticodePolicy
    products: tuple[ProductPolicy, ...] = field(repr=False)
    podman_compose: PodmanComposePolicy = field(repr=False)
    content_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"RuntimePolicy(id={self.policy_id!r}, "
            f"products={len(self.products)}, <redacted>)"
        )


class _FormatFailure(Exception):
    pass


class _SchemaFailure(Exception):
    pass


def _fail_schema() -> NoReturn:
    raise _SchemaFailure


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in output:
            raise _FormatFailure
        output[key] = value
    return output


def _reject_constant(_value: str) -> NoReturn:
    raise _FormatFailure


def _strict_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 19:
        raise _FormatFailure
    try:
        return int(value, 10)
    except (TypeError, ValueError, OverflowError):
        raise _FormatFailure from None


def _reject_float(_value: str) -> NoReturn:
    raise _FormatFailure


def _walk_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
        raise _FormatFailure
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING:
            raise _FormatFailure
        try:
            encoded = value.encode("ascii", errors="strict")
        except UnicodeError:
            raise _FormatFailure from None
        if any(byte < 0x20 or byte == 0x7F for byte in encoded):
            raise _FormatFailure
        return
    if type(value) in {bool, int}:
        if type(value) is int and not -(2**63) <= value < 2**63:
            raise _FormatFailure
        return
    if type(value) is list:
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            raise _FormatFailure
        for item in value:
            _walk_json(item, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict:
        if len(value) > _MAX_JSON_COLLECTION_ITEMS:
            raise _FormatFailure
        for key, item in value.items():
            _walk_json(key, depth=depth + 1, nodes=nodes)
            _walk_json(item, depth=depth + 1, nodes=nodes)
        return
    raise _FormatFailure


def _decode_policy(data: bytes) -> dict[str, Any]:
    if (
        type(data) is not bytes
        or not 1 <= len(data) <= _MAX_POLICY_BYTES
        or data.startswith(b"\xef\xbb\xbf")
        or b"\x00" in data
    ):
        raise RuntimePolicyError(PolicyErrorCode.FORMAT_INVALID)
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_int=_strict_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        _walk_json(value, depth=0, nodes=[0])
    except (
        UnicodeError,
        json.JSONDecodeError,
        OverflowError,
        ValueError,
        RecursionError,
        _FormatFailure,
    ):
        raise RuntimePolicyError(PolicyErrorCode.FORMAT_INVALID) from None
    if type(value) is not dict:
        raise RuntimePolicyError(PolicyErrorCode.SCHEMA_INVALID)
    return value


def _object(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail_schema()
    return value


def _array(value: Any, *, minimum: int = 1, maximum: int = 16) -> list[Any]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        _fail_schema()
    return value


def _text(value: Any, *, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value or value != value.strip():
        _fail_schema()
    if pattern is not None and not pattern.fullmatch(value):
        _fail_schema()
    return value


def _optional_text(value: Any) -> str:
    if type(value) is not str or value != value.strip():
        _fail_schema()
    return value


def _exact_bool(value: Any, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _fail_schema()
    return value


def _exact_int(value: Any, expected: int) -> int:
    if type(value) is not int or value != expected:
        _fail_schema()
    return value


def _enum(value: Any, enum_type: type[Enum]) -> Any:
    if type(value) is not str:
        _fail_schema()
    try:
        return enum_type(value)
    except ValueError:
        _fail_schema()


def _safe_relative_path(value: Any, *, expected_leaf: str | None = None) -> str:
    text = _text(value)
    if (
        "/" in text
        or "%" in text
        or "$" in text
        or "\x00" in text
        or text.startswith("\\")
    ):
        _fail_schema()
    path = PureWindowsPath(text)
    if path.is_absolute() or path.drive or path.root or len(path.parts) < 1:
        _fail_schema()
    for part in path.parts:
        base = part.split(".", 1)[0].casefold()
        if (
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or base in _WINDOWS_RESERVED_NAMES
        ):
            _fail_schema()
    if expected_leaf is not None and path.name.casefold() != expected_leaf.casefold():
        _fail_schema()
    return text


def _registry_component(value: Any, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    text = _text(value)
    if not _REGISTRY_COMPONENT.fullmatch(text) or text in {".", ".."}:
        _fail_schema()
    return text


def _registry_key(value: Any) -> str:
    text = _text(value)
    if (
        text.startswith("\\")
        or text.endswith("\\")
        or "\\\\" in text
        or "%" in text
        or "$" in text
    ):
        _fail_schema()
    for component in text.split("\\"):
        _registry_component(component)
    return text


def _parse_platform(value: Any) -> PlatformPolicy:
    item = _object(value, frozenset({"operating_system", "architecture"}))
    operating_system = _text(item["operating_system"])
    architecture = _text(item["architecture"])
    if operating_system != "windows" or architecture != "amd64":
        _fail_schema()
    return PlatformPolicy(operating_system, architecture)


def _parse_updates(value: Any) -> UpdatePolicy:
    fields = frozenset(
        {"runtime_upgrade", "signer_rollover", "installation_record_change"}
    )
    item = _object(value, fields)
    expected = "reviewed_policy_update_required"
    values = tuple(_text(item[field]) for field in sorted(fields))
    if any(candidate != expected for candidate in values):
        _fail_schema()
    return UpdatePolicy(
        runtime_upgrade=expected,
        signer_rollover=expected,
        installation_record_change=expected,
    )


def _parse_bindings(value: Any) -> RuntimeBindingsPolicy:
    item = _object(value, frozenset({"docker", "podman"}))
    docker_item = _object(
        item["docker"],
        frozenset({"runtime_product_id", "compose_product_id"}),
    )
    podman_item = _object(
        item["podman"],
        frozenset({"runtime_product_id", "compose_provider_id"}),
    )
    docker = DockerComposeBindingPolicy(
        runtime_product_id=_enum(docker_item["runtime_product_id"], RuntimeProductId),
        compose_product_id=_enum(docker_item["compose_product_id"], RuntimeProductId),
    )
    podman = PodmanComposeBindingPolicy(
        runtime_product_id=_enum(podman_item["runtime_product_id"], RuntimeProductId),
        compose_provider_id=_text(
            podman_item["compose_provider_id"], pattern=_POLICY_ID
        ),
    )
    if (
        docker.runtime_product_id is not RuntimeProductId.DOCKER_CLI
        or docker.compose_product_id is not RuntimeProductId.DOCKER_COMPOSE
        or podman.runtime_product_id is not RuntimeProductId.PODMAN_CLI
        or podman.compose_provider_id != "podman-compose-pypi-1.5.0"
    ):
        _fail_schema()
    return RuntimeBindingsPolicy(docker=docker, podman=podman)


def _parse_authenticode(value: Any) -> AuthenticodePolicy:
    item = _object(
        value,
        frozenset(
            {
                "signature_form",
                "signature_cardinality",
                "file_digest_algorithm",
                "signer_signature_algorithm",
                "require_code_signing_eku",
                "require_windows_chain_trust",
                "unhashed_pe_regions",
                "revocation",
                "expired_signer",
                "trusted_timestamp",
                "timestamp_cardinality",
                "timestamp_form",
                "timestamp_digest_algorithm",
                "timestamp_signature_algorithm",
            }
        ),
    )
    revocation_item = _object(
        item["revocation"],
        frozenset(
            {
                "retrieval",
                "scope",
                "applies_to",
                "revoked",
                "unknown",
                "offline",
            }
        ),
    )
    applies_to = tuple(
        _text(candidate)
        for candidate in _array(revocation_item["applies_to"], minimum=2, maximum=2)
    )
    if applies_to != ("signer_chain", "timestamp_chain"):
        _fail_schema()
    revocation = RevocationPolicy(
        retrieval=_enum(revocation_item["retrieval"], RevocationRetrieval),
        scope=_enum(revocation_item["scope"], RevocationScope),
        applies_to=applies_to,
        revoked=_text(revocation_item["revoked"]),
        unknown=_text(revocation_item["unknown"]),
        offline=_text(revocation_item["offline"]),
    )
    if (revocation.revoked, revocation.unknown, revocation.offline) != (
        "reject",
        "reject",
        "reject",
    ):
        _fail_schema()
    signature_cardinality = _text(item["signature_cardinality"])
    unhashed_pe_regions = _text(item["unhashed_pe_regions"])
    trusted_timestamp = _text(item["trusted_timestamp"])
    timestamp_cardinality = _text(item["timestamp_cardinality"])
    file_digest_algorithm = _text(item["file_digest_algorithm"])
    signer_signature_algorithm = _text(item["signer_signature_algorithm"])
    timestamp_form = _text(item["timestamp_form"])
    timestamp_digest_algorithm = _text(item["timestamp_digest_algorithm"])
    timestamp_signature_algorithm = _text(item["timestamp_signature_algorithm"])
    if (
        signature_cardinality
        != "exactly_one_across_all_certificate_table_entries_and_nested_signatures"
        or unhashed_pe_regions != "require_zero_padding_and_no_overlay"
        or trusted_timestamp != "windows_trusted_time_within_signer_validity"
        or timestamp_cardinality != "zero_or_one_require_one_when_signer_expired"
        or file_digest_algorithm != "sha256"
        or signer_signature_algorithm != "rsa_pkcs1v15"
        or timestamp_form != "rfc3161"
        or timestamp_digest_algorithm != "sha256"
        or timestamp_signature_algorithm != "rsa_pkcs1v15"
    ):
        _fail_schema()
    return AuthenticodePolicy(
        signature_form=_enum(item["signature_form"], SignatureForm),
        signature_cardinality=signature_cardinality,
        file_digest_algorithm=file_digest_algorithm,
        signer_signature_algorithm=signer_signature_algorithm,
        require_code_signing_eku=_exact_bool(item["require_code_signing_eku"], True),
        require_windows_chain_trust=_exact_bool(
            item["require_windows_chain_trust"], True
        ),
        unhashed_pe_regions=unhashed_pe_regions,
        revocation=revocation,
        expired_signer=_enum(item["expired_signer"], ExpiredSignerRule),
        trusted_timestamp=trusted_timestamp,
        timestamp_cardinality=timestamp_cardinality,
        timestamp_form=timestamp_form,
        timestamp_digest_algorithm=timestamp_digest_algorithm,
        timestamp_signature_algorithm=timestamp_signature_algorithm,
    )


_SIGNER_FIELDS = frozenset(
    {
        "certificate_sha256",
        "subject_common_name",
        "subject_organization",
        "issuer_common_name",
        "serial_number",
        "not_before_utc",
        "not_after_utc",
        "public_key_algorithm",
        "minimum_public_key_bits",
    }
)


def _parse_signer(value: Any) -> SignerCertificatePolicy:
    item = _object(value, _SIGNER_FIELDS)
    certificate_sha256 = _text(item["certificate_sha256"], pattern=_SHA256)
    serial_number = _text(item["serial_number"], pattern=_SERIAL)
    not_before = _text(item["not_before_utc"], pattern=_UTC_TIME)
    not_after = _text(item["not_after_utc"], pattern=_UTC_TIME)
    try:
        before_time = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ")
        after_time = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail_schema()
    if before_time >= after_time:
        _fail_schema()
    key_bits = item["minimum_public_key_bits"]
    if type(key_bits) is not int or key_bits not in {3072, 4096}:
        _fail_schema()
    public_key_algorithm = _text(item["public_key_algorithm"])
    if public_key_algorithm != "rsa":
        _fail_schema()
    return SignerCertificatePolicy(
        certificate_sha256=certificate_sha256,
        subject_common_name=_text(item["subject_common_name"]),
        subject_organization=_text(item["subject_organization"]),
        issuer_common_name=_text(item["issuer_common_name"]),
        serial_number=serial_number,
        not_before_utc=not_before,
        not_after_utc=not_after,
        public_key_algorithm=public_key_algorithm,
        minimum_public_key_bits=key_bits,
    )


def _parse_version_evidence(value: Any) -> VersionEvidencePolicy:
    if type(value) is not dict or type(value.get("kind")) is not str:
        _fail_schema()
    kind = _enum(value["kind"], VersionEvidenceKind)
    if kind is VersionEvidenceKind.PE_VERSION_RESOURCE:
        item = _object(
            value,
            frozenset(
                {
                    "kind",
                    "company_name",
                    "product_name",
                    "original_filename",
                    "file_version",
                    "product_version",
                }
            ),
        )
        return VersionEvidencePolicy(
            kind=kind,
            company_name=_text(item["company_name"]),
            product_name=_text(item["product_name"]),
            original_filename=_text(item["original_filename"]),
            file_version=_text(item["file_version"], pattern=_VERSION),
            product_version=_text(item["product_version"], pattern=_VERSION),
        )
    if kind is VersionEvidenceKind.AUTHENTICATED_COMMAND_TEXT:
        item = _object(value, frozenset({"kind", "arguments", "exact_output"}))
        arguments = tuple(
            _text(argument) for argument in _array(item["arguments"], maximum=8)
        )
        return VersionEvidencePolicy(
            kind=kind,
            arguments=arguments,
            exact_output=_text(item["exact_output"], pattern=_VERSION),
        )
    item = _object(value, frozenset({"kind", "arguments", "json_pointer"}))
    arguments = tuple(
        _text(argument) for argument in _array(item["arguments"], maximum=8)
    )
    json_pointer = _text(item["json_pointer"])
    if not json_pointer.startswith("/") or "~" in json_pointer:
        _fail_schema()
    return VersionEvidencePolicy(
        kind=kind,
        arguments=arguments,
        json_pointer=json_pointer,
    )


def _parse_registry_value(value: Any) -> RegistryValuePolicy:
    item = _object(value, frozenset({"subkey", "name", "equals"}))
    return RegistryValuePolicy(
        subkey=_registry_component(item["subkey"], allow_empty=True),
        name=_registry_component(item["name"]),
        equals=_text(item["equals"]),
    )


def _parse_registry(value: Any) -> RegistryRecordPolicy:
    item = _object(value, frozenset({"hive", "view", "key", "required_values"}))
    hive = _text(item["hive"])
    view = _text(item["view"])
    if hive not in {"HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"} or view != (
        "registry64"
    ):
        _fail_schema()
    required_values = tuple(
        _parse_registry_value(candidate)
        for candidate in _array(item["required_values"], maximum=8)
    )
    identities = tuple(
        (candidate.subkey, candidate.name) for candidate in required_values
    )
    if len(set(identities)) != len(identities):
        _fail_schema()
    return RegistryRecordPolicy(
        hive=hive,
        view=view,
        key=_registry_key(item["key"]),
        required_values=required_values,
    )


def _parse_location(value: Any) -> ExecutableLocationPolicy:
    if type(value) is not dict or type(value.get("kind")) is not str:
        _fail_schema()
    kind = _enum(value["kind"], LocationKind)
    if kind is LocationKind.REGISTRY_DIRECTORY_RELATIVE:
        item = _object(
            value,
            frozenset({"kind", "value_subkey", "value_name", "relative_path"}),
        )
        return ExecutableLocationPolicy(
            kind=kind,
            value_subkey=_registry_component(item["value_subkey"], allow_empty=True),
            value_name=_registry_component(item["value_name"]),
            relative_path=_safe_relative_path(item["relative_path"]),
        )
    if kind is LocationKind.REGISTRY_FILE:
        item = _object(
            value,
            frozenset({"kind", "value_subkey", "value_name", "required_leaf_name"}),
        )
        required_leaf = _text(item["required_leaf_name"])
        if PureWindowsPath(required_leaf).name != required_leaf:
            _fail_schema()
        return ExecutableLocationPolicy(
            kind=kind,
            value_subkey=_registry_component(item["value_subkey"]),
            value_name=_registry_component(item["value_name"]),
            required_leaf_name=required_leaf,
        )
    item = _object(value, frozenset({"kind", "known_folder", "relative_path"}))
    known_folder = _text(item["known_folder"])
    if known_folder not in {"local_app_data", "program_files"}:
        _fail_schema()
    return ExecutableLocationPolicy(
        kind=kind,
        known_folder=known_folder,
        relative_path=_safe_relative_path(item["relative_path"]),
    )


def _parse_install_record(value: Any) -> InstallRecordPolicy:
    item = _object(value, frozenset({"id", "scope", "registry", "location"}))
    return InstallRecordPolicy(
        record_id=_text(item["id"], pattern=_POLICY_ID),
        scope=_enum(item["scope"], InstallScope),
        registry=_parse_registry(item["registry"]),
        location=_parse_location(item["location"]),
    )


_PRODUCT_FIELDS = frozenset(
    {
        "id",
        "role",
        "executable_name",
        "architecture",
        "exact_version",
        "version_evidence",
        "signers",
        "install_records",
        "file_hash_policy",
        "file_identity_policy",
    }
)


def _parse_product(value: Any) -> ProductPolicy:
    item = _object(value, _PRODUCT_FIELDS)
    product_id = _enum(item["id"], RuntimeProductId)
    signers = tuple(
        _parse_signer(candidate) for candidate in _array(item["signers"], maximum=4)
    )
    if len({candidate.certificate_sha256 for candidate in signers}) != len(signers):
        _fail_schema()
    records = tuple(
        _parse_install_record(candidate)
        for candidate in _array(item["install_records"], maximum=8)
    )
    if len({candidate.record_id for candidate in records}) != len(records):
        _fail_schema()
    architecture = _text(item["architecture"])
    file_hash_policy = _text(item["file_hash_policy"])
    file_identity_policy = _text(item["file_identity_policy"])
    if (
        architecture != "amd64"
        or file_hash_policy != "record_and_bind"
        or file_identity_policy != "held_handle_record_and_revalidate"
    ):
        _fail_schema()
    executable_name = _text(item["executable_name"])
    if PureWindowsPath(executable_name).name != executable_name:
        _fail_schema()
    return ProductPolicy(
        product_id=product_id,
        role=_enum(item["role"], ProductRole),
        executable_name=executable_name,
        architecture=architecture,
        exact_version=_text(item["exact_version"], pattern=_VERSION),
        version_evidence=_parse_version_evidence(item["version_evidence"]),
        signers=signers,
        install_records=records,
        file_hash_policy=file_hash_policy,
        file_identity_policy=file_identity_policy,
    )


def _signer_key(value: SignerCertificatePolicy) -> tuple[Any, ...]:
    return (
        value.certificate_sha256,
        value.subject_common_name,
        value.subject_organization,
        value.issuer_common_name,
        value.serial_number,
        value.not_before_utc,
        value.not_after_utc,
        value.public_key_algorithm,
        value.minimum_public_key_bits,
    )


def _registry_values_key(
    values: tuple[RegistryValuePolicy, ...],
) -> tuple[tuple[str, str, str], ...]:
    return tuple((item.subkey, item.name, item.equals) for item in values)


def _record_key(value: InstallRecordPolicy) -> tuple[Any, ...]:
    location = value.location
    return (
        value.record_id,
        value.scope.value,
        value.registry.hive,
        value.registry.view,
        value.registry.key,
        _registry_values_key(value.registry.required_values),
        location.kind.value,
        location.relative_path,
        location.value_subkey,
        location.value_name,
        location.required_leaf_name,
        location.known_folder,
    )


def _version_key(value: VersionEvidencePolicy) -> tuple[Any, ...]:
    return (
        value.kind.value,
        value.arguments,
        value.company_name,
        value.product_name,
        value.original_filename,
        value.file_version,
        value.product_version,
        value.exact_output,
        value.json_pointer,
    )


_DOCKER_SIGNER = (
    "a1114dec9407df1bf9e52e13917d9a4257d18f2a23198ec3d391674308c30477",
    "Docker Inc",
    "Docker Inc",
    "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    "0dce683683ae70c7c647addb7e609a9a",
    "2026-06-26T00:00:00Z",
    "2027-06-25T23:59:59Z",
    "rsa",
    4096,
)
_PODMAN_SIGNER = (
    "a3e52b0d4273340dc8f5a0a0152cfd73d73d46aef7c5093fe5c10e3b80c30513",
    "Red Hat, Inc",
    "Red Hat, Inc",
    "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    "0a717996ccf3ffaaf1d76b14a59dc089",
    "2023-06-15T00:00:00Z",
    "2026-08-07T23:59:59Z",
    "rsa",
    4096,
)
_PYTHON_SIGNER = (
    "f0e4f5974299809383869188a87d305827ace5a7336e7c35ed03858d5816ee62",
    "Python Software Foundation",
    "Python Software Foundation",
    "Microsoft ID Verified CS AOC CA 01",
    "3300033fcb65b25969c57e965c000000033fcb",
    "2025-04-08T01:07:24Z",
    "2025-04-11T01:07:24Z",
    "rsa",
    3072,
)


def _docker_record(
    *, record_id: str, scope: str, hive: str, leaf: str
) -> tuple[Any, ...]:
    return (
        record_id,
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


_PODMAN_RECORD = (
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
)


def _python_record(*, record_id: str, scope: str, hive: str) -> tuple[Any, ...]:
    return (
        record_id,
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


_PRODUCT_APPROVALS: dict[RuntimeProductId, tuple[Any, ...]] = {
    RuntimeProductId.DOCKER_CLI: (
        ProductRole.RUNTIME,
        "docker.exe",
        "29.7.2",
        (
            "pe_version_resource",
            (),
            "Docker Inc",
            "Docker Client",
            "docker-windows-amd64.exe",
            "29.7.2",
            "29.7.2",
            "",
            "",
        ),
        (_DOCKER_SIGNER,),
        (
            _docker_record(
                record_id="docker-desktop-system",
                scope="system",
                hive="HKEY_LOCAL_MACHINE",
                leaf="docker.exe",
            ),
            _docker_record(
                record_id="docker-desktop-user",
                scope="user",
                hive="HKEY_CURRENT_USER",
                leaf="docker.exe",
            ),
        ),
    ),
    RuntimeProductId.DOCKER_COMPOSE: (
        ProductRole.COMPOSE,
        "docker-compose.exe",
        "5.3.1",
        (
            "authenticated_command_text",
            ("version", "--short"),
            "",
            "",
            "",
            "",
            "",
            "5.3.1",
            "",
        ),
        (_DOCKER_SIGNER,),
        (
            _docker_record(
                record_id="docker-desktop-system-compose",
                scope="system",
                hive="HKEY_LOCAL_MACHINE",
                leaf="docker-compose.exe",
            ),
            _docker_record(
                record_id="docker-desktop-user-compose",
                scope="user",
                hive="HKEY_CURRENT_USER",
                leaf="docker-compose.exe",
            ),
        ),
    ),
    RuntimeProductId.PODMAN_CLI: (
        ProductRole.RUNTIME,
        "podman.exe",
        "6.0.2",
        (
            "authenticated_command_json",
            ("version", "--format", "json"),
            "",
            "",
            "",
            "",
            "",
            "",
            "/Client/Version",
        ),
        (_PODMAN_SIGNER,),
        (_PODMAN_RECORD,),
    ),
    RuntimeProductId.CPYTHON: (
        ProductRole.INTERPRETER,
        "python.exe",
        "3.12.10",
        (
            "pe_version_resource",
            (),
            "Python Software Foundation",
            "Python",
            "python.exe",
            "3.12.10",
            "3.12.10",
            "",
            "",
        ),
        (_PYTHON_SIGNER,),
        (
            _python_record(
                record_id="pythoncore-3.12-system",
                scope="system",
                hive="HKEY_LOCAL_MACHINE",
            ),
            _python_record(
                record_id="pythoncore-3.12-user",
                scope="user",
                hive="HKEY_CURRENT_USER",
            ),
        ),
    ),
}


def _validate_product_approval(product: ProductPolicy) -> None:
    expected = _PRODUCT_APPROVALS[product.product_id]
    observed = (
        product.role,
        product.executable_name,
        product.exact_version,
        _version_key(product.version_evidence),
        tuple(_signer_key(signer) for signer in product.signers),
        tuple(_record_key(record) for record in product.install_records),
    )
    if observed != expected:
        _fail_schema()


def _parse_catalog(value: Any) -> CatalogPolicy:
    item = _object(value, frozenset({"catalog_id", "authentication"}))
    catalog_id = _text(item["catalog_id"], pattern=_POLICY_ID)
    authentication = _enum(item["authentication"], CatalogAuthentication)
    if catalog_id != "towerscout-managed-podman-compose-2026-08-21":
        _fail_schema()
    return CatalogPolicy(
        catalog_id=catalog_id,
        authentication=authentication,
    )


def _parse_managed_interpreter(value: Any) -> ManagedInterpreterPolicy:
    item = _object(
        value,
        frozenset(
            {
                "relative_path",
                "base_product_id",
                "relationship",
                "require_same_authenticode_signer",
                "require_same_pe_product_version",
                "require_file_hash",
                "require_stable_file_identity",
                "require_authenticated_base_runtime_closure",
                "require_venv_config_base_path_match",
            }
        ),
    )
    relative_path = _safe_relative_path(
        item["relative_path"], expected_leaf="python.exe"
    )
    base_product_id = _enum(item["base_product_id"], RuntimeProductId)
    relationship = _text(item["relationship"])
    if (
        relative_path != r".venv\Scripts\python.exe"
        or base_product_id is not RuntimeProductId.CPYTHON
        or relationship != "venv_created_from_authenticated_base"
    ):
        _fail_schema()
    return ManagedInterpreterPolicy(
        relative_path=relative_path,
        base_product_id=base_product_id,
        relationship=relationship,
        require_same_authenticode_signer=_exact_bool(
            item["require_same_authenticode_signer"], True
        ),
        require_same_pe_product_version=_exact_bool(
            item["require_same_pe_product_version"], True
        ),
        require_file_hash=_exact_bool(item["require_file_hash"], True),
        require_stable_file_identity=_exact_bool(
            item["require_stable_file_identity"], True
        ),
        require_authenticated_base_runtime_closure=_exact_bool(
            item["require_authenticated_base_runtime_closure"], True
        ),
        require_venv_config_base_path_match=_exact_bool(
            item["require_venv_config_base_path_match"], True
        ),
    )


def _parse_distribution(value: Any) -> DistributionPolicy:
    item = _object(
        value,
        frozenset({"name", "version", "wheel_filename", "source_url", "wheel_sha256"}),
    )
    source_url = _text(item["source_url"])
    parsed_url = urlsplit(source_url)
    if (
        parsed_url.scheme != "https"
        or parsed_url.netloc != "files.pythonhosted.org"
        or not parsed_url.path.startswith("/packages/")
        or parsed_url.query
        or parsed_url.fragment
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        _fail_schema()
    wheel_filename = _text(item["wheel_filename"])
    if PureWindowsPath(wheel_filename).name != wheel_filename or not (
        wheel_filename.endswith(".whl")
    ):
        _fail_schema()
    return DistributionPolicy(
        name=_text(item["name"]),
        version=_text(item["version"], pattern=_VERSION),
        wheel_filename=wheel_filename,
        source_url=source_url,
        wheel_sha256=_text(item["wheel_sha256"], pattern=_SHA256),
    )


_EXPECTED_DISTRIBUTIONS = (
    (
        "podman-compose",
        "1.5.0",
        "podman_compose-1.5.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/41/4b/75ab5c151b9d170fdae0048a6f6528535aff848140c007f408af9ac555d6/podman_compose-1.5.0-py3-none-any.whl",
        "f0b9d35f4da1b309172adf208a5cb7a882b532a834c2202666c1988b6f147546",
    ),
    (
        "python-dotenv",
        "1.1.1",
        "python_dotenv-1.1.1-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/5f/ed/539768cf28c661b5b068d66d96a2f155c4971a5d55684a514c1a0e0dec2f/python_dotenv-1.1.1-py3-none-any.whl",
        "31f23644fe2602f88ff55e1f5c79ba497e01224ee7737937930c448e4d0e24dc",
    ),
    (
        "PyYAML",
        "6.0.3",
        "pyyaml-6.0.3-cp312-cp312-win_amd64.whl",
        "https://files.pythonhosted.org/packages/86/bf/899e81e4cce32febab4fb42bb97dcdf66bc135272882d1987881a4b519e9/pyyaml-6.0.3-cp312-cp312-win_amd64.whl",
        "5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b",
    ),
)


def _distribution_key(value: DistributionPolicy) -> tuple[str, ...]:
    return (
        value.name,
        value.version,
        value.wheel_filename,
        value.source_url,
        value.wheel_sha256,
    )


def _parse_provider_inventory(value: Any) -> ProviderInventoryPolicy:
    item = _object(
        value,
        frozenset(
            {
                "site_packages_relative_path",
                "module_relative_path",
                "generated_entrypoint_relative_path",
                "venv_config_relative_path",
                "record_validation",
                "loadable_suffixes",
                "require_exact_authenticated_install_tree",
                "reject_unowned_loadable_files",
                "reject_extra_distributions",
                "reject_pth_files",
                "reject_sitecustomize",
                "reject_usercustomize",
            }
        ),
    )
    site_packages = _safe_relative_path(item["site_packages_relative_path"])
    module_path = _safe_relative_path(
        item["module_relative_path"], expected_leaf="podman_compose.py"
    )
    entrypoint_path = _safe_relative_path(
        item["generated_entrypoint_relative_path"],
        expected_leaf="podman-compose.exe",
    )
    venv_config_path = _safe_relative_path(
        item["venv_config_relative_path"], expected_leaf="pyvenv.cfg"
    )
    record_validation = _text(item["record_validation"])
    loadable_suffixes = tuple(
        _text(candidate)
        for candidate in _array(item["loadable_suffixes"], minimum=5, maximum=5)
    )
    if (
        site_packages != r".venv\Lib\site-packages"
        or module_path != r".venv\Lib\site-packages\podman_compose.py"
        or entrypoint_path != r".venv\Scripts\podman-compose.exe"
        or venv_config_path != r".venv\pyvenv.cfg"
        or record_validation
        != "reconstruct_from_pinned_wheels_and_compare_exact_inventory"
        or loadable_suffixes != (".py", ".pyc", ".pyd", ".dll", ".pth")
    ):
        _fail_schema()
    return ProviderInventoryPolicy(
        site_packages_relative_path=site_packages,
        module_relative_path=module_path,
        generated_entrypoint_relative_path=entrypoint_path,
        venv_config_relative_path=venv_config_path,
        record_validation=record_validation,
        loadable_suffixes=loadable_suffixes,
        require_exact_authenticated_install_tree=_exact_bool(
            item["require_exact_authenticated_install_tree"], True
        ),
        reject_unowned_loadable_files=_exact_bool(
            item["reject_unowned_loadable_files"], True
        ),
        reject_extra_distributions=_exact_bool(
            item["reject_extra_distributions"], True
        ),
        reject_pth_files=_exact_bool(item["reject_pth_files"], True),
        reject_sitecustomize=_exact_bool(item["reject_sitecustomize"], True),
        reject_usercustomize=_exact_bool(item["reject_usercustomize"], True),
    )


def _parse_provider(value: Any) -> PodmanComposePolicy:
    item = _object(
        value,
        frozenset(
            {
                "kind",
                "provider_id",
                "exact_version",
                "managed_install_root",
                "catalog",
                "interpreter",
                "invocation",
                "endpoint_propagation",
                "distributions",
                "inventory",
                "verification",
                "allow_external",
                "allow_docker_desktop",
                "allow_command_wrapper",
                "allow_podman_compose_delegation",
            }
        ),
    )
    invocation_item = _object(
        item["invocation"], frozenset({"kind", "arguments", "module"})
    )
    invocation = ProviderInvocationPolicy(
        kind=_enum(invocation_item["kind"], InvocationKind),
        arguments=tuple(
            _text(argument)
            for argument in _array(invocation_item["arguments"], maximum=8)
        ),
        module=_text(invocation_item["module"]),
    )
    if invocation.arguments != ("-I", "-m", "podman_compose") or (
        invocation.module != "podman_compose"
    ):
        _fail_schema()

    endpoint_item = _object(
        item["endpoint_propagation"],
        frozenset({"mechanism", "required_variables", "allow_provider_rediscovery"}),
    )
    endpoint = EndpointPropagationPolicy(
        mechanism=_text(endpoint_item["mechanism"]),
        required_variables=tuple(
            _text(candidate)
            for candidate in _array(endpoint_item["required_variables"], maximum=4)
        ),
        allow_provider_rediscovery=_exact_bool(
            endpoint_item["allow_provider_rediscovery"], False
        ),
    )
    if endpoint.mechanism != "constructed_environment" or (
        endpoint.required_variables != ("CONTAINER_HOST", "CONTAINER_SSHKEY")
    ):
        _fail_schema()

    verification_item = _object(
        item["verification"],
        frozenset(
            {
                "require_hash_verified_installer_inputs",
                "require_fresh_reconstruction_comparison",
                "require_exact_distribution_inventory",
                "require_record_hashes",
                "require_module_hash",
                "require_generated_entrypoint_hash",
                "require_stable_file_identity",
                "receipt_is_trust_anchor",
            }
        ),
    )
    verification = ProviderVerificationPolicy(
        require_hash_verified_installer_inputs=_exact_bool(
            verification_item["require_hash_verified_installer_inputs"], True
        ),
        require_fresh_reconstruction_comparison=_exact_bool(
            verification_item["require_fresh_reconstruction_comparison"], True
        ),
        require_exact_distribution_inventory=_exact_bool(
            verification_item["require_exact_distribution_inventory"], True
        ),
        require_record_hashes=_exact_bool(
            verification_item["require_record_hashes"], True
        ),
        require_module_hash=_exact_bool(verification_item["require_module_hash"], True),
        require_generated_entrypoint_hash=_exact_bool(
            verification_item["require_generated_entrypoint_hash"], True
        ),
        require_stable_file_identity=_exact_bool(
            verification_item["require_stable_file_identity"], True
        ),
        receipt_is_trust_anchor=_exact_bool(
            verification_item["receipt_is_trust_anchor"], False
        ),
    )
    distributions = tuple(
        _parse_distribution(candidate)
        for candidate in _array(item["distributions"], minimum=3, maximum=3)
    )
    if (
        len({candidate.name.casefold() for candidate in distributions})
        != len(distributions)
        or tuple(_distribution_key(candidate) for candidate in distributions)
        != _EXPECTED_DISTRIBUTIONS
    ):
        _fail_schema()

    kind = _enum(item["kind"], ProviderKind)
    provider_id = _text(item["provider_id"], pattern=_POLICY_ID)
    exact_version = _text(item["exact_version"], pattern=_VERSION)
    managed_install_root = _safe_relative_path(item["managed_install_root"])
    if (
        provider_id != "podman-compose-pypi-1.5.0"
        or exact_version != "1.5.0"
        or managed_install_root
        != r"tools\podman-compose-provider\podman-compose-pypi-1.5.0"
    ):
        _fail_schema()
    return PodmanComposePolicy(
        kind=kind,
        provider_id=provider_id,
        exact_version=exact_version,
        managed_install_root=managed_install_root,
        catalog=_parse_catalog(item["catalog"]),
        interpreter=_parse_managed_interpreter(item["interpreter"]),
        invocation=invocation,
        endpoint_propagation=endpoint,
        distributions=distributions,
        inventory=_parse_provider_inventory(item["inventory"]),
        verification=verification,
        allow_external=_exact_bool(item["allow_external"], False),
        allow_docker_desktop=_exact_bool(item["allow_docker_desktop"], False),
        allow_command_wrapper=_exact_bool(item["allow_command_wrapper"], False),
        allow_podman_compose_delegation=_exact_bool(
            item["allow_podman_compose_delegation"], False
        ),
    )


def parse_runtime_policy_bytes(data: bytes) -> RuntimePolicy:
    """Parse exact policy bytes without trusting any digest declared inside them."""

    payload = _decode_policy(data)
    try:
        item = _object(
            payload,
            frozenset(
                {
                    "schema_version",
                    "policy_id",
                    "platform",
                    "updates",
                    "bindings",
                    "authenticode",
                    "products",
                    "podman_compose",
                }
            ),
        )
        schema_version = _exact_int(item["schema_version"], 1)
        policy_id = _text(item["policy_id"], pattern=_POLICY_ID)
        if policy_id != "towerscout-runtime-policy-2026-08-21":
            _fail_schema()
        products = tuple(
            _parse_product(candidate)
            for candidate in _array(item["products"], minimum=4, maximum=4)
        )
        expected_order = (
            RuntimeProductId.DOCKER_CLI,
            RuntimeProductId.DOCKER_COMPOSE,
            RuntimeProductId.PODMAN_CLI,
            RuntimeProductId.CPYTHON,
        )
        if tuple(product.product_id for product in products) != expected_order:
            _fail_schema()
        for product in products:
            _validate_product_approval(product)
        return RuntimePolicy(
            schema_version=schema_version,
            policy_id=policy_id,
            platform=_parse_platform(item["platform"]),
            updates=_parse_updates(item["updates"]),
            bindings=_parse_bindings(item["bindings"]),
            authenticode=_parse_authenticode(item["authenticode"]),
            products=products,
            podman_compose=_parse_provider(item["podman_compose"]),
            content_sha256=hashlib.sha256(data).hexdigest(),
        )
    except (_SchemaFailure, KeyError, TypeError, ValueError):
        raise RuntimePolicyError(PolicyErrorCode.SCHEMA_INVALID) from None


def parse_package_bound_runtime_policy_bytes(data: bytes) -> RuntimePolicy:
    """Verify the compiled policy pin before parsing the resource bytes."""

    if type(data) is not bytes or not 1 <= len(data) <= _MAX_POLICY_BYTES:
        raise RuntimePolicyError(PolicyErrorCode.INTEGRITY_INVALID)
    if hashlib.sha256(data).hexdigest() != _PACKAGE_POLICY_SHA256:
        raise RuntimePolicyError(PolicyErrorCode.INTEGRITY_INVALID)
    return parse_runtime_policy_bytes(data)


def load_package_bound_runtime_policy() -> RuntimePolicy:
    """Load only the fixed policy resource bundled with this launcher build."""

    try:
        with _POLICY_RESOURCE.open("rb") as handle:
            data = handle.read(_MAX_POLICY_BYTES + 1)
    except OSError:
        raise RuntimePolicyError(PolicyErrorCode.RESOURCE_UNAVAILABLE) from None
    return parse_package_bound_runtime_policy_bytes(data)
