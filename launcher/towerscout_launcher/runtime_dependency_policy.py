"""Strict, inert parser for the package-bound Windows dependency policy.

The checked-in policy records the reviewed native load surface for the exact
CPython artifact and the entrypoint import surface for supported container
clients.  Parsing performs no discovery, network access, signature checking,
DLL loading, or child execution.  Runtime enforcement must use the
package-bound loader so arbitrary caller-supplied policy bytes are never an
authority source.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from .runtime_policy import RuntimeProductId, SignerCertificatePolicy

_POLICY_RESOURCE = Path(__file__).with_name("runtime-dependency-policy.v1.json")
_PACKAGE_POLICY_SHA256 = (
    "1c699ac7d2d2592305e876431d57231ef63e5ccdaaeb033c7d3526db307a3890"
)
_MAX_POLICY_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 12
_MAX_JSON_COLLECTION_ITEMS = 128
_MAX_JSON_NODES = 4096
_MAX_JSON_STRING = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SERIAL = re.compile(r"^(?:[0-9a-f]{2}){1,32}$")
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_DEPENDENCY_LEAF = re.compile(r"^[a-z0-9_.-]{1,251}\.(?:dll|pyd)$")
_ARCHIVE_PATH_PART = re.compile(r"^[A-Za-z0-9_. -]{1,255}$")
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
_EXPECTED_SIGNER_CERTIFICATES = (
    "f0e4f5974299809383869188a87d305827ace5a7336e7c35ed03858d5816ee62",
    "6045e624888e299179d5ae0ceda57c9874ff6ccf889fa14b2d50f751bfb9e2f8",
    "da3b7ce37f8d5abb20c2c3c982e99312dde1debb0dd46697689dd8357a420657",
    "7698e1de0131245a5ef86a3df9bc7c4de048b4684bdd0bc7891c3643d7f8b52e",
    "b665eca200033085fae5fc06086586223b79e226ab646b723012262c004e2a96",
)
_EXPECTED_PRODUCT_ORDER = (
    RuntimeProductId.DOCKER_CLI,
    RuntimeProductId.DOCKER_COMPOSE,
    RuntimeProductId.PODMAN_CLI,
)


class DependencyPolicyErrorCode(str, Enum):
    FORMAT_INVALID = "format_invalid"
    SCHEMA_INVALID = "schema_invalid"
    INTEGRITY_INVALID = "integrity_invalid"
    RESOURCE_UNAVAILABLE = "resource_unavailable"


class RuntimeDependencyPolicyError(ValueError):
    """Sanitized policy failure with no untrusted value or local path."""

    _MESSAGES = {
        DependencyPolicyErrorCode.FORMAT_INVALID: (
            "The runtime dependency policy format is invalid."
        ),
        DependencyPolicyErrorCode.SCHEMA_INVALID: (
            "The runtime dependency policy schema is invalid."
        ),
        DependencyPolicyErrorCode.INTEGRITY_INVALID: (
            "The runtime dependency policy integrity check failed."
        ),
        DependencyPolicyErrorCode.RESOURCE_UNAVAILABLE: (
            "The package runtime dependency policy is unavailable."
        ),
    }

    def __init__(self, code: DependencyPolicyErrorCode) -> None:
        if type(code) is not DependencyPolicyErrorCode:
            raise ValueError("Unknown runtime dependency-policy error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeDependencyPolicyError(code={self.code.value!r})"


class PeMachine(str, Enum):
    AMD64 = "amd64"
    I386 = "i386"
    ARM64 = "arm64"


class DependencySignaturePolicy(str, Enum):
    EXACT_AUTHENTICODE_SIGNER = "exact_authenticode_signer"
    UPSTREAM_UNSIGNED_EXACT_HASH_ONLY = "upstream_unsigned_exact_hash_only"


@dataclass(frozen=True, slots=True)
class DependencySearchPolicy:
    parent_dll_directory: str
    path: str
    working_directory: str
    application_directory: str
    system_directory: str
    external_manifests: str
    dll_redirection: str
    private_assemblies: str
    user_directories: str
    image_load_mitigations: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class DependencyImports:
    direct: tuple[str, ...]
    delay: tuple[str, ...]
    forwarded: tuple[str, ...]

    def __repr__(self) -> str:
        return (
            "DependencyImports("
            f"direct_count={len(self.direct)}, delay_count={len(self.delay)}, "
            f"forwarded_count={len(self.forwarded)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ProductDependencyPolicy:
    product_id: RuntimeProductId
    entrypoint_imports: DependencyImports = field(repr=False)
    application_image_policy: str
    declared_system_imports: tuple[str, ...] = field(repr=False)
    declared_api_set_imports: tuple[str, ...] = field(repr=False)
    declared_private_imports: tuple[str, ...] = field(repr=False)
    dynamic_load_policy: str

    def __repr__(self) -> str:
        return f"ProductDependencyPolicy(product_id={self.product_id.value!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ApprovedDependencyFile:
    path: str = field(repr=False)
    sha256: str = field(repr=False)
    signature_policy: DependencySignaturePolicy
    signer_certificate_sha256: str | None = field(repr=False)
    dependency_manifest_sha256: str = field(repr=False)

    @property
    def leaf_name(self) -> str:
        return PurePosixPath(self.path).name.casefold()

    def __repr__(self) -> str:
        return "ApprovedDependencyFile(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class NonAmd64PeFile:
    path: str = field(repr=False)
    sha256: str = field(repr=False)
    machine: PeMachine
    signature_policy: str

    def __repr__(self) -> str:
        return f"NonAmd64PeFile(machine={self.machine.value!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CpythonDependencyArtifactPolicy:
    product_id: RuntimeProductId
    exact_version: str
    archive_url: str = field(repr=False)
    archive_sha256: str = field(repr=False)
    pe_file_count: int
    amd64_loadable_count: int
    signers: tuple[SignerCertificatePolicy, ...] = field(repr=False)
    declared_system_imports: tuple[str, ...] = field(repr=False)
    declared_api_set_imports: tuple[str, ...] = field(repr=False)
    declared_private_imports: tuple[str, ...] = field(repr=False)
    loadable_files: tuple[ApprovedDependencyFile, ...] = field(repr=False)
    non_amd64_pe_files: tuple[NonAmd64PeFile, ...] = field(repr=False)
    dynamic_load_policy: str
    private_assembly_policy: str

    def __repr__(self) -> str:
        return (
            "CpythonDependencyArtifactPolicy("
            f"exact_version={self.exact_version!r}, "
            f"loadable_count={len(self.loadable_files)}, "
            f"non_amd64_count={len(self.non_amd64_pe_files)}, <redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeDependencyPolicy:
    schema_version: int
    policy_id: str
    operating_system: str
    architecture: str
    search: DependencySearchPolicy
    products: tuple[ProductDependencyPolicy, ...]
    cpython: CpythonDependencyArtifactPolicy
    content_sha256: str = field(repr=False)

    def product(self, product_id: RuntimeProductId) -> ProductDependencyPolicy:
        if type(product_id) is not RuntimeProductId:
            raise ValueError("Runtime product identifier is invalid.")
        for product in self.products:
            if product.product_id is product_id:
                return product
        raise ValueError("Runtime product has no dependency policy.")

    def __repr__(self) -> str:
        return (
            "RuntimeDependencyPolicy("
            f"schema_version={self.schema_version}, policy_id={self.policy_id!r}, "
            f"product_count={len(self.products)}, <redacted>)"
        )


class _FormatFailure(Exception):
    pass


class _SchemaFailure(Exception):
    pass


def _fail_schema() -> NoReturn:
    raise _SchemaFailure


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise _FormatFailure
        result[key] = value
    return result


def _strict_integer(value: str) -> int:
    if len(value) > 10 or value.startswith(("+", "-")) or not value.isdigit():
        raise _FormatFailure
    return int(value)


def _reject_number(_value: str) -> NoReturn:
    raise _FormatFailure


def _walk_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if depth > _MAX_JSON_DEPTH or nodes[0] > _MAX_JSON_NODES:
        raise _FormatFailure
    if type(value) is str:
        if len(value) > _MAX_JSON_STRING:
            raise _FormatFailure
        return
    if value is None or type(value) in (bool, int):
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
        raise RuntimeDependencyPolicyError(DependencyPolicyErrorCode.FORMAT_INVALID)
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_int=_strict_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
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
        raise RuntimeDependencyPolicyError(
            DependencyPolicyErrorCode.FORMAT_INVALID
        ) from None
    if type(value) is not dict:
        raise RuntimeDependencyPolicyError(DependencyPolicyErrorCode.SCHEMA_INVALID)
    return value


def _object(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail_schema()
    return value


def _array(value: Any, *, minimum: int, maximum: int) -> list[Any]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        _fail_schema()
    return value


def _text(value: Any, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        _fail_schema()
    return value


def _exact_text(value: Any, expected: str) -> str:
    if _text(value, maximum=max(512, len(expected))) != expected:
        _fail_schema()
    return expected


def _sha256(value: Any) -> str:
    text = _text(value, maximum=64)
    if not _SHA256.fullmatch(text):
        _fail_schema()
    return text


def _archive_path(value: Any) -> str:
    text = _text(value, maximum=1024)
    if (
        "\\" in text
        or ":" in text
        or "%" in text
        or "$" in text
        or text.startswith("/")
        or text.endswith(("/", ".", " "))
    ):
        _fail_schema()
    path = PurePosixPath(text)
    if path.is_absolute() or len(path.parts) < 1:
        _fail_schema()
    for part in path.parts:
        base = part.split(".", 1)[0].casefold()
        if (
            part in {"", ".", ".."}
            or not _ARCHIVE_PATH_PART.fullmatch(part)
            or part.endswith((".", " "))
            or base in _WINDOWS_RESERVED_NAMES
        ):
            _fail_schema()
    if path.suffix.casefold() not in {".dll", ".exe", ".pyd"}:
        _fail_schema()
    return text


def _dependency_leaf(value: Any) -> str:
    text = _text(value, maximum=255)
    if text != text.casefold() or not _DEPENDENCY_LEAF.fullmatch(text):
        _fail_schema()
    return text


def _leaf_array(value: Any, *, maximum: int = 128) -> tuple[str, ...]:
    values = tuple(
        _dependency_leaf(candidate)
        for candidate in _array(value, minimum=0, maximum=maximum)
    )
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        _fail_schema()
    return values


def _parse_imports(value: Any) -> DependencyImports:
    item = _object(value, frozenset({"direct", "delay", "forwarded"}))
    result = DependencyImports(
        direct=_leaf_array(item["direct"]),
        delay=_leaf_array(item["delay"]),
        forwarded=_leaf_array(item["forwarded"]),
    )
    combined = result.direct + result.delay + result.forwarded
    if len(combined) != len(set(combined)):
        _fail_schema()
    return result


def _parse_product(value: Any) -> ProductDependencyPolicy:
    item = _object(
        value,
        frozenset(
            {
                "product_id",
                "entrypoint_imports",
                "application_image_policy",
                "declared_system_imports",
                "declared_api_set_imports",
                "declared_private_imports",
                "dynamic_load_policy",
            }
        ),
    )
    try:
        product_id = RuntimeProductId(_text(item["product_id"]))
    except ValueError:
        _fail_schema()
    if product_id not in _EXPECTED_PRODUCT_ORDER:
        _fail_schema()
    imports = _parse_imports(item["entrypoint_imports"])
    system = _leaf_array(item["declared_system_imports"])
    api_sets = _leaf_array(item["declared_api_set_imports"])
    private = _leaf_array(item["declared_private_imports"])
    if (
        imports != DependencyImports(("kernel32.dll",), (), ())
        or system != ("kernel32.dll",)
        or api_sets
        or private
    ):
        _fail_schema()
    return ProductDependencyPolicy(
        product_id=product_id,
        entrypoint_imports=imports,
        application_image_policy=_exact_text(
            item["application_image_policy"],
            "runtime_product_signer_and_held_exact_inventory",
        ),
        declared_system_imports=system,
        declared_api_set_imports=api_sets,
        declared_private_imports=private,
        dynamic_load_policy=_exact_text(
            item["dynamic_load_policy"],
            "authenticated_product_code_system32_or_held_application_inventory",
        ),
    )


def _parse_signer(value: Any) -> SignerCertificatePolicy:
    item = _object(
        value,
        frozenset(
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
        ),
    )
    serial = _text(item["serial_number"], maximum=64)
    not_before = _text(item["not_before_utc"], maximum=20)
    not_after = _text(item["not_after_utc"], maximum=20)
    if not _SERIAL.fullmatch(serial):
        _fail_schema()
    try:
        if (
            not _UTC_TIME.fullmatch(not_before)
            or not _UTC_TIME.fullmatch(not_after)
            or datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ")
            <= datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ")
        ):
            _fail_schema()
    except ValueError:
        _fail_schema()
    key_bits = item["minimum_public_key_bits"]
    if type(key_bits) is not int or key_bits not in {2048, 3072, 4096}:
        _fail_schema()
    return SignerCertificatePolicy(
        certificate_sha256=_sha256(item["certificate_sha256"]),
        subject_common_name=_text(item["subject_common_name"]),
        subject_organization=_text(item["subject_organization"]),
        issuer_common_name=_text(item["issuer_common_name"]),
        serial_number=serial,
        not_before_utc=not_before,
        not_after_utc=not_after,
        public_key_algorithm=_exact_text(item["public_key_algorithm"], "rsa"),
        minimum_public_key_bits=key_bits,
    )


def _parse_loadable(value: Any) -> ApprovedDependencyFile:
    signed_fields = frozenset(
        {
            "path",
            "sha256",
            "signer_certificate_sha256",
            "dependency_manifest_sha256",
        }
    )
    unsigned_fields = frozenset(
        {
            "path",
            "sha256",
            "signature_policy",
            "dependency_manifest_sha256",
        }
    )
    if type(value) is not dict or set(value) not in {signed_fields, unsigned_fields}:
        _fail_schema()
    item = value
    signed = set(item) == signed_fields
    if not signed:
        _exact_text(
            item["signature_policy"],
            DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY.value,
        )
    return ApprovedDependencyFile(
        path=_archive_path(item["path"]),
        sha256=_sha256(item["sha256"]),
        signature_policy=(
            DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER
            if signed
            else DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY
        ),
        signer_certificate_sha256=(
            _sha256(item["signer_certificate_sha256"]) if signed else None
        ),
        dependency_manifest_sha256=_sha256(item["dependency_manifest_sha256"]),
    )


def _parse_non_amd64(value: Any) -> NonAmd64PeFile:
    item = _object(
        value,
        frozenset({"path", "sha256", "machine", "signature_policy"}),
    )
    try:
        machine = PeMachine(_text(item["machine"], maximum=8))
    except ValueError:
        _fail_schema()
    if machine is PeMachine.AMD64:
        _fail_schema()
    return NonAmd64PeFile(
        path=_archive_path(item["path"]),
        sha256=_sha256(item["sha256"]),
        machine=machine,
        signature_policy=_exact_text(
            item["signature_policy"], "upstream_unsigned_exact_hash_only"
        ),
    )


def _parse_search(value: Any) -> DependencySearchPolicy:
    fields = frozenset(
        {
            "parent_dll_directory",
            "path",
            "working_directory",
            "application_directory",
            "system_directory",
            "external_manifests",
            "dll_redirection",
            "private_assemblies",
            "user_directories",
            "image_load_mitigations",
        }
    )
    item = _object(value, fields)
    mitigations = tuple(
        _text(candidate, maximum=32)
        for candidate in _array(item["image_load_mitigations"], minimum=3, maximum=3)
    )
    if mitigations != ("no_remote", "no_low_label", "prefer_system32"):
        _fail_schema()
    return DependencySearchPolicy(
        parent_dll_directory=_exact_text(item["parent_dll_directory"], "empty"),
        path=_exact_text(item["path"], "empty"),
        working_directory=_exact_text(item["working_directory"], "system32"),
        application_directory=_exact_text(
            item["application_directory"], "held_exact_inventory"
        ),
        system_directory=_exact_text(item["system_directory"], "trusted_system32"),
        external_manifests=_exact_text(item["external_manifests"], "deny"),
        dll_redirection=_exact_text(item["dll_redirection"], "deny"),
        private_assemblies=_exact_text(
            item["private_assemblies"], "deny_unless_exact_artifact_record"
        ),
        user_directories=_exact_text(item["user_directories"], "deny"),
        image_load_mitigations=mitigations,
    )


def _parse_cpython(value: Any) -> CpythonDependencyArtifactPolicy:
    item = _object(
        value,
        frozenset(
            {
                "product_id",
                "exact_version",
                "archive_url",
                "archive_sha256",
                "pe_file_count",
                "amd64_loadable_count",
                "signers",
                "declared_system_imports",
                "declared_api_set_imports",
                "declared_private_imports",
                "loadable_files",
                "non_amd64_pe_files",
                "dynamic_load_policy",
                "private_assembly_policy",
            }
        ),
    )
    product_id = _exact_text(item["product_id"], "cpython")
    signers = tuple(
        _parse_signer(candidate)
        for candidate in _array(item["signers"], minimum=5, maximum=5)
    )
    signer_ids = tuple(signer.certificate_sha256 for signer in signers)
    if signer_ids != _EXPECTED_SIGNER_CERTIFICATES:
        _fail_schema()
    system = _leaf_array(item["declared_system_imports"])
    api_sets = _leaf_array(item["declared_api_set_imports"])
    private = _leaf_array(item["declared_private_imports"])
    if (
        set(system) & set(api_sets)
        or set(system) & set(private)
        or set(api_sets) & set(private)
        or any(not leaf.startswith(("api-ms-win-", "ext-ms-win-")) for leaf in api_sets)
        or any(leaf.startswith(("api-ms-win-", "ext-ms-win-")) for leaf in system)
    ):
        _fail_schema()
    loadable = tuple(
        _parse_loadable(candidate)
        for candidate in _array(item["loadable_files"], minimum=43, maximum=43)
    )
    non_amd64 = tuple(
        _parse_non_amd64(candidate)
        for candidate in _array(item["non_amd64_pe_files"], minimum=4, maximum=4)
    )
    loadable_paths = tuple(record.path for record in loadable)
    non_amd64_paths = tuple(record.path for record in non_amd64)
    all_paths = loadable_paths + non_amd64_paths
    if (
        loadable_paths != tuple(sorted(loadable_paths, key=str.casefold))
        or non_amd64_paths != tuple(sorted(non_amd64_paths, key=str.casefold))
        or len(all_paths) != len({path.casefold() for path in all_paths})
        or any(
            record.signature_policy
            is DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER
            and record.signer_certificate_sha256 not in signer_ids
            for record in loadable
        )
        or any(
            record.signature_policy
            is DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY
            and record.signer_certificate_sha256 is not None
            for record in loadable
        )
        or {
            record.signer_certificate_sha256
            for record in loadable
            if record.signer_certificate_sha256 is not None
        }
        != set(signer_ids)
        or sum(
            record.signature_policy
            is DependencySignaturePolicy.EXACT_AUTHENTICODE_SIGNER
            for record in loadable
        )
        != 39
        or sum(
            record.signature_policy
            is DependencySignaturePolicy.UPSTREAM_UNSIGNED_EXACT_HASH_ONLY
            for record in loadable
        )
        != 4
        or sum(record.machine is PeMachine.I386 for record in non_amd64) != 2
        or sum(record.machine is PeMachine.ARM64 for record in non_amd64) != 2
        or not set(private).issubset({record.leaf_name for record in loadable})
        or not any(record.path == "python.exe" for record in loadable)
    ):
        _fail_schema()
    if type(item["pe_file_count"]) is not int or item["pe_file_count"] != 47:
        _fail_schema()
    if (
        type(item["amd64_loadable_count"]) is not int
        or item["amd64_loadable_count"] != 43
    ):
        _fail_schema()
    return CpythonDependencyArtifactPolicy(
        product_id=RuntimeProductId(product_id),
        exact_version=_exact_text(item["exact_version"], "3.12.10"),
        archive_url=_exact_text(
            item["archive_url"],
            "https://www.python.org/ftp/python/3.12.10/" "python-3.12.10-amd64.zip",
        ),
        archive_sha256=_exact_text(
            item["archive_sha256"],
            "8649692de846c56a7189d6dae5c322ab20deb1b5908b6f39426b62a36f39415d",
        ),
        pe_file_count=47,
        amd64_loadable_count=43,
        signers=signers,
        declared_system_imports=system,
        declared_api_set_imports=api_sets,
        declared_private_imports=private,
        loadable_files=loadable,
        non_amd64_pe_files=non_amd64,
        dynamic_load_policy=_exact_text(
            item["dynamic_load_policy"], "exact_artifact_files_only"
        ),
        private_assembly_policy=_exact_text(
            item["private_assembly_policy"], "deny_unlisted"
        ),
    )


def parse_runtime_dependency_policy_bytes(data: bytes) -> RuntimeDependencyPolicy:
    """Parse structurally safe policy bytes without granting them authority."""

    payload = _decode_policy(data)
    try:
        item = _object(
            payload,
            frozenset(
                {
                    "schema",
                    "policy_id",
                    "platform",
                    "search_policy",
                    "products",
                    "cpython_artifact",
                }
            ),
        )
        if type(item["schema"]) is not int or item["schema"] != 1:
            _fail_schema()
        policy_id = _text(item["policy_id"], maximum=128)
        if (
            not _POLICY_ID.fullmatch(policy_id)
            or policy_id != "towerscout-runtime-dependency-policy-2026-09-08"
        ):
            _fail_schema()
        platform = _object(
            item["platform"],
            frozenset({"operating_system", "architecture"}),
        )
        operating_system = _exact_text(platform["operating_system"], "windows")
        architecture = _exact_text(platform["architecture"], "amd64")
        products = tuple(
            _parse_product(candidate)
            for candidate in _array(item["products"], minimum=3, maximum=3)
        )
        if tuple(product.product_id for product in products) != _EXPECTED_PRODUCT_ORDER:
            _fail_schema()
        return RuntimeDependencyPolicy(
            schema_version=1,
            policy_id=policy_id,
            operating_system=operating_system,
            architecture=architecture,
            search=_parse_search(item["search_policy"]),
            products=products,
            cpython=_parse_cpython(item["cpython_artifact"]),
            content_sha256=hashlib.sha256(data).hexdigest(),
        )
    except (_SchemaFailure, KeyError, TypeError, ValueError):
        raise RuntimeDependencyPolicyError(
            DependencyPolicyErrorCode.SCHEMA_INVALID
        ) from None


def parse_package_bound_runtime_dependency_policy_bytes(
    data: bytes,
) -> RuntimeDependencyPolicy:
    """Verify the compiled policy pin before parsing the resource bytes."""

    if type(data) is not bytes or not 1 <= len(data) <= _MAX_POLICY_BYTES:
        raise RuntimeDependencyPolicyError(DependencyPolicyErrorCode.INTEGRITY_INVALID)
    if hashlib.sha256(data).hexdigest() != _PACKAGE_POLICY_SHA256:
        raise RuntimeDependencyPolicyError(DependencyPolicyErrorCode.INTEGRITY_INVALID)
    return parse_runtime_dependency_policy_bytes(data)


def load_package_bound_runtime_dependency_policy() -> RuntimeDependencyPolicy:
    """Load only the fixed dependency policy bundled with this launcher."""

    try:
        with _POLICY_RESOURCE.open("rb") as handle:
            data = handle.read(_MAX_POLICY_BYTES + 1)
    except OSError:
        raise RuntimeDependencyPolicyError(
            DependencyPolicyErrorCode.RESOURCE_UNAVAILABLE
        ) from None
    return parse_package_bound_runtime_dependency_policy_bytes(data)


def package_bound_runtime_dependency_policy_path() -> Path:
    """Return the fixed dependency-policy path used by the package loader."""

    return _POLICY_RESOURCE.resolve()


__all__ = [
    "ApprovedDependencyFile",
    "CpythonDependencyArtifactPolicy",
    "DependencyImports",
    "DependencyPolicyErrorCode",
    "DependencySearchPolicy",
    "DependencySignaturePolicy",
    "NonAmd64PeFile",
    "PeMachine",
    "ProductDependencyPolicy",
    "RuntimeDependencyPolicy",
    "RuntimeDependencyPolicyError",
    "load_package_bound_runtime_dependency_policy",
    "package_bound_runtime_dependency_policy_path",
    "parse_package_bound_runtime_dependency_policy_bytes",
    "parse_runtime_dependency_policy_bytes",
]
