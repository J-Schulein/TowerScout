"""Exact certificate replacement plan for the durable repair transaction."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import NoReturn

from .target_contracts import MapProvider
from .trust_policy import SelectedWindowsRootMaterial

MAX_LOCAL_CA_BYTES = 256 * 1024
MAX_CA_BUNDLE_BYTES = 1024 * 1024
CERTIFICATE_FILE_MODE = 0o644
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _fail() -> NoReturn:
    raise ValueError("Certificate replacement plan is invalid.")


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class CertificateReplacementPlan:
    """Bind the exact two transaction-produced certificate destinations."""

    provider: MapProvider
    windows_root_fingerprint_sha256: str = field(repr=False)
    local_ca_contents: bytes = field(repr=False)
    ca_bundle_contents: bytes = field(repr=False)
    local_ca_mode: int = CERTIFICATE_FILE_MODE
    ca_bundle_mode: int = CERTIFICATE_FILE_MODE
    local_ca_sha256: str = field(init=False, repr=False)
    ca_bundle_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.provider) is not MapProvider
            or type(self.windows_root_fingerprint_sha256) is not str
            or _SHA256.fullmatch(self.windows_root_fingerprint_sha256) is None
            or type(self.local_ca_contents) is not bytes
            or type(self.ca_bundle_contents) is not bytes
        ):
            _fail()
        bundle_prefix = self.ca_bundle_contents[: -len(self.local_ca_contents)]
        if (
            not 1 <= len(self.local_ca_contents) <= MAX_LOCAL_CA_BYTES
            or not 1 <= len(self.ca_bundle_contents) <= MAX_CA_BUNDLE_BYTES
            or type(self.local_ca_mode) is not int
            or self.local_ca_mode != CERTIFICATE_FILE_MODE
            or type(self.ca_bundle_mode) is not int
            or self.ca_bundle_mode != CERTIFICATE_FILE_MODE
            or b"\x00" in self.local_ca_contents
            or b"\x00" in self.ca_bundle_contents
            or not self.local_ca_contents.startswith(b"-----BEGIN CERTIFICATE-----\n")
            or not self.local_ca_contents.endswith(b"-----END CERTIFICATE-----\n")
            or self.local_ca_contents.count(b"-----BEGIN CERTIFICATE-----") != 1
            or self.local_ca_contents.count(b"-----END CERTIFICATE-----") != 1
            or not self.ca_bundle_contents.endswith(self.local_ca_contents)
            or not bundle_prefix
            or not bundle_prefix.endswith(b"\n")
        ):
            _fail()
        object.__setattr__(
            self,
            "local_ca_sha256",
            _sha256(self.local_ca_contents),
        )
        object.__setattr__(
            self,
            "ca_bundle_sha256",
            _sha256(self.ca_bundle_contents),
        )

    def __repr__(self) -> str:
        return (
            "CertificateReplacementPlan("
            f"provider={self.provider.value!r}, "
            f"local_ca_size={len(self.local_ca_contents)!r}, "
            f"ca_bundle_size={len(self.ca_bundle_contents)!r}, <redacted>)"
        )


def plan_certificate_replacement(
    selected_root: SelectedWindowsRootMaterial,
    system_bundle: bytes,
) -> CertificateReplacementPlan:
    """Append one selected Windows root to one exact container system bundle."""

    if (
        type(selected_root) is not SelectedWindowsRootMaterial
        or type(system_bundle) is not bytes
        or not 1 <= len(system_bundle) <= MAX_CA_BUNDLE_BYTES
        or b"\x00" in system_bundle
    ):
        _fail()
    local_ca = selected_root.pem_bytes
    if (
        len(local_ca) > MAX_LOCAL_CA_BYTES
        or _sha256(local_ca) != selected_root.pem_sha256
    ):
        _fail()
    base = system_bundle.rstrip(b"\r\n")
    if not base:
        _fail()
    combined = base + b"\n" + local_ca.lstrip(b"\r\n")
    if len(combined) > MAX_CA_BUNDLE_BYTES:
        _fail()
    return CertificateReplacementPlan(
        selected_root.provider,
        selected_root.fingerprint_sha256,
        local_ca,
        combined,
    )


__all__ = [
    "CERTIFICATE_FILE_MODE",
    "MAX_CA_BUNDLE_BYTES",
    "MAX_LOCAL_CA_BYTES",
    "CertificateReplacementPlan",
    "plan_certificate_replacement",
]
