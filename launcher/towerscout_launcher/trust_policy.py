"""Pure policy for already-native-verified Windows TLS chain candidates.

This module performs no socket, store, or CryptoAPI work. Its evidence types
must be populated by the separate Windows-native verifier before they can
authorize any repair; caller-asserted fixtures prove policy behavior only.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from .target_contracts import MapProvider

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CHAIN_ELEMENTS = 16
_MAX_CANDIDATES = 16
_MAX_ELIGIBLE_ROOTS = 2048
_MAX_CERTIFICATE_DER_BYTES = 128 * 1024
_MAX_ROOT_SNAPSHOT_BYTES = 32 * 1024 * 1024
_CA_REDIRECT_VARIABLES = frozenset(
    {
        "AWS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
        "HTTPLIB2_CA_CERTS",
        "NIX_SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "PERL_LWP_SSL_CA_FILE",
        "PIP_CERT",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    }
)
_PROVIDER_HOSTS = {
    MapProvider.GOOGLE: "maps.googleapis.com",
    MapProvider.AZURE: "atlas.microsoft.com",
}


class TrustPurpose(str, Enum):
    SERVER_AUTH = "server_auth"
    ALL_PURPOSE = "all_purpose"


class TrustPolicyError(RuntimeError):
    """A sanitized, stable trust-policy failure."""

    _MESSAGES = {
        "ambient_ca_redirect": "An unsupported certificate override is active.",
        "chain_ambiguous": "The provider certificate chain is ambiguous.",
        "chain_invalid": "The provider certificate chain is invalid.",
        "chain_unverified": "The provider certificate chain was not verified.",
        "root_ineligible": "The provider chain has no eligible Windows root.",
        "unsupported_provider": "The selected provider is unsupported.",
    }

    def __init__(self, code: str) -> None:
        if code not in self._MESSAGES:
            raise ValueError("Unknown trust-policy error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"TrustPolicyError(code={self.code!r})"


def _is_dword(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**32


@dataclass(frozen=True, slots=True, repr=False)
class NativeChainCandidate:
    """One bounded Crypt32 chain candidate, including its native policy result."""

    element_fingerprints_sha256: tuple[str, ...] = field(repr=False)
    native_trust_error_status: int = field(repr=False)
    ssl_policy_error: int = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.element_fingerprints_sha256) is not tuple
            or not 2 <= len(self.element_fingerprints_sha256) <= _MAX_CHAIN_ELEMENTS
            or any(
                type(value) is not str or not _SHA256.fullmatch(value)
                for value in self.element_fingerprints_sha256
            )
            or len(set(self.element_fingerprints_sha256))
            != len(self.element_fingerprints_sha256)
            or not _is_dword(self.native_trust_error_status)
            or not _is_dword(self.ssl_policy_error)
        ):
            raise ValueError("Native chain candidate is invalid.")

    @property
    def policy_valid(self) -> bool:
        return self.native_trust_error_status == 0 and self.ssl_policy_error == 0

    @property
    def terminal_fingerprint_sha256(self) -> str:
        return self.element_fingerprints_sha256[-1]

    def __repr__(self) -> str:
        return "NativeChainCandidate(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class EligibleWindowsRoot:
    """Exact DER from the independently filtered Windows ROOT snapshot."""

    der_bytes: bytes = field(repr=False)
    purpose: TrustPurpose
    fingerprint_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.der_bytes) is not bytes
            or not 1 <= len(self.der_bytes) <= _MAX_CERTIFICATE_DER_BYTES
            or type(self.purpose) is not TrustPurpose
        ):
            raise ValueError("Eligible Windows root material is invalid.")
        object.__setattr__(
            self, "fingerprint_sha256", hashlib.sha256(self.der_bytes).hexdigest()
        )

    def __repr__(self) -> str:
        return f"EligibleWindowsRoot(purpose={self.purpose.value!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class NativeWindowsTrustEvidence:
    """One immutable native snapshot containing best and alternate candidates."""

    provider: MapProvider
    verified_hostname: str
    candidates: tuple[NativeChainCandidate, ...] = field(repr=False)
    eligible_roots: tuple[EligibleWindowsRoot, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.provider) is not MapProvider
            or type(self.verified_hostname) is not str
            or not self.verified_hostname
            or "\x00" in self.verified_hostname
            or len(self.verified_hostname) > 253
            or type(self.candidates) is not tuple
            or not 1 <= len(self.candidates) <= _MAX_CANDIDATES
            or any(
                type(candidate) is not NativeChainCandidate
                for candidate in self.candidates
            )
            or type(self.eligible_roots) is not tuple
            or not 1 <= len(self.eligible_roots) <= _MAX_ELIGIBLE_ROOTS
            or any(
                type(root) is not EligibleWindowsRoot for root in self.eligible_roots
            )
            or sum(len(root.der_bytes) for root in self.eligible_roots)
            > _MAX_ROOT_SNAPSHOT_BYTES
            or len({root.fingerprint_sha256 for root in self.eligible_roots})
            != len(self.eligible_roots)
            or len(
                {
                    candidate.element_fingerprints_sha256[0]
                    for candidate in self.candidates
                }
            )
            != 1
        ):
            raise ValueError("Native Windows trust evidence is invalid.")

    def __repr__(self) -> str:
        return f"NativeWindowsTrustEvidence(provider={self.provider.value!r})"


def _pem_from_der(der_bytes: bytes) -> bytes:
    encoded = base64.b64encode(der_bytes)
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"\n".join(lines)
        + (b"\n-----END CERTIFICATE-----\n")
    )


@dataclass(frozen=True, slots=True, repr=False)
class SelectedWindowsRootMaterial:
    provider: MapProvider
    der_bytes: bytes = field(repr=False)
    fingerprint_sha256: str = field(init=False, repr=False)
    pem_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.provider) is not MapProvider
            or type(self.der_bytes) is not bytes
            or not 1 <= len(self.der_bytes) <= _MAX_CERTIFICATE_DER_BYTES
        ):
            raise ValueError("Selected Windows root material is invalid.")
        pem = _pem_from_der(self.der_bytes)
        object.__setattr__(
            self, "fingerprint_sha256", hashlib.sha256(self.der_bytes).hexdigest()
        )
        object.__setattr__(self, "pem_sha256", hashlib.sha256(pem).hexdigest())

    @property
    def pem_bytes(self) -> bytes:
        return _pem_from_der(self.der_bytes)

    @property
    def public_message(self) -> str:
        return "One eligible Windows root was selected for the fixed provider target."

    def __repr__(self) -> str:
        return f"SelectedWindowsRootMaterial(provider={self.provider.value!r})"


def reject_ambient_ca_redirects(environment: Mapping[str, str]) -> None:
    """Reject rather than inherit certificate-path overrides."""

    if not isinstance(environment, Mapping):
        raise TrustPolicyError("ambient_ca_redirect")
    try:
        active = {
            key.upper()
            for key, value in environment.items()
            if type(key) is str
            and type(value) is str
            and key.upper() in _CA_REDIRECT_VARIABLES
            and value
        }
        malformed = any(
            type(key) is not str or type(value) is not str
            for key, value in environment.items()
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise TrustPolicyError("ambient_ca_redirect") from None
    if active or malformed:
        raise TrustPolicyError("ambient_ca_redirect")


def select_eligible_windows_root(
    evidence: NativeWindowsTrustEvidence,
    *,
    environment: Mapping[str, str],
) -> SelectedWindowsRootMaterial:
    """Select one exact ROOT DER across all native policy-valid candidates."""

    reject_ambient_ca_redirects(environment)
    if type(evidence) is not NativeWindowsTrustEvidence:
        raise TrustPolicyError("chain_invalid")
    expected_hostname = _PROVIDER_HOSTS.get(evidence.provider)
    if expected_hostname is None:
        raise TrustPolicyError("unsupported_provider")
    if evidence.verified_hostname.casefold() != expected_hostname:
        raise TrustPolicyError("chain_invalid")

    valid_candidates = tuple(
        candidate for candidate in evidence.candidates if candidate.policy_valid
    )
    if not valid_candidates:
        raise TrustPolicyError("chain_unverified")
    eligible_by_fingerprint = {
        root.fingerprint_sha256: root for root in evidence.eligible_roots
    }
    if any(
        candidate.terminal_fingerprint_sha256 not in eligible_by_fingerprint
        for candidate in valid_candidates
    ):
        raise TrustPolicyError("root_ineligible")
    selected_fingerprints = {
        candidate.terminal_fingerprint_sha256 for candidate in valid_candidates
    }
    if len(selected_fingerprints) != 1:
        raise TrustPolicyError("chain_ambiguous")
    selected = eligible_by_fingerprint[next(iter(selected_fingerprints))]
    return SelectedWindowsRootMaterial(evidence.provider, selected.der_bytes)
