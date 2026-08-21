"""Inert combined trust evidence for one retained Windows runtime file."""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Sequence

from .authenticode import (
    AuthenticodeBackend,
    AuthenticodeErrorCode,
    AuthenticodeVerificationError,
    VerificationClock,
    VerifiedAuthenticodeEvidence,
    verify_package_bound_authenticode_signer,
)
from .runtime_identity import (
    BoundInstallationCandidate,
    InstallationCandidateEvidence,
    InstallationRecordBackend,
    PeProductBackend,
    RuntimeIdentityErrorCode,
    RuntimeIdentityVerificationError,
    VerifiedPeProductEvidence,
    open_package_bound_installation,
    verify_package_bound_pe_product,
)
from .runtime_policy import (
    ProductPolicy,
    RuntimePolicy,
    RuntimePolicyError,
    RuntimeProductId,
    VersionEvidenceKind,
    load_package_bound_runtime_policy,
)
from .windows_security import FileSnapshot, StableFileIdentity, WindowsFileApi

_EVIDENCE_DOMAIN = b"TowerScout.CombinedRuntimeEvidence.v1"
_VERSION_CHARACTERS = frozenset("0123456789")


class RuntimeVerificationErrorCode(str, Enum):
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    RUNTIME_IDENTITY_INVALID = "runtime_identity_invalid"
    RUNTIME_REPLACED = "runtime_replaced"


class RuntimeVerificationError(RuntimeError):
    """Sanitized failure at the combined runtime-evidence boundary."""

    _MESSAGES = {
        RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE: (
            "Secure combined Windows runtime verification is unavailable."
        ),
        RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID: (
            "The runtime installation, product, version, or signer is not approved."
        ),
        RuntimeVerificationErrorCode.RUNTIME_REPLACED: (
            "The runtime executable or installation record changed during review."
        ),
    }

    def __init__(self, code: RuntimeVerificationErrorCode) -> None:
        if type(code) is not RuntimeVerificationErrorCode:
            raise ValueError("Unknown combined runtime-verification error code.")
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"RuntimeVerificationError(code={self.code.value!r})"


def _fail(code: RuntimeVerificationErrorCode) -> NoReturn:
    raise RuntimeVerificationError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_digest(fields: Sequence[bytes]) -> str:
    digest = hashlib.sha256()
    for value in (_EVIDENCE_DOMAIN, *fields):
        if type(value) is not bytes or len(value) > 128 * 1024:
            raise ValueError("Combined runtime evidence is invalid.")
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return digest.hexdigest()


def _identity_fields(identity: StableFileIdentity) -> tuple[bytes, bytes]:
    return (identity.volume_serial.to_bytes(8, "big"), identity.file_id)


@dataclass(frozen=True, slots=True, repr=False)
class CombinedRuntimeEvidence:
    """Installation, PE, and signer proof for one retained file snapshot."""

    installation: InstallationCandidateEvidence = field(repr=False)
    pe_product: VerifiedPeProductEvidence = field(repr=False)
    authenticode: VerifiedAuthenticodeEvidence = field(repr=False)
    product_id: RuntimeProductId = field(init=False)
    exact_version: str = field(init=False)
    policy_sha256: str = field(init=False, repr=False)
    file_identity: StableFileIdentity = field(init=False, repr=False)
    file_sha256: str = field(init=False, repr=False)
    evidence_sha256: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.installation) is not InstallationCandidateEvidence
            or type(self.pe_product) is not VerifiedPeProductEvidence
            or type(self.authenticode) is not VerifiedAuthenticodeEvidence
        ):
            raise ValueError("Combined runtime evidence is invalid.")

        product_id = self.pe_product.product_id
        exact_version = self.pe_product.exact_version
        signer_products = self.authenticode.signer_policy_product_ids
        policy_hashes = (
            self.installation.policy_sha256,
            self.pe_product.policy_sha256,
            self.authenticode.policy_sha256,
        )
        identities = (
            self.installation.file_identity,
            self.pe_product.file_identity,
            self.authenticode.file_identity,
        )
        file_hashes = (
            self.installation.file_sha256,
            self.pe_product.file_sha256,
            self.authenticode.file_sha256,
        )
        evidence_hashes = (
            self.installation.evidence_sha256,
            self.pe_product.evidence_sha256,
            self.authenticode.evidence_sha256,
        )
        version_parts = exact_version.split(".") if type(exact_version) is str else []
        if (
            type(product_id) is not RuntimeProductId
            or type(signer_products) is not tuple
            or any(type(value) is not RuntimeProductId for value in signer_products)
            or any(type(value) is not str for value in policy_hashes)
            or any(type(value) is not StableFileIdentity for value in identities)
            or any(type(value) is not str for value in file_hashes)
            or any(not _is_sha256(value) for value in evidence_hashes)
            or len(version_parts) != 3
            or any(
                not part
                or any(character not in _VERSION_CHARACTERS for character in part)
                for part in version_parts
            )
        ):
            raise ValueError("Combined runtime evidence is invalid.")
        if (
            self.installation.product_id is not product_id
            or product_id not in signer_products
            or len(set(policy_hashes)) != 1
            or len(set(identities)) != 1
            or len(set(file_hashes)) != 1
            or not _is_sha256(policy_hashes[0])
            or not _is_sha256(file_hashes[0])
        ):
            raise ValueError("Combined runtime evidence is invalid.")

        identity = identities[0]
        object.__setattr__(self, "product_id", product_id)
        object.__setattr__(self, "exact_version", exact_version)
        object.__setattr__(self, "policy_sha256", policy_hashes[0])
        object.__setattr__(self, "file_identity", identity)
        object.__setattr__(self, "file_sha256", file_hashes[0])
        object.__setattr__(
            self,
            "evidence_sha256",
            _canonical_digest(
                (
                    product_id.value.encode("ascii"),
                    exact_version.encode("ascii"),
                    policy_hashes[0].encode("ascii"),
                    *_identity_fields(identity),
                    file_hashes[0].encode("ascii"),
                    self.installation.evidence_sha256.encode("ascii"),
                    self.pe_product.evidence_sha256.encode("ascii"),
                    self.authenticode.evidence_sha256.encode("ascii"),
                )
            ),
        )

    def __repr__(self) -> str:
        return (
            "CombinedRuntimeEvidence("
            f"product={self.product_id.value!r}, version={self.exact_version!r}, "
            "state='non-executable', <redacted>)"
        )


def combine_runtime_evidence(
    installation: InstallationCandidateEvidence,
    pe_product: VerifiedPeProductEvidence,
    authenticode: VerifiedAuthenticodeEvidence,
) -> CombinedRuntimeEvidence:
    """Combine three independently validated evidence objects fail closed."""

    try:
        return CombinedRuntimeEvidence(installation, pe_product, authenticode)
    except (TypeError, ValueError):
        _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _map_identity_error(error: RuntimeIdentityVerificationError) -> NoReturn:
    if error.code is RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE:
        _fail(RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if error.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED:
        _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
    _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _map_authenticode_error(error: AuthenticodeVerificationError) -> NoReturn:
    if error.code is AuthenticodeErrorCode.VERIFICATION_UNAVAILABLE:
        _fail(RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    if error.code is AuthenticodeErrorCode.RUNTIME_REPLACED:
        _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
    _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)


def _snapshot_matches(
    snapshot: FileSnapshot, evidence: CombinedRuntimeEvidence
) -> bool:
    return (
        type(snapshot) is FileSnapshot
        and snapshot.identity == evidence.file_identity
        and snapshot.sha256 == evidence.file_sha256
    )


class BoundRuntimeEvidence:
    """Own inert combined evidence and its handle through the caller's final use.

    Evidence authority is live only while this owner remains open.  Call
    :meth:`assert_unchanged` at the final non-executable use, then close the
    owner explicitly or through its context manager.  Revalidation and close
    are serialized across the installation-record scan and held-file hash.
    """

    __slots__ = ("_active_owner", "_candidate", "_evidence", "_lifetime_lock")

    def __init__(
        self,
        *,
        candidate: BoundInstallationCandidate,
        evidence: CombinedRuntimeEvidence,
    ) -> None:
        if (
            type(candidate) is not BoundInstallationCandidate
            or type(evidence) is not CombinedRuntimeEvidence
            or candidate.evidence != evidence.installation
            or candidate.closed
        ):
            raise ValueError("Bound combined runtime evidence is invalid.")
        self._candidate = candidate
        self._evidence = evidence
        self._lifetime_lock = threading.RLock()
        self._active_owner: int | None = None

    @property
    def evidence(self) -> CombinedRuntimeEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._lifetime_lock:
            return bool(self._candidate.closed)

    def assert_unchanged(self) -> CombinedRuntimeEvidence:
        """Revalidate all installation records and the same held file."""

        self._lifetime_lock.acquire()
        if self._active_owner is not None:
            self._lifetime_lock.release()
            _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
        if self._candidate.closed:
            self._lifetime_lock.release()
            _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
        self._active_owner = threading.get_ident()
        try:
            try:
                snapshot = self._candidate.assert_unchanged()
            except RuntimeIdentityVerificationError as error:
                _map_identity_error(error)
            except Exception:
                _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
            if not _snapshot_matches(snapshot, self._evidence):
                _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
            return self._evidence
        finally:
            self._active_owner = None
            self._lifetime_lock.release()

    def close(self) -> None:
        with self._lifetime_lock:
            if self._active_owner is not None:
                _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
            try:
                self._candidate.close()
            except Exception:
                _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)

    def __enter__(self) -> "BoundRuntimeEvidence":
        if self.closed:
            _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else "open"
        return (
            "BoundRuntimeEvidence("
            f"product={self._evidence.product_id.value!r}, state={state!r}, "
            "capability='non-executable', <redacted>)"
        )


def _close_candidate(candidate: BoundInstallationCandidate | None) -> None:
    if candidate is None:
        return
    try:
        candidate.close()
    except BaseException:
        pass


def _load_pe_product_policy(
    product_id: RuntimeProductId,
) -> tuple[RuntimePolicy, ProductPolicy]:
    if type(product_id) is not RuntimeProductId:
        _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    try:
        policy = load_package_bound_runtime_policy()
    except RuntimePolicyError:
        _fail(RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    products = tuple(
        product for product in policy.products if product.product_id is product_id
    )
    if len(products) != 1:
        _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    product = products[0]
    if product.version_evidence.kind is not VersionEvidenceKind.PE_VERSION_RESOURCE:
        _fail(RuntimeVerificationErrorCode.VERIFICATION_UNAVAILABLE)
    return policy, product


def open_package_bound_runtime_evidence(
    product_id: RuntimeProductId,
    *,
    installation_backend: InstallationRecordBackend | None = None,
    file_api: WindowsFileApi | None = None,
    pe_backend: PeProductBackend | None = None,
    authenticode_backend: AuthenticodeBackend | None = None,
    clock: VerificationClock | None = None,
) -> BoundRuntimeEvidence:
    """Open, combine, finally revalidate, and retain inert runtime evidence."""

    policy, product = _load_pe_product_policy(product_id)

    candidate: BoundInstallationCandidate | None = None
    transferred = False
    try:
        candidate = open_package_bound_installation(
            product_id,
            backend=installation_backend,
            file_api=file_api,
        )
        bound_file = candidate.bound_file
        pe_product = verify_package_bound_pe_product(
            bound_file,
            backend=pe_backend,
        )
        authenticode = verify_package_bound_authenticode_signer(
            bound_file,
            backend=authenticode_backend,
            clock=clock,
        )
        evidence = combine_runtime_evidence(
            candidate.evidence,
            pe_product,
            authenticode,
        )
        if (
            evidence.product_id is not product_id
            or evidence.exact_version != product.exact_version
            or evidence.policy_sha256 != policy.content_sha256
            or candidate.bound_file is not bound_file
        ):
            _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)

        final_snapshot = candidate.assert_unchanged()
        if not _snapshot_matches(final_snapshot, evidence):
            _fail(RuntimeVerificationErrorCode.RUNTIME_REPLACED)
        result = BoundRuntimeEvidence(candidate=candidate, evidence=evidence)
        transferred = True
        return result
    except RuntimeVerificationError:
        raise
    except RuntimeIdentityVerificationError as error:
        _map_identity_error(error)
    except AuthenticodeVerificationError as error:
        _map_authenticode_error(error)
    except Exception:
        _fail(RuntimeVerificationErrorCode.RUNTIME_IDENTITY_INVALID)
    finally:
        if not transferred:
            _close_candidate(candidate)


__all__ = [
    "BoundRuntimeEvidence",
    "CombinedRuntimeEvidence",
    "RuntimeVerificationError",
    "RuntimeVerificationErrorCode",
    "combine_runtime_evidence",
    "open_package_bound_runtime_evidence",
]
