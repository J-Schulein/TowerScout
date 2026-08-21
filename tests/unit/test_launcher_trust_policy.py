from __future__ import annotations

import hashlib
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.target_contracts import MapProvider  # noqa: E402
from towerscout_launcher.trust_policy import (  # noqa: E402
    EligibleWindowsRoot,
    NativeChainCandidate,
    NativeWindowsTrustEvidence,
    TrustPolicyError,
    TrustPurpose,
    reject_ambient_ca_redirects,
    select_eligible_windows_root,
)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _root(marker: bytes = b"root-one") -> EligibleWindowsRoot:
    return EligibleWindowsRoot(marker, TrustPurpose.SERVER_AUTH)


def _candidate(
    root: EligibleWindowsRoot,
    *,
    intermediate_marker: str = "2",
    leaf_marker: str = "1",
    native_error: int = 0,
    policy_error: int = 0,
) -> NativeChainCandidate:
    return NativeChainCandidate(
        element_fingerprints_sha256=(
            leaf_marker * 64,
            intermediate_marker * 64,
            root.fingerprint_sha256,
        ),
        native_trust_error_status=native_error,
        ssl_policy_error=policy_error,
    )


def _evidence(
    *,
    roots: tuple[EligibleWindowsRoot, ...] | None = None,
    candidates: tuple[NativeChainCandidate, ...] | None = None,
) -> NativeWindowsTrustEvidence:
    selected_roots = roots or (_root(),)
    selected_candidates = candidates or (_candidate(selected_roots[0]),)
    return NativeWindowsTrustEvidence(
        provider=MapProvider.GOOGLE,
        verified_hostname="maps.googleapis.com",
        candidates=selected_candidates,
        eligible_roots=selected_roots,
    )


def test_selects_exact_der_from_one_policy_valid_windows_root() -> None:
    evidence = _evidence()

    selected = select_eligible_windows_root(evidence, environment={})

    assert selected.provider is MapProvider.GOOGLE
    assert selected.der_bytes == evidence.eligible_roots[0].der_bytes
    assert selected.fingerprint_sha256 == _digest(selected.der_bytes)
    assert selected.pem_sha256 == _digest(selected.pem_bytes)
    assert selected.pem_bytes.count(b"BEGIN CERTIFICATE") == 1
    assert selected.pem_bytes.count(b"END CERTIFICATE") == 1


def test_two_valid_paths_to_same_exact_root_are_not_ambiguous() -> None:
    root = _root()
    evidence = _evidence(
        roots=(root,),
        candidates=(
            _candidate(root, intermediate_marker="2"),
            _candidate(root, intermediate_marker="3"),
        ),
    )

    assert select_eligible_windows_root(evidence, environment={}).der_bytes == (
        root.der_bytes
    )


def test_two_valid_paths_to_distinct_eligible_roots_fail_ambiguous() -> None:
    first = _root(b"root-one")
    second = _root(b"root-two")
    evidence = _evidence(
        roots=(first, second),
        candidates=(
            _candidate(first, intermediate_marker="2"),
            _candidate(second, intermediate_marker="3"),
        ),
    )

    with pytest.raises(TrustPolicyError) as failure:
        select_eligible_windows_root(evidence, environment={})
    assert failure.value.code == "chain_ambiguous"


def test_invalid_lower_quality_path_does_not_create_ambiguity() -> None:
    first = _root(b"root-one")
    second = _root(b"root-two")
    evidence = _evidence(
        roots=(first, second),
        candidates=(
            _candidate(first, intermediate_marker="2"),
            _candidate(second, intermediate_marker="3", policy_error=1),
        ),
    )

    assert select_eligible_windows_root(evidence, environment={}).der_bytes == (
        first.der_bytes
    )


@pytest.mark.parametrize(("native_error", "policy_error"), ((1, 0), (0, 1)))
def test_no_native_policy_valid_path_fails_closed(
    native_error: int, policy_error: int
) -> None:
    root = _root()
    evidence = _evidence(
        roots=(root,),
        candidates=(
            _candidate(root, native_error=native_error, policy_error=policy_error),
        ),
    )

    with pytest.raises(TrustPolicyError) as failure:
        select_eligible_windows_root(evidence, environment={})
    assert failure.value.code == "chain_unverified"


def test_ca_only_or_partial_terminal_cannot_anchor() -> None:
    root = _root()
    partial = NativeChainCandidate(("1" * 64, "9" * 64), 0, 0)

    with pytest.raises(TrustPolicyError) as failure:
        select_eligible_windows_root(
            _evidence(roots=(root,), candidates=(partial,)), environment={}
        )
    assert failure.value.code == "root_ineligible"


def test_fixed_provider_hostname_is_required() -> None:
    with pytest.raises(TrustPolicyError) as failure:
        select_eligible_windows_root(
            replace(_evidence(), verified_hostname="attacker.invalid"), environment={}
        )
    assert failure.value.code == "chain_invalid"


@pytest.mark.parametrize(
    "variable",
    (
        "SSL_CERT_FILE",
        "ssl_cert_dir",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "PIP_CERT",
        "GIT_SSL_CAINFO",
    ),
)
def test_ambient_certificate_redirects_are_rejected_without_disclosure(
    variable: str,
) -> None:
    private_path = r"C:\Users\PRIVATE\attacker-ca.pem"

    with pytest.raises(TrustPolicyError) as failure:
        reject_ambient_ca_redirects({variable: private_path})

    assert failure.value.code == "ambient_ca_redirect"
    assert private_path not in str(failure.value)
    assert private_path not in repr(failure.value)


@pytest.mark.parametrize(
    "constructor",
    (
        lambda: NativeChainCandidate(("1" * 64,), 0, 0),
        lambda: NativeChainCandidate(("1" * 64, "bad"), 0, 0),
        lambda: NativeChainCandidate(("1" * 64, "1" * 64), 0, 0),
        lambda: NativeChainCandidate(("1" * 64, "2" * 64), -1, 0),
        lambda: EligibleWindowsRoot(b"", TrustPurpose.SERVER_AUTH),
        lambda: EligibleWindowsRoot(b"x" * (128 * 1024 + 1), TrustPurpose.SERVER_AUTH),
    ),
)
def test_candidate_and_root_bounds_fail_closed(constructor) -> None:  # noqa: ANN001
    with pytest.raises(ValueError):
        constructor()


def test_evidence_count_and_root_snapshot_bounds_fail_closed() -> None:
    root = _root()
    candidate = _candidate(root)

    with pytest.raises(ValueError):
        NativeWindowsTrustEvidence(
            MapProvider.GOOGLE,
            "maps.googleapis.com",
            (candidate,) * 17,
            (root,),
        )
    with pytest.raises(ValueError):
        NativeWindowsTrustEvidence(
            MapProvider.GOOGLE,
            "maps.googleapis.com",
            (candidate,),
            tuple(_root(index.to_bytes(4, "big")) for index in range(2049)),
        )


def test_nested_evidence_collections_must_be_immutable_tuples() -> None:
    root = _root()
    candidate = _candidate(root)

    with pytest.raises(ValueError, match="candidate is invalid"):
        NativeChainCandidate(["1" * 64, root.fingerprint_sha256], 0, 0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="evidence is invalid"):
        NativeWindowsTrustEvidence(
            MapProvider.GOOGLE,
            "maps.googleapis.com",
            [candidate],  # type: ignore[arg-type]
            (root,),
        )
    with pytest.raises(ValueError, match="evidence is invalid"):
        NativeWindowsTrustEvidence(
            MapProvider.GOOGLE,
            "maps.googleapis.com",
            (candidate,),
            [root],  # type: ignore[arg-type]
        )


def test_policy_boundary_rejects_subclass_type_confusion() -> None:
    class HostileFingerprint(str):
        pass

    class HostileEvidence(NativeWindowsTrustEvidence):
        pass

    root = _root()
    with pytest.raises(ValueError, match="candidate is invalid"):
        NativeChainCandidate(
            (HostileFingerprint("1" * 64), root.fingerprint_sha256), 0, 0
        )

    evidence = _evidence()
    hostile = HostileEvidence(
        evidence.provider,
        evidence.verified_hostname,
        evidence.candidates,
        evidence.eligible_roots,
    )
    with pytest.raises(TrustPolicyError) as failure:
        select_eligible_windows_root(hostile, environment={})
    assert failure.value.code == "chain_invalid"


def test_one_native_snapshot_cannot_mix_distinct_tls_leaves() -> None:
    root = _root()

    with pytest.raises(ValueError, match="evidence is invalid"):
        _evidence(
            roots=(root,),
            candidates=(
                _candidate(root, leaf_marker="1"),
                _candidate(root, leaf_marker="9"),
            ),
        )


def test_all_purpose_windows_root_is_eligible() -> None:
    root = EligibleWindowsRoot(b"all-purpose-root", TrustPurpose.ALL_PURPOSE)

    selected = select_eligible_windows_root(
        _evidence(roots=(root,), candidates=(_candidate(root),)), environment={}
    )

    assert selected.der_bytes == root.der_bytes


def test_malformed_environment_mapping_fails_closed() -> None:
    with pytest.raises(TrustPolicyError) as failure:
        reject_ambient_ca_redirects({"SSL_CERT_FILE": object()})  # type: ignore[dict-item]

    assert failure.value.code == "ambient_ca_redirect"


def test_material_and_evidence_are_immutable_and_redacted() -> None:
    evidence = _evidence()
    selected = select_eligible_windows_root(evidence, environment={})
    private_values = (
        evidence.eligible_roots[0].fingerprint_sha256,
        evidence.candidates[0].terminal_fingerprint_sha256,
        evidence.eligible_roots[0].der_bytes.hex(),
    )
    output = " ".join(
        (
            repr(evidence),
            repr(evidence.candidates[0]),
            repr(evidence.eligible_roots[0]),
            repr(selected),
            selected.public_message,
        )
    )

    assert all(value not in output for value in private_values)
    with pytest.raises(FrozenInstanceError):
        evidence.verified_hostname = "attacker.invalid"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        selected.der_bytes = b"attacker"  # type: ignore[misc]
