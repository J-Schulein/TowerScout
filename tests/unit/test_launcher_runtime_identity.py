from __future__ import annotations

import ast
import ctypes
import dataclasses
import hashlib
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_identity as runtime_identity_module  # noqa: E402
from towerscout_launcher.pe_version import PeVersionResource  # noqa: E402
from towerscout_launcher.runtime_identity import (  # noqa: E402
    BoundInstallationCandidate,
    InstallationCandidateEvidence,
    NativeWindowsInstallationBackend,
    RegistryValueSelector,
    RegistryStringValues,
    RuntimeIdentityErrorCode,
    RuntimeIdentityVerificationError,
    VerifiedPeProductEvidence,
    open_package_bound_installation,
    verify_package_bound_pe_product,
)
from towerscout_launcher.runtime_policy import (  # noqa: E402
    RuntimeProductId,
    load_package_bound_runtime_policy,
)
from towerscout_launcher.windows_security import (  # noqa: E402
    NativeFileFacts,
    capture_handle_bound_file,
)

_SECRET = r"C:\Users\private-user\secret-runtime.exe"
_POLICY = load_package_bound_runtime_policy()
_DOCKER_SYSTEM = (
    "HKEY_LOCAL_MACHINE",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
)
_DOCKER_USER = (
    "HKEY_CURRENT_USER",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
)
_PODMAN = (
    "HKEY_LOCAL_MACHINE",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0D5BAFD9-FE6A-4267-841A-7760A8F2B03C}",
)
_PYTHON_SYSTEM = (
    "HKEY_LOCAL_MACHINE",
    r"SOFTWARE\Python\PythonCore\3.12",
)
_DOCKER_PATH = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
_DOCKER_FINAL = r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker.exe"


def _native_facts(
    path: str,
    content: bytes,
    *,
    identity: int = 1,
    link_count: int = 1,
) -> NativeFileFacts:
    return NativeFileFacts(
        final_path=path,
        volume_serial=0x0102030405060708,
        file_id=identity.to_bytes(16, "big"),
        attributes=0x80,
        link_count=link_count,
        size=len(content),
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


class _OpenFileState:
    def __init__(self, path: str, content: bytes, facts: NativeFileFacts) -> None:
        self.path = path
        self.content = content
        self.facts = facts
        self.cursor = 0


class _FileApi:
    supported = True

    def __init__(self) -> None:
        self.specs: dict[str, tuple[bytes, NativeFileFacts] | Exception] = {}
        self.states: dict[object, _OpenFileState] = {}
        self.opened: list[str] = []
        self.closed: list[object] = []

    def add(
        self,
        requested_path: str,
        *,
        content: bytes = b"signed-runtime",
        final_path: str | None = None,
        identity: int = 1,
        link_count: int = 1,
    ) -> None:
        self.specs[requested_path] = (
            content,
            _native_facts(
                final_path or requested_path,
                content,
                identity=identity,
                link_count=link_count,
            ),
        )

    def open_file_for_identity(self, path: str) -> object:
        self.opened.append(path)
        selected = self.specs[path]
        if isinstance(selected, Exception):
            raise selected
        content, facts = selected
        handle = object()
        self.states[handle] = _OpenFileState(path, content, facts)
        return handle

    def query_file(self, handle: object) -> NativeFileFacts:
        state = self.states[handle]
        return replace(state.facts, size=len(state.content))

    def rewind_file(self, handle: object) -> None:
        self.states[handle].cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        state = self.states[handle]
        value = state.content[state.cursor : state.cursor + maximum]
        state.cursor += len(value)
        return value

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)


def _docker_pe(**changes: object) -> PeVersionResource:
    values: dict[str, object] = {
        "company_name": "Docker Inc",
        "product_name": "Docker Client",
        "original_filename": "docker-windows-amd64.exe",
        "file_version": "29.7.2",
        "product_version": "29.7.2",
        "fixed_file_version": (29, 7, 2, 17),
        "fixed_product_version": (29, 7, 2, 19),
        "translations": ((0x0409, 0x04B0),),
        "resource_sha256": "7" * 64,
    }
    values.update(changes)
    return PeVersionResource(**values)  # type: ignore[arg-type]


class _PeBackend:
    def __init__(
        self,
        facts: object,
        *,
        supported: object = True,
        failure: Exception | None = None,
        mutate=None,  # noqa: ANN001
    ) -> None:
        self.facts = facts
        self._supported = supported
        self.failure = failure
        self.mutate = mutate
        self.handles: list[object] = []
        self.snapshots: list[object] = []

    @property
    def supported(self) -> bool:
        return self._supported  # type: ignore[return-value]

    def inspect_open_file(self, *, handle: object, snapshot: object) -> object:
        self.handles.append(handle)
        self.snapshots.append(snapshot)
        if self.mutate is not None:
            self.mutate(handle)
        if self.failure is not None:
            raise self.failure
        return self.facts


def _verify_pe(
    facts: object,
    *,
    final_path: str = _DOCKER_FINAL,
    backend: _PeBackend | None = None,
) -> tuple[VerifiedPeProductEvidence, _FileApi, _PeBackend]:
    api = _FileApi()
    api.add("runtime.exe", final_path=final_path)
    selected = backend or _PeBackend(facts)
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        evidence = verify_package_bound_pe_product(
            bound, backend=selected  # type: ignore[arg-type]
        )
        assert selected.handles == [next(iter(api.states))]
        assert selected.snapshots == [bound.snapshot]
        assert not bound.closed
    return evidence, api, selected


def _reject_pe(
    facts: object,
    *,
    final_path: str = _DOCKER_FINAL,
    backend: _PeBackend | None = None,
) -> RuntimeIdentityVerificationError:
    api = _FileApi()
    api.add("runtime.exe", final_path=final_path)
    selected = backend or _PeBackend(facts)
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(RuntimeIdentityVerificationError) as failure:
            verify_package_bound_pe_product(
                bound, backend=selected  # type: ignore[arg-type]
            )
    assert _SECRET not in str(failure.value)
    assert _SECRET not in repr(failure.value)
    return failure.value


class _InstallBackend:
    supported = True

    def __init__(self) -> None:
        self.records: dict[
            tuple[str, str], dict[tuple[str, str], str] | object | None
        ] = {}
        self.known_folders = {
            "local_app_data": r"C:\Users\reviewed-user\AppData\Local",
            "program_files": r"C:\Program Files",
        }
        self.calls: list[tuple[str, str, str, tuple[object, ...]]] = []
        self.on_read = None

    def read_string_values(
        self,
        *,
        hive: str,
        view: str,
        key: str,
        selectors: tuple[object, ...],
    ) -> object:
        self.calls.append((hive, view, key, selectors))
        if self.on_read is not None:
            self.on_read(len(self.calls))
        record = self.records.get((hive, key))
        if record is None or not isinstance(record, dict):
            return record
        values = tuple(record[(item.subkey, item.name)] for item in selectors)
        return RegistryStringValues(values)

    def known_folder_path(self, known_folder: str) -> str:
        value = self.known_folders[known_folder]
        if isinstance(value, Exception):
            raise value
        return value


class _FakeAdvapi32:
    def __init__(
        self,
        *,
        values: tuple[str, ...] = (r"C:\Program Files\Python312\python.exe",),
        query_type: int = 1,
        data_type: int | None = None,
        required_override: int | None = None,
        data_size_override: int | None = None,
        query_status: int = 0,
        data_status: int = 0,
        terminate: bool = True,
        open_status: int = 0,
    ) -> None:
        self.values = values
        self.query_type = query_type
        self.data_type = query_type if data_type is None else data_type
        self.required_override = required_override
        self.data_size_override = data_size_override
        self.query_status = query_status
        self.data_status = data_status
        self.terminate = terminate
        self.open_status = open_status
        self.open_calls: list[tuple[int | None, str, int]] = []
        self.get_calls: list[tuple[str, int, bool]] = []
        self.closed: list[int | None] = []
        self._next_handle = 0x1000
        self._completed_reads = 0

    def _value(self) -> str:
        return self.values[min(self._completed_reads, len(self.values) - 1)]

    def RegOpenKeyExW(
        self,
        hive: ctypes.c_void_p,
        key: str,
        _reserved: int,
        access: int,
        result: object,
    ) -> int:
        self.open_calls.append((hive.value, key, access))
        if self.open_status:
            return self.open_status
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p)).contents.value = (
            self._next_handle
        )
        self._next_handle += 1
        return 0

    def RegGetValueW(
        self,
        _handle: ctypes.c_void_p,
        _subkey: object,
        name: str,
        flags: int,
        value_type: object,
        data: object,
        size: object,
    ) -> int:
        query = data is None
        self.get_calls.append((name, flags, query))
        selected = self._value()
        type_pointer = ctypes.cast(value_type, ctypes.POINTER(ctypes.c_uint32))
        type_pointer.contents.value = self.query_type if query else self.data_type
        size_pointer = ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32))
        required = (
            self.required_override
            if self.required_override is not None
            else (len(selected) + (1 if self.terminate else 0))
            * ctypes.sizeof(ctypes.c_wchar)
        )
        if query:
            size_pointer.contents.value = required
            return self.query_status
        status = self.data_status
        if status == 0:
            characters = required // ctypes.sizeof(ctypes.c_wchar)
            pointer = ctypes.cast(data, ctypes.POINTER(ctypes.c_wchar))
            payload = selected + ("\x00" if self.terminate else "")
            for index, character in enumerate(payload[:characters]):
                pointer[index] = character
            size_pointer.contents.value = (
                required if self.data_size_override is None else self.data_size_override
            )
        self._completed_reads += 1
        return status

    def RegCloseKey(self, handle: ctypes.c_void_p) -> int:
        self.closed.append(handle.value)
        return 0


class _FakeShell32:
    def __init__(self, *, status: int = 0, allocate: bool = True) -> None:
        self.status = status
        self.calls: list[tuple[bytes, int, object]] = []
        self.buffer = (
            ctypes.create_unicode_buffer(r"C:\Users\reviewed\AppData\Local")
            if allocate
            else None
        )

    def SHGetKnownFolderPath(
        self,
        guid: object,
        flags: int,
        token: object,
        result: object,
    ) -> int:
        self.calls.append((ctypes.string_at(guid, 16), flags, token))
        if self.buffer is not None:
            ctypes.cast(result, ctypes.POINTER(ctypes.c_wchar_p))[0] = ctypes.cast(
                self.buffer, ctypes.c_wchar_p
            )
        return self.status


class _FakeOle32:
    def __init__(self) -> None:
        self.freed: list[int | None] = []

    def CoTaskMemFree(self, pointer: ctypes.c_void_p) -> None:
        self.freed.append(pointer.value)


def _native_install_backend(
    *,
    advapi32: object | None = None,
    shell32: object | None = None,
    ole32: object | None = None,
) -> NativeWindowsInstallationBackend:
    backend = object.__new__(NativeWindowsInstallationBackend)
    backend._advapi32 = object() if advapi32 is None else advapi32
    backend._shell32 = object() if shell32 is None else shell32
    backend._ole32 = object() if ole32 is None else ole32
    return backend


def _docker_record(path: str = r"C:\Program Files\Docker\Docker") -> dict:
    return {
        ("", "DisplayName"): "Docker Desktop",
        ("", "Publisher"): "Docker Inc.",
        ("", "InstallLocation"): path,
    }


def _podman_record() -> dict:
    return {
        ("", "DisplayName"): "Podman CLI",
        ("", "DisplayVersion"): "6.0.2",
        ("", "Publisher"): "Podman",
    }


def _python_record(path: str) -> dict:
    return {
        ("", "DisplayName"): "Python 3.12.10",
        ("", "SysArchitecture"): "64bit",
        ("", "Version"): "3.12.10",
        ("InstallPath", "ExecutablePath"): path,
    }


def _open_docker(
    backend: _InstallBackend,
    api: _FileApi,
) -> BoundInstallationCandidate:
    return open_package_bound_installation(
        RuntimeProductId.DOCKER_CLI,
        backend=backend,  # type: ignore[arg-type]
        file_api=api,
    )


def test_pe_verifier_derives_unique_product_without_caller_label() -> None:
    evidence, api, _backend = _verify_pe(_docker_pe())

    assert evidence.product_id is RuntimeProductId.DOCKER_CLI
    assert evidence.exact_version == "29.7.2"
    assert evidence.policy_sha256 == _POLICY.content_sha256
    assert evidence.file_sha256 == hashlib.sha256(b"signed-runtime").hexdigest()
    assert evidence.fixed_file_version == (29, 7, 2, 17)
    assert evidence.fixed_product_version == (29, 7, 2, 19)
    assert len(evidence.evidence_sha256) == 64
    assert api.closed
    assert not hasattr(evidence, "path")


def test_pe_verifier_has_no_product_assertion_parameter() -> None:
    api = _FileApi()
    api.add("runtime.exe", final_path=_DOCKER_FINAL)
    backend = _PeBackend(_docker_pe())
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(TypeError):
            verify_package_bound_pe_product(
                bound,
                RuntimeProductId.DOCKER_CLI,  # type: ignore[misc]
                backend=backend,  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            verify_package_bound_pe_product(
                bound,
                product_id=RuntimeProductId.DOCKER_CLI,  # type: ignore[call-arg]
                backend=backend,  # type: ignore[arg-type]
            )
    assert backend.handles == []


@pytest.mark.parametrize(
    "change",
    (
        {"company_name": "docker inc"},
        {"product_name": "Docker Client "},
        {"original_filename": "docker.exe"},
        {"file_version": "29.7.3"},
        {"product_version": "29.7.3"},
    ),
)
def test_every_reviewed_pe_string_field_is_exact(change: dict[str, object]) -> None:
    error = _reject_pe(_docker_pe(**change))
    assert error.code is RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID


def test_fixed_numeric_versions_are_bound_but_not_inferred_from_three_part_policy() -> (
    None
):
    first, _api, _backend = _verify_pe(_docker_pe())
    second, _api, _backend = _verify_pe(
        _docker_pe(
            fixed_file_version=(29, 7, 2, 99),
            fixed_product_version=(29, 7, 2, 101),
        )
    )

    assert first.product_id is second.product_id
    assert first.exact_version == second.exact_version
    assert first.evidence_sha256 != second.evidence_sha256


@pytest.mark.parametrize(
    "change",
    (
        {"fixed_file_version": (30, 7, 2, 17)},
        {"fixed_file_version": (29, 8, 2, 17)},
        {"fixed_file_version": (29, 7, 3, 17)},
        {"fixed_product_version": (30, 7, 2, 19)},
        {"fixed_product_version": (29, 8, 2, 19)},
        {"fixed_product_version": (29, 7, 3, 19)},
    ),
)
def test_fixed_numeric_major_minor_patch_must_match_reviewed_version(
    change: dict[str, object],
) -> None:
    error = _reject_pe(_docker_pe(**change))
    assert error.code is RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID


@pytest.mark.parametrize(
    "final_path",
    (
        r"\\?\C:\approved\docker-compose.exe",
        r"\\?\C:\approved\Docker.exe",
        r"\\?\C:\approved\dоcker.exe",
    ),
)
def test_final_leaf_must_match_exact_reviewed_product(final_path: str) -> None:
    _reject_pe(_docker_pe(), final_path=final_path)


def test_command_version_products_cannot_be_inferred_from_pe_strings() -> None:
    compose_like = _docker_pe(
        product_name="Docker Compose",
        original_filename="docker-compose.exe",
        file_version="5.3.1",
        product_version="5.3.1",
    )
    _reject_pe(
        compose_like,
        final_path=r"\\?\C:\approved\docker-compose.exe",
    )


@pytest.mark.parametrize("supported", (False, None, 1, "yes"))
def test_pe_backend_support_is_exact_boolean(supported: object) -> None:
    backend = _PeBackend(_docker_pe(), supported=supported)
    error = _reject_pe(_docker_pe(), backend=backend)
    assert error.code is RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE
    assert backend.handles == []


def test_pe_backend_failure_and_type_confusion_are_sanitized() -> None:
    error = _reject_pe(
        _docker_pe(), backend=_PeBackend(_docker_pe(), failure=OSError(_SECRET))
    )
    assert error.code is RuntimeIdentityErrorCode.RUNTIME_IDENTITY_INVALID
    _reject_pe(object())


def test_post_pe_inspection_content_change_is_runtime_replaced() -> None:
    api = _FileApi()
    api.add("runtime.exe", final_path=_DOCKER_FINAL)

    def mutate(handle: object) -> None:
        api.states[handle].content = b"SIGNED-RUNTIME"

    backend = _PeBackend(_docker_pe(), mutate=mutate)
    with capture_handle_bound_file(Path("runtime.exe"), api=api) as bound:
        with pytest.raises(RuntimeIdentityVerificationError) as failure:
            verify_package_bound_pe_product(
                bound, backend=backend  # type: ignore[arg-type]
            )
    assert failure.value.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED


def test_pe_evidence_is_immutable_redacted_and_binds_core_fields() -> None:
    evidence, _api, _backend = _verify_pe(_docker_pe())
    assert evidence.file_sha256 not in repr(evidence)
    assert evidence.resource_sha256 not in repr(evidence)
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.file_sha256 = "0" * 64  # type: ignore[misc]
    changed = replace(evidence, resource_sha256="8" * 64)
    assert changed.evidence_sha256 != evidence.evidence_sha256


def test_opens_only_exact_docker_registry_record_and_holds_candidate() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    backend.records[_DOCKER_USER] = None
    api = _FileApi()
    api.add(
        _DOCKER_PATH,
        final_path=_DOCKER_FINAL,
        link_count=2,
    )

    with _open_docker(backend, api) as candidate:
        assert candidate.evidence.product_id is RuntimeProductId.DOCKER_CLI
        assert candidate.evidence.record_ids == ("docker-desktop-system",)
        assert candidate.evidence.policy_sha256 == _POLICY.content_sha256
        assert candidate.bound_file.snapshot.classification.single_link is False
        assert candidate.assert_unchanged() == candidate.bound_file.snapshot
        assert not candidate.closed
        assert "trust='unverified'" in repr(candidate)
        assert _SECRET not in repr(candidate)

    assert candidate.closed
    assert api.opened == [_DOCKER_PATH]
    assert all(call[1] == "registry64" for call in backend.calls)


def test_resolves_user_known_folder_without_environment_or_path_search() -> None:
    backend = _InstallBackend()
    backend.records[_PODMAN] = _podman_record()
    candidate_path = r"C:\Users\reviewed-user\AppData\Local\Programs\Podman\podman.exe"
    api = _FileApi()
    api.add(
        candidate_path,
        final_path=(
            r"\\?\C:\Users\reviewed-user\AppData\Local\Programs\Podman\podman.exe"
        ),
    )

    with open_package_bound_installation(
        RuntimeProductId.PODMAN_CLI,
        backend=backend,  # type: ignore[arg-type]
        file_api=api,
    ) as candidate:
        assert candidate.evidence.record_ids == ("podman-cli-msi-userlocal-6.0.2",)
    assert api.opened == [candidate_path]


def test_resolves_exact_registry_file_and_leaf_for_python() -> None:
    backend = _InstallBackend()
    python_path = r"C:\Program Files\Python312\python.exe"
    backend.records[_PYTHON_SYSTEM] = _python_record(python_path)
    api = _FileApi()
    api.add(
        python_path,
        final_path=r"\\?\C:\Program Files\Python312\python.exe",
    )

    with open_package_bound_installation(
        RuntimeProductId.CPYTHON,
        backend=backend,  # type: ignore[arg-type]
        file_api=api,
    ) as candidate:
        assert candidate.evidence.record_ids == ("pythoncore-3.12-system",)


def test_absent_records_are_not_installed_and_open_nothing() -> None:
    backend = _InstallBackend()
    api = _FileApi()

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)

    assert failure.value.code is RuntimeIdentityErrorCode.INSTALLATION_NOT_FOUND
    assert api.opened == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda record: record.__setitem__(("", "DisplayName"), "docker desktop"),
        lambda record: record.__setitem__(("", "Publisher"), "Docker Inc. "),
        lambda record: record.pop(("", "Publisher")),
        lambda record: record.__setitem__(("", "Publisher"), "Dоcker Inc."),
    ),
)
def test_present_mismatched_or_incomplete_record_poison_result(
    mutation,
) -> None:  # noqa: ANN001
    backend = _InstallBackend()
    record = _docker_record()
    mutation(record)
    backend.records[_DOCKER_SYSTEM] = record
    api = _FileApi()

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)

    assert failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    assert api.opened == []


@pytest.mark.parametrize(
    "install_location",
    (
        r"relative\Docker",
        r"\\server\share\Docker",
        r"%LOCALAPPDATA%\Docker",
        '"C:\\Program Files\\Docker" --argument',
        r"C:\Program Files\Docker\..\attacker",
        r"C:\Program Files\Docker:stream",
        r"C:\Program Files\Docker.",
    ),
)
def test_unsafe_registry_paths_fail_before_file_open(
    install_location: str,
) -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record(install_location)
    api = _FileApi()

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)

    assert failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    assert api.opened == []
    assert install_location not in str(failure.value)
    assert install_location not in repr(failure.value)


def test_registry_and_known_folder_surrogates_are_sanitized_before_hashing() -> None:
    unsafe = "C:\\reviewed\\\ud800"
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record(unsafe)
    api = _FileApi()

    with pytest.raises(RuntimeIdentityVerificationError) as registry_failure:
        _open_docker(backend, api)
    assert (
        registry_failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    )
    assert unsafe not in str(registry_failure.value)
    assert unsafe not in repr(registry_failure.value)
    assert api.opened == []

    backend = _InstallBackend()
    backend.records[_PODMAN] = _podman_record()
    backend.known_folders["local_app_data"] = unsafe
    with pytest.raises(RuntimeIdentityVerificationError) as folder_failure:
        open_package_bound_installation(
            RuntimeProductId.PODMAN_CLI,
            backend=backend,  # type: ignore[arg-type]
            file_api=api,
        )
    assert folder_failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    assert unsafe not in str(folder_failure.value)
    assert unsafe not in repr(folder_failure.value)
    assert api.opened == []


def test_exact_same_candidate_from_two_records_is_collapsed_by_identity() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    backend.records[_DOCKER_USER] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL, identity=11)

    with _open_docker(backend, api) as candidate:
        assert candidate.evidence.record_ids == (
            "docker-desktop-system",
            "docker-desktop-user",
        )
        assert len(api.closed) == 1
    assert len(api.closed) == 2


def test_distinct_system_and_user_candidates_are_ambiguous_and_all_closed() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    user_root = r"C:\Users\reviewed-user\Docker"
    user_path = user_root + r"\resources\bin\docker.exe"
    backend.records[_DOCKER_USER] = _docker_record(user_root)
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL, identity=11)
    api.add(
        user_path,
        final_path=r"\\?\C:\Users\reviewed-user\Docker\resources\bin\docker.exe",
        identity=12,
    )

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)

    assert failure.value.code is RuntimeIdentityErrorCode.INSTALLATION_AMBIGUOUS
    assert len(api.closed) == 2


def test_same_identity_with_distinct_final_name_is_still_ambiguous() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    user_root = r"C:\Users\reviewed-user\Docker"
    user_path = user_root + r"\resources\bin\docker.exe"
    backend.records[_DOCKER_USER] = _docker_record(user_root)
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL, identity=11)
    api.add(
        user_path,
        final_path=r"\\?\C:\Users\reviewed-user\Docker\resources\bin\docker.exe",
        identity=11,
    )

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)
    assert failure.value.code is RuntimeIdentityErrorCode.INSTALLATION_AMBIGUOUS
    assert len(api.closed) == 2


def test_registry_change_between_open_and_return_closes_candidate() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL)

    def mutate(call_count: int) -> None:
        if call_count == 3:
            backend.records[_DOCKER_SYSTEM] = _docker_record(
                r"C:\Program Files\Changed"
            )

    backend.on_read = mutate
    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, api)

    assert failure.value.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED
    assert len(api.closed) == 1


def test_candidate_rechecks_all_records_and_fails_after_record_appearance() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL)

    with _open_docker(backend, api) as candidate:
        backend.records[_DOCKER_USER] = _docker_record(r"C:\Users\reviewed-user\Docker")
        with pytest.raises(RuntimeIdentityVerificationError) as failure:
            candidate.assert_unchanged()
        assert failure.value.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED


def test_wrong_final_leaf_and_open_failure_are_sanitized() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(
        _DOCKER_PATH,
        final_path=r"\\?\C:\approved\podman.exe",
    )
    with pytest.raises(RuntimeIdentityVerificationError) as wrong_leaf:
        _open_docker(backend, api)
    assert wrong_leaf.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    assert len(api.closed) == 1

    api = _FileApi()
    api.specs[_DOCKER_PATH] = OSError(_SECRET)
    with pytest.raises(RuntimeIdentityVerificationError) as open_failure:
        _open_docker(backend, api)
    assert open_failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID
    assert _SECRET not in str(open_failure.value)
    assert _SECRET not in repr(open_failure.value)


@pytest.mark.parametrize("supported", (False, None, 1, "yes"))
def test_install_backend_support_is_exact_boolean(supported: object) -> None:
    backend = _InstallBackend()
    backend.supported = supported  # type: ignore[assignment]
    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _open_docker(backend, _FileApi())
    assert failure.value.code is RuntimeIdentityErrorCode.VERIFICATION_UNAVAILABLE


def test_install_evidence_is_immutable_and_redacted() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL)

    with _open_docker(backend, api) as candidate:
        evidence = candidate.evidence
        assert isinstance(evidence, InstallationCandidateEvidence)
        assert evidence.file_sha256 not in repr(evidence)
        assert evidence.resolution_sha256 not in repr(evidence)
        with pytest.raises(dataclasses.FrozenInstanceError):
            evidence.file_sha256 = "0" * 64  # type: ignore[misc]


def test_closed_candidate_never_reopens_by_name() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL)
    candidate = _open_docker(backend, api)
    candidate.close()

    with pytest.raises(RuntimeIdentityVerificationError) as failure:
        _ = candidate.bound_file
    assert failure.value.code is RuntimeIdentityErrorCode.RUNTIME_REPLACED
    assert api.opened == [_DOCKER_PATH]


def test_source_has_no_generic_discovery_environment_or_process_execution() -> None:
    source = Path(runtime_identity_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.partition(".")[0])
    assert imported_roots.isdisjoint({"shutil", "subprocess", "winreg"})
    for forbidden in (
        "os.environ",
        "os.getenv",
        "Path.cwd",
        "shutil.which",
        "where.exe",
        "App Paths",
        "ExpandEnvironmentStrings",
    ):
        assert forbidden not in source


def test_runtime_identity_slice_is_not_wired_into_live_launcher_modules() -> None:
    for relative in (
        "towerscout_launcher/app.py",
        "towerscout_launcher/discovery.py",
        "towerscout_launcher/repair.py",
        "towerscout_launcher/runtime_execution.py",
    ):
        source = (LAUNCHER_ROOT / relative).read_text(encoding="utf-8")
        assert "runtime_identity" not in source


def test_resolution_api_accepts_only_closed_product_enum_not_path_or_name() -> None:
    backend = _InstallBackend()
    for value in ("docker-cli", Path(_SECRET), None, 1):
        with pytest.raises(RuntimeIdentityVerificationError) as failure:
            open_package_bound_installation(
                value,  # type: ignore[arg-type]
                backend=backend,  # type: ignore[arg-type]
                file_api=_FileApi(),
            )
        assert failure.value.code is RuntimeIdentityErrorCode.INSTALL_RECORD_INVALID


def test_registry_requests_are_exact_policy_order_and_never_enumerated() -> None:
    backend = _InstallBackend()
    backend.records[_DOCKER_SYSTEM] = _docker_record()
    api = _FileApi()
    api.add(_DOCKER_PATH, final_path=_DOCKER_FINAL)

    with _open_docker(backend, api):
        pass

    first_scan = backend.calls[:2]
    assert [(hive, key) for hive, _view, key, _selectors in first_scan] == [
        _DOCKER_SYSTEM,
        _DOCKER_USER,
    ]
    assert all(view == "registry64" for _hive, view, _key, _ in backend.calls)
    assert all(selectors for _hive, _view, _key, selectors in backend.calls)
    assert os.fspath(Path(_DOCKER_PATH)) == api.opened[0]


def test_predefined_registry_hives_are_sign_extended_and_unknown_is_rejected() -> None:
    for hive, raw in (
        ("HKEY_CURRENT_USER", 0x80000001),
        ("HKEY_LOCAL_MACHINE", 0x80000002),
    ):
        expected = ctypes.c_void_p(ctypes.c_int32(raw).value).value
        assert NativeWindowsInstallationBackend._hive_handle(hive).value == expected

    with pytest.raises(ValueError, match="Registry hive is not approved"):
        NativeWindowsInstallationBackend._hive_handle("HKEY_CLASSES_ROOT")


def test_native_registry_reads_exact_64_bit_reg_sz_and_closes_every_key() -> None:
    advapi32 = _FakeAdvapi32()
    backend = _native_install_backend(advapi32=advapi32)
    selectors = (RegistryValueSelector("InstallPath", "ExecutablePath"),)

    result = backend.read_string_values(
        hive="HKEY_LOCAL_MACHINE",
        view="registry64",
        key=r"SOFTWARE\Python\PythonCore\3.12",
        selectors=selectors,
    )

    assert result == RegistryStringValues((r"C:\Program Files\Python312\python.exe",))
    expected_hive = ctypes.c_void_p(ctypes.c_int32(0x80000002).value).value
    assert {call[0] for call in advapi32.open_calls} == {expected_hive}
    assert [call[1] for call in advapi32.open_calls] == [
        r"SOFTWARE\Python\PythonCore\3.12",
        r"SOFTWARE\Python\PythonCore\3.12\InstallPath",
    ] * 2
    assert all(call[2] == 0x0101 for call in advapi32.open_calls)
    assert (
        advapi32.get_calls
        == [
            ("ExecutablePath", 0x30000002, True),
            ("ExecutablePath", 0x30000002, False),
        ]
        * 2
    )
    assert len(advapi32.closed) == len(advapi32.open_calls) == 4

    with pytest.raises(ValueError, match="Registry read request is invalid"):
        backend.read_string_values(
            hive="HKEY_LOCAL_MACHINE",
            view="registry32",
            key=r"SOFTWARE\Python\PythonCore\3.12",
            selectors=selectors,
        )
    assert len(advapi32.open_calls) == 4


def test_native_registry_distinguishes_absent_record_from_access_failure() -> None:
    selectors = (RegistryValueSelector("", "DisplayName"),)
    absent_api = _FakeAdvapi32(open_status=2)
    absent = _native_install_backend(advapi32=absent_api)
    assert (
        absent.read_string_values(
            hive="HKEY_CURRENT_USER",
            view="registry64",
            key=r"SOFTWARE\Reviewed",
            selectors=selectors,
        )
        is None
    )
    assert len(absent_api.open_calls) == 2
    assert absent_api.closed == []

    denied_api = _FakeAdvapi32(open_status=5)
    denied = _native_install_backend(advapi32=denied_api)
    with pytest.raises(OSError) as failure:
        denied.read_string_values(
            hive="HKEY_CURRENT_USER",
            view="registry64",
            key=r"SOFTWARE\Reviewed",
            selectors=selectors,
        )
    assert _SECRET not in str(failure.value)
    assert len(denied_api.open_calls) == 1
    assert denied_api.closed == []


@pytest.mark.parametrize(
    "configuration",
    (
        {"query_type": 2},
        {"required_override": 3},
        {"required_override": (32_767 + 2) * ctypes.sizeof(ctypes.c_wchar)},
        {"values": ("AB",), "terminate": False},
        {"values": ("A\x00B",)},
        {"query_status": 5},
        {"data_status": 5},
        {"data_type": 2},
        {"data_size_override": 2},
        {"values": ("first", "other")},
    ),
)
def test_native_registry_rejects_type_buffer_status_and_value_races(
    configuration: dict[str, object],
) -> None:
    advapi32 = _FakeAdvapi32(**configuration)  # type: ignore[arg-type]
    backend = _native_install_backend(advapi32=advapi32)

    with pytest.raises((OSError, RuntimeError, ValueError)) as failure:
        backend.read_string_values(
            hive="HKEY_CURRENT_USER",
            view="registry64",
            key=r"SOFTWARE\Reviewed",
            selectors=(RegistryValueSelector("InstallPath", "ExecutablePath"),),
        )

    assert _SECRET not in str(failure.value)
    assert len(advapi32.closed) == len(advapi32.open_calls)


@pytest.mark.parametrize(
    ("known_folder", "guid_bytes"),
    (
        (
            "local_app_data",
            bytes.fromhex("8527b3f1ba6fcf4f9d557b8e7f157091"),
        ),
        (
            "program_files",
            bytes.fromhex("7793806df06a4b448957a3773f02200e"),
        ),
    ),
)
def test_native_known_folder_uses_exact_guid_current_token_and_frees_result(
    known_folder: str,
    guid_bytes: bytes,
) -> None:
    shell32 = _FakeShell32()
    ole32 = _FakeOle32()
    backend = _native_install_backend(shell32=shell32, ole32=ole32)

    assert backend.known_folder_path(known_folder) == (
        r"C:\Users\reviewed\AppData\Local"
    )
    assert shell32.calls == [(guid_bytes, 0, None)]
    assert shell32.buffer is not None
    assert ole32.freed == [ctypes.addressof(shell32.buffer)]


def test_native_known_folder_frees_partial_failure_and_rejects_unknown_id() -> None:
    shell32 = _FakeShell32(status=-2147467259)
    ole32 = _FakeOle32()
    backend = _native_install_backend(shell32=shell32, ole32=ole32)

    with pytest.raises(OSError):
        backend.known_folder_path("local_app_data")
    assert shell32.buffer is not None
    assert ole32.freed == [ctypes.addressof(shell32.buffer)]

    with pytest.raises(ValueError, match="Known Folder request is invalid"):
        backend.known_folder_path("desktop")
    assert len(shell32.calls) == 1
