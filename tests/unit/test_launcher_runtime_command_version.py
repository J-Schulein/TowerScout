from __future__ import annotations

import ast
import ctypes
import dataclasses
import hashlib
import inspect
import subprocess
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

import towerscout_launcher.runtime_command_version as command_module  # noqa: E402
import towerscout_launcher.runtime_command_native as native_module  # noqa: E402
from towerscout_launcher.authenticode import (  # noqa: E402
    NativeAuthenticodeFacts,
    NativeTrustStatus,
    SignerCertificateFacts,
    TimestampFacts,
    TimestampForm,
)
from towerscout_launcher.runtime_command_version import (  # noqa: E402
    BoundCommandRuntimeEvidence,
    CommandExecutionError,
    CommandExecutionErrorCode,
    CommandProcessResult,
    CombinedCommandRuntimeEvidence,
    RuntimeCommandVerificationError,
    RuntimeCommandVerificationErrorCode,
    open_package_bound_command_runtime_evidence,
)
from towerscout_launcher.runtime_policy import (  # noqa: E402
    LocationKind,
    RuntimeProductId,
    SignatureForm,
    load_package_bound_runtime_policy,
)
from towerscout_launcher.windows_security import NativeFileFacts  # noqa: E402

_NOW = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
_POLICY = load_package_bound_runtime_policy()
_DOCKER_BASE = r"C:\Program Files\Docker\Docker"
_COMPOSE_PATH = _DOCKER_BASE + r"\resources\bin\docker-compose.exe"
_COMPOSE_FINAL = r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker-compose.exe"
_PODMAN_BASE = r"C:\Users\reviewed-user\AppData\Local"
_PODMAN_PATH = _PODMAN_BASE + r"\Programs\Podman\podman.exe"
_PODMAN_FINAL = r"\\?\C:\Users\reviewed-user\AppData\Local\Programs\Podman\podman.exe"
_WINDOWS_DIRECTORY = r"C:\Windows"
_SYSTEM_DIRECTORY = r"C:\Windows\System32"


def _product(product_id: RuntimeProductId):  # noqa: ANN202
    return next(item for item in _POLICY.products if item.product_id is product_id)


def _native_facts(final_path: str, content: bytes) -> NativeFileFacts:
    return NativeFileFacts(
        final_path=final_path,
        volume_serial=0x0102030405060708,
        file_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        attributes=0x80,
        link_count=2,
        size=len(content),
        creation_time=100,
        last_write_time=200,
        drive_type=3,
        file_type=1,
        reparse_tag=0,
    )


class _FileApi:
    supported = True

    def __init__(self, *, final_path: str, content: bytes = b"signed-runtime") -> None:
        self.content = content
        self.facts = _native_facts(final_path, content)
        self.handle = object()
        self.cursor = 0
        self.opened: list[str] = []
        self.close_count = 0

    def open_file_for_identity(self, path: str) -> object:
        self.opened.append(path)
        return self.handle

    def query_file(self, handle: object) -> NativeFileFacts:
        assert handle is self.handle
        return replace(self.facts, size=len(self.content))

    def rewind_file(self, handle: object) -> None:
        assert handle is self.handle
        self.cursor = 0

    def read_file(self, handle: object, maximum: int) -> bytes:
        assert handle is self.handle
        chunk = self.content[self.cursor : self.cursor + maximum]
        self.cursor += len(chunk)
        return chunk

    def close_handle(self, handle: object) -> None:
        assert handle is self.handle
        self.close_count += 1


class _InstallBackend:
    supported = True

    def __init__(self, product_id: RuntimeProductId) -> None:
        self.records: dict[
            tuple[str, str], dict[tuple[str, str], str] | object | None
        ] = {}
        self.known_folders = {
            "local_app_data": _PODMAN_BASE,
            "program_files": r"C:\Program Files",
        }
        product = _product(product_id)
        record = product.install_records[0]
        values = {
            (item.subkey, item.name): item.equals
            for item in record.registry.required_values
        }
        if record.location.kind is LocationKind.REGISTRY_DIRECTORY_RELATIVE:
            values[(record.location.value_subkey, record.location.value_name)] = (
                _DOCKER_BASE
            )
        self.records[(record.registry.hive, record.registry.key)] = values
        self.calls = 0

    def read_string_values(
        self,
        *,
        hive: str,
        view: str,
        key: str,
        selectors: tuple[object, ...],
    ) -> object:
        from towerscout_launcher.runtime_identity import RegistryStringValues

        del view
        self.calls += 1
        record = self.records.get((hive, key))
        if record is None or not isinstance(record, dict):
            return record
        return RegistryStringValues(
            tuple(record[(item.subkey, item.name)] for item in selectors)
        )

    def known_folder_path(self, known_folder: str) -> str:
        return self.known_folders[known_folder]


class _AuthenticodeBackend:
    supported = True

    def __init__(self, facts: NativeAuthenticodeFacts) -> None:
        self.facts = facts
        self.handles: list[object] = []

    def inspect_open_file(self, *, handle: object, snapshot: object) -> object:
        del snapshot
        self.handles.append(handle)
        return self.facts


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW


class _CommandBackend:
    supported = True

    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[object] = []
        self.on_execute = None

    def windows_directory(self) -> str:
        return _WINDOWS_DIRECTORY

    def system_directory(self) -> str:
        return _SYSTEM_DIRECTORY

    def execute(self, request: object) -> object:
        self.requests.append(request)
        if self.on_execute is not None:
            self.on_execute()
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _signer(product_id: RuntimeProductId) -> SignerCertificateFacts:
    approved = _product(product_id).signers[0]
    return SignerCertificateFacts(
        certificate_sha256=approved.certificate_sha256,
        subject_common_name=approved.subject_common_name,
        subject_organization=approved.subject_organization,
        issuer_common_name=approved.issuer_common_name,
        serial_number=approved.serial_number,
        not_before_utc=approved.not_before_utc,
        not_after_utc=approved.not_after_utc,
        public_key_algorithm=approved.public_key_algorithm,
        public_key_bits=approved.minimum_public_key_bits,
        code_signing_eku=True,
    )


def _trusted_timestamp() -> TimestampFacts:
    return TimestampFacts(
        form=TimestampForm.RFC3161,
        token_sha256="3" * 64,
        signing_time_utc="2025-04-09T12:00:00Z",
        digest_algorithm="sha256",
        signature_algorithm="rsa_pkcs1v15",
        primary_signature_valid=True,
        chain_status=NativeTrustStatus.TRUSTED,
        chain_sha256="4" * 64,
    )


def _authenticode_facts(product_id: RuntimeProductId) -> NativeAuthenticodeFacts:
    timestamps = (
        (_trusted_timestamp(),) if product_id is RuntimeProductId.PODMAN_CLI else ()
    )
    return NativeAuthenticodeFacts(
        signature_form=SignatureForm.EMBEDDED_AUTHENTICODE,
        certificate_table_entry_count=1,
        primary_signer_count=1,
        secondary_signature_count=0,
        nested_signature_count=0,
        legacy_countersignature_count=0,
        embedded_signature_sha256="5" * 64,
        file_digest_algorithm="sha256",
        signer_signature_algorithm="rsa_pkcs1v15",
        wintrust_status=0,
        signer_chain_status=NativeTrustStatus.TRUSTED,
        signer_chain_sha256="6" * 64,
        signer=_signer(product_id),
        timestamps=timestamps,
    )


def _result(stdout: bytes) -> CommandProcessResult:
    return CommandProcessResult(
        stdout=stdout,
        stderr=b"",
        exit_code=0,
        stdin_closed=True,
        stdout_streamed=True,
        stderr_streamed=True,
        process_tree_contained=True,
        process_tree_empty=True,
    )


def _open(
    product_id: RuntimeProductId,
    stdout: bytes,
    *,
    result: object | None = None,
    auth_product: RuntimeProductId | None = None,
    final_path: str | None = None,
) -> tuple[
    BoundCommandRuntimeEvidence,
    _InstallBackend,
    _FileApi,
    _AuthenticodeBackend,
    _CommandBackend,
]:
    is_compose = product_id is RuntimeProductId.DOCKER_COMPOSE
    installation = _InstallBackend(product_id)
    api = _FileApi(
        final_path=final_path or (_COMPOSE_FINAL if is_compose else _PODMAN_FINAL)
    )
    authenticode = _AuthenticodeBackend(_authenticode_facts(auth_product or product_id))
    command = _CommandBackend(_result(stdout) if result is None else result)
    owner = open_package_bound_command_runtime_evidence(
        product_id,
        installation_backend=installation,  # type: ignore[arg-type]
        file_api=api,
        authenticode_backend=authenticode,  # type: ignore[arg-type]
        command_backend=command,  # type: ignore[arg-type]
        clock=_Clock(),
    )
    return owner, installation, api, authenticode, command


def test_compose_command_evidence_is_bound_to_one_retained_runtime() -> None:
    owner, installation, api, authenticode, command = _open(
        RuntimeProductId.DOCKER_COMPOSE, b"5.3.1\r\n"
    )

    assert isinstance(owner, BoundCommandRuntimeEvidence)
    assert not owner.closed
    assert api.opened == [_COMPOSE_PATH]
    assert api.close_count == 0
    assert authenticode.handles == [api.handle]
    assert installation.calls >= 6
    assert len(command.requests) == 1

    request = command.requests[0]
    assert request.executable_path == PureWindowsPath(_COMPOSE_FINAL)
    assert request.arguments == ("version", "--short")
    assert request.environment == (
        ("SystemRoot", _WINDOWS_DIRECTORY),
        ("WINDIR", _WINDOWS_DIRECTORY),
    )
    assert request.working_directory == PureWindowsPath(_SYSTEM_DIRECTORY)
    assert request.stdin_closed is True
    assert request.shell is False
    assert request.stdout_limit_bytes == 64 * 1024
    assert request.stderr_limit_bytes == 16 * 1024
    assert request.timeout_ms == 15_000

    evidence = owner.evidence
    assert isinstance(evidence, CombinedCommandRuntimeEvidence)
    assert evidence.product_id is RuntimeProductId.DOCKER_COMPOSE
    assert evidence.exact_version == "5.3.1"
    assert evidence.policy_sha256 == _POLICY.content_sha256
    assert evidence.file_sha256 == hashlib.sha256(b"signed-runtime").hexdigest()
    assert evidence.authenticode.signer_policy_product_ids == (
        RuntimeProductId.DOCKER_CLI,
        RuntimeProductId.DOCKER_COMPOSE,
    )
    assert evidence.installation.file_identity == evidence.command.file_identity
    assert evidence.command.file_identity == evidence.authenticode.file_identity
    assert evidence.command.arguments == ("version", "--short")
    assert evidence.command.output_sha256 == hashlib.sha256(b"5.3.1\r\n").hexdigest()

    assert owner.assert_unchanged() is evidence
    owner.close()
    owner.close()
    assert owner.closed
    assert api.close_count == 1


def test_podman_json_pointer_version_uses_timestamped_signer() -> None:
    owner, _installation, api, _authenticode, command = _open(
        RuntimeProductId.PODMAN_CLI,
        b'{"Client":{"APIVersion":"5.6.0","Version":"6.0.2"}}\n',
    )
    with owner:
        assert owner.evidence.product_id is RuntimeProductId.PODMAN_CLI
        assert owner.evidence.exact_version == "6.0.2"
        assert owner.evidence.command.arguments == (
            "version",
            "--format",
            "json",
        )
        assert owner.evidence.authenticode.timestamp_time_utc == (
            "2025-04-09T12:00:00Z"
        )
        assert command.requests[0].executable_path == PureWindowsPath(_PODMAN_FINAL)
        assert api.opened == [_PODMAN_PATH]
    assert api.close_count == 1


@pytest.mark.parametrize(
    "product_id",
    (RuntimeProductId.DOCKER_CLI, RuntimeProductId.CPYTHON),
)
def test_pe_version_products_are_rejected_before_discovery_or_execution(
    product_id: RuntimeProductId,
) -> None:
    installation = _InstallBackend(product_id)
    api = _FileApi(final_path=_COMPOSE_FINAL)
    command = _CommandBackend(_result(b"ignored"))

    with pytest.raises(RuntimeCommandVerificationError) as captured:
        open_package_bound_command_runtime_evidence(
            product_id,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.DOCKER_COMPOSE)
            ),  # type: ignore[arg-type]
            command_backend=command,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert (
        captured.value.code
        is RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE
    )
    assert installation.calls == 0
    assert api.opened == []
    assert command.requests == []


@pytest.mark.parametrize(
    "bad_output",
    (
        b"5.3.0\n",
        b" 5.3.1\n",
        b"5.3.1 \n",
        b"5.3.1\n\n",
        b"v5.3.1\n",
        b"\xef\xbb\xbf5.3.1\n",
        b"5.3.1\x00\n",
        b"\xff",
    ),
)
def test_compose_text_parser_rejects_non_exact_output(bad_output: bytes) -> None:
    with pytest.raises(RuntimeCommandVerificationError) as captured:
        _open(RuntimeProductId.DOCKER_COMPOSE, bad_output)
    assert (
        captured.value.code
        is RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    )


@pytest.mark.parametrize(
    "bad_output",
    (
        b'{"Client":{"Version":"6.0.1"}}\n',
        b'{"Client":{"version":"6.0.2"}}\n',
        b'{"client":{"Version":"6.0.2"}}\n',
        b'{"Client":{"Version":"6.0.2","Version":"6.0.2"}}\n',
        b'{"Client":{"Version":6.002}}\n',
        b'{"Client":{"Version":"6.0.2"}} trailing\n',
        b' {"Client":{"Version":"6.0.2"}}\n',
        b'{"Client":{"Version":"6.0.2"}}\n\n',
        b"\xef\xbb\xbf{}",
        b"\xff",
    ),
)
def test_podman_json_parser_fails_closed(bad_output: bytes) -> None:
    with pytest.raises(RuntimeCommandVerificationError) as captured:
        _open(RuntimeProductId.PODMAN_CLI, bad_output)
    assert (
        captured.value.code
        is RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    )


@pytest.mark.parametrize(
    ("result", "code"),
    (
        (
            CommandProcessResult(
                stdout=b"5.3.1\n",
                stderr=b"warning",
                exit_code=0,
                stdin_closed=True,
                stdout_streamed=True,
                stderr_streamed=True,
                process_tree_contained=True,
                process_tree_empty=True,
            ),
            RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID,
        ),
        (
            CommandProcessResult(
                stdout=b"5.3.1\n",
                stderr=b"",
                exit_code=1,
                stdin_closed=True,
                stdout_streamed=True,
                stderr_streamed=True,
                process_tree_contained=True,
                process_tree_empty=True,
            ),
            RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID,
        ),
        (
            CommandExecutionError(CommandExecutionErrorCode.OUTPUT_LIMIT),
            RuntimeCommandVerificationErrorCode.RUNTIME_OUTPUT_LIMIT,
        ),
        (
            CommandExecutionError(CommandExecutionErrorCode.TIMEOUT),
            RuntimeCommandVerificationErrorCode.RUNTIME_TIMEOUT,
        ),
        (
            CommandExecutionError(CommandExecutionErrorCode.CONTAINMENT_FAILED),
            RuntimeCommandVerificationErrorCode.VERIFICATION_UNAVAILABLE,
        ),
    ),
)
def test_execution_failures_are_sanitized_and_close_the_handle(
    result: object,
    code: RuntimeCommandVerificationErrorCode,
) -> None:
    installation = _InstallBackend(RuntimeProductId.DOCKER_COMPOSE)
    api = _FileApi(final_path=_COMPOSE_FINAL)
    command = _CommandBackend(result)

    with pytest.raises(RuntimeCommandVerificationError) as captured:
        open_package_bound_command_runtime_evidence(
            RuntimeProductId.DOCKER_COMPOSE,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.DOCKER_COMPOSE)
            ),  # type: ignore[arg-type]
            command_backend=command,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert captured.value.code is code
    assert _COMPOSE_PATH not in str(captured.value)
    assert _COMPOSE_FINAL not in repr(captured.value)
    assert api.close_count == 1


def test_runtime_or_installation_change_during_command_fails_closed() -> None:
    installation = _InstallBackend(RuntimeProductId.DOCKER_COMPOSE)
    api = _FileApi(final_path=_COMPOSE_FINAL)
    command = _CommandBackend(_result(b"5.3.1\n"))
    command.on_execute = lambda: setattr(api, "content", b"replaced-runtime")

    with pytest.raises(RuntimeCommandVerificationError) as captured:
        open_package_bound_command_runtime_evidence(
            RuntimeProductId.DOCKER_COMPOSE,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.DOCKER_COMPOSE)
            ),  # type: ignore[arg-type]
            command_backend=command,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert captured.value.code is RuntimeCommandVerificationErrorCode.RUNTIME_REPLACED
    assert api.close_count == 1


def test_command_interruption_propagates_only_after_handle_cleanup() -> None:
    installation = _InstallBackend(RuntimeProductId.DOCKER_COMPOSE)
    api = _FileApi(final_path=_COMPOSE_FINAL)
    command = _CommandBackend(KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        open_package_bound_command_runtime_evidence(
            RuntimeProductId.DOCKER_COMPOSE,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.DOCKER_COMPOSE)
            ),  # type: ignore[arg-type]
            command_backend=command,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert len(command.requests) == 1
    assert api.close_count == 1


@pytest.mark.parametrize(
    "final_path",
    (
        r"\\server\share\docker-compose.exe",
        r"C:relative\docker-compose.exe",
        r"\\?\C:\Program Files\Docker\Docker\resources\bin\DOCKER-COMPOSE.EXE",
        r"\\?\C:\Program Files\Docker\Docker\resources\bin\docker-compose.exe.",
    ),
)
def test_exact_local_case_preserving_final_path_is_required(final_path: str) -> None:
    with pytest.raises(RuntimeCommandVerificationError) as captured:
        _open(
            RuntimeProductId.DOCKER_COMPOSE,
            b"5.3.1\n",
            final_path=final_path,
        )
    assert (
        captured.value.code
        is RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    )


def test_wrong_signer_overlap_prevents_command_execution() -> None:
    installation = _InstallBackend(RuntimeProductId.DOCKER_COMPOSE)
    api = _FileApi(final_path=_COMPOSE_FINAL)
    command = _CommandBackend(_result(b"5.3.1\n"))

    with pytest.raises(RuntimeCommandVerificationError) as captured:
        open_package_bound_command_runtime_evidence(
            RuntimeProductId.DOCKER_COMPOSE,
            installation_backend=installation,  # type: ignore[arg-type]
            file_api=api,
            authenticode_backend=_AuthenticodeBackend(
                _authenticode_facts(RuntimeProductId.PODMAN_CLI)
            ),  # type: ignore[arg-type]
            command_backend=command,  # type: ignore[arg-type]
            clock=_Clock(),
        )

    assert (
        captured.value.code
        is RuntimeCommandVerificationErrorCode.RUNTIME_IDENTITY_INVALID
    )
    assert command.requests == []
    assert api.close_count == 1


def test_models_are_frozen_slotted_and_redact_paths_and_output() -> None:
    owner, _installation, _api, _authenticode, command = _open(
        RuntimeProductId.DOCKER_COMPOSE, b"5.3.1\n"
    )
    evidence = owner.evidence
    request = command.requests[0]

    assert dataclasses.is_dataclass(evidence)
    assert dataclasses.is_dataclass(evidence.command)
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.command.exact_version = "0.0.0"  # type: ignore[misc]
    for rendered in (
        repr(evidence),
        repr(evidence.command),
        repr(request),
        repr(owner),
    ):
        assert _COMPOSE_PATH not in rendered
        assert _COMPOSE_FINAL not in rendered
        assert "5.3.1\n" not in rendered
    owner.close()


def test_combiner_rejects_policy_identity_hash_and_signer_mismatch() -> None:
    owner, _installation, _api, _authenticode, _command = _open(
        RuntimeProductId.DOCKER_COMPOSE, b"5.3.1\n"
    )
    evidence = owner.evidence
    owner.close()

    replacements = (
        replace(
            evidence.command,
            policy_sha256="a" * 64,
        ),
        replace(
            evidence.command,
            file_sha256="b" * 64,
        ),
        replace(
            evidence.command,
            product_id=RuntimeProductId.PODMAN_CLI,
        ),
    )
    for command_evidence in replacements:
        with pytest.raises(ValueError):
            CombinedCommandRuntimeEvidence(
                evidence.installation,
                evidence.authenticode,
                command_evidence,
            )


def test_command_evidence_module_is_unwired_from_live_launcher_paths() -> None:
    forbidden = (
        LAUNCHER_ROOT / "towerscout_launcher" / "app.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "discovery.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "repair.py",
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_execution.py",
    )
    for path in forbidden:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert not any("runtime_command_version" in item for item in imports)

    source = inspect.getsource(command_module)
    assert "subprocess.run" not in source
    assert "subprocess.Popen" not in source
    assert "os.environ" not in source


class _NativeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def wait(self, seconds: float) -> None:
        self.value += seconds


class _NativeProcessApi:
    supported = True

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        active: int = 0,
        wait_advance: float = 0.001,
        terminate_clears: bool = True,
        block_stdout: bool = False,
    ) -> None:
        self.streams = {3: bytearray(stdout), 4: bytearray(stderr)}
        self.active = active
        self.wait_advance = wait_advance
        self.terminate_clears = terminate_clears
        self.block_stdout = block_stdout
        self.stdout_read_entered = threading.Event()
        self.stdout_release = threading.Event()
        self.clock: _NativeClock | None = None
        self.requests: list[object] = []
        self.terminate_count = 0
        self.close_count = 0

    def windows_directory(self) -> str:
        return _WINDOWS_DIRECTORY

    def system_directory(self) -> str:
        return _SYSTEM_DIRECTORY

    def start(self, request: object) -> object:
        self.requests.append(request)
        return native_module._NativeProcess(1, 2, 3, 4)

    def read_file(self, handle: int, maximum: int) -> bytes:
        if handle == 3 and self.block_stdout:
            self.stdout_read_entered.set()
            self.stdout_release.wait(2.0)
        stream = self.streams[handle]
        result = bytes(stream[:maximum])
        del stream[:maximum]
        return result

    def wait_process(self, process: int, milliseconds: int) -> bool:
        del process, milliseconds
        assert self.clock is not None
        self.clock.value += self.wait_advance
        threading.Event().wait(0)
        return self.active == 0

    def exit_code(self, process: int) -> int:
        del process
        return 0

    def active_processes(self, job: int) -> int:
        del job
        return self.active

    def terminate_job(self, job: int) -> None:
        del job
        self.terminate_count += 1
        if self.terminate_clears:
            self.active = 0
        self.stdout_release.set()

    def close_process(self, process: object) -> None:
        del process
        self.close_count += 1


def _native_handle_value(value: object) -> int:
    if isinstance(value, int):
        return value
    return int(getattr(value, "value"))


class _Kernel32ProcessShim:
    def __init__(
        self,
        *,
        assign_succeeds: bool = True,
        resume_result: int = 0,
        terminate_process_succeeds: bool = True,
        terminate_job_succeeds: bool = True,
        wait_result: int = native_module._WAIT_OBJECT_0,
        returned_size: int | None = None,
        process_handle: int = 701,
        thread_handle: int = 702,
    ) -> None:
        self.assign_succeeds = assign_succeeds
        self.resume_result = resume_result
        self.terminate_process_succeeds = terminate_process_succeeds
        self.terminate_job_succeeds = terminate_job_succeeds
        self.wait_result = wait_result
        self.returned_size = returned_size
        self.process_handle = process_handle
        self.thread_handle = thread_handle
        self.job_handle = 601
        self.pipe_pairs = [(101, 102), (103, 104), (105, 106)]
        self.active = 1
        self.last_error = 0
        self.calls: list[str] = []
        self.closed: list[int] = []
        self.noninheritable: list[tuple[int, int, int]] = []
        self.inherited_handles: tuple[int, ...] = ()
        self.job_limit_flags = 0
        self.application_name = ""
        self.command_line = ""
        self.environment_block = ""
        self.current_directory = ""
        self.creation_flags = 0
        self.inherit_handles = False
        self.startup_std_handles: tuple[int, int, int] = ()

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def get_last_error(self) -> int:
        return self.last_error

    def CreatePipe(
        self,
        read_pointer: object,
        write_pointer: object,
        _attributes: object,
        _size: int,
    ) -> bool:
        self.calls.append("CreatePipe")
        read, write = self.pipe_pairs.pop(0)
        ctypes.cast(
            read_pointer, ctypes.POINTER(native_module._HANDLE)
        ).contents.value = read
        ctypes.cast(
            write_pointer, ctypes.POINTER(native_module._HANDLE)
        ).contents.value = write
        return True

    def SetHandleInformation(self, handle: object, mask: int, flags: int) -> bool:
        self.calls.append("SetHandleInformation")
        self.noninheritable.append((_native_handle_value(handle), mask, flags))
        return True

    def CreateJobObjectW(self, _attributes: object, _name: object) -> int:
        self.calls.append("CreateJobObjectW")
        return self.job_handle

    def SetInformationJobObject(
        self,
        _job: object,
        information_class: int,
        information: object,
        size: int,
    ) -> bool:
        self.calls.append("SetInformationJobObject")
        assert information_class == native_module._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION
        assert size == ctypes.sizeof(
            native_module._JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        )
        limits = ctypes.cast(
            information,
            ctypes.POINTER(native_module._JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
        ).contents
        self.job_limit_flags = int(limits.BasicLimitInformation.LimitFlags)
        return True

    def InitializeProcThreadAttributeList(
        self,
        attribute_list: object,
        count: int,
        flags: int,
        size_pointer: object,
    ) -> bool:
        self.calls.append("InitializeProcThreadAttributeList")
        assert count == 1
        assert flags == 0
        if attribute_list is None:
            ctypes.cast(
                size_pointer, ctypes.POINTER(native_module._SIZE_T)
            ).contents.value = 64
            self.last_error = native_module._ERROR_INSUFFICIENT_BUFFER
            return False
        return True

    def UpdateProcThreadAttribute(
        self,
        _attribute_list: object,
        flags: int,
        attribute: int,
        value: object,
        size: int,
        _previous: object,
        _returned: object,
    ) -> bool:
        self.calls.append("UpdateProcThreadAttribute")
        assert flags == 0
        assert attribute == native_module.PROC_THREAD_ATTRIBUTE_HANDLE_LIST
        assert size == 3 * ctypes.sizeof(native_module._HANDLE)
        handle_array = ctypes.cast(
            value, ctypes.POINTER(native_module._HANDLE * 3)
        ).contents
        self.inherited_handles = tuple(
            _native_handle_value(handle) for handle in handle_array
        )
        return True

    def DeleteProcThreadAttributeList(self, _attribute_list: object) -> None:
        self.calls.append("DeleteProcThreadAttributeList")

    def CreateProcessW(
        self,
        application_name: str,
        command_line: object,
        _process_attributes: object,
        _thread_attributes: object,
        inherit_handles: bool,
        creation_flags: int,
        environment: object,
        current_directory: str,
        startup_pointer: object,
        process_information_pointer: object,
    ) -> bool:
        self.calls.append("CreateProcessW")
        self.application_name = application_name
        self.command_line = command_line.value
        self.environment_block = environment[:]
        self.current_directory = current_directory
        self.creation_flags = creation_flags
        self.inherit_handles = bool(inherit_handles)
        startup = ctypes.cast(
            startup_pointer, ctypes.POINTER(native_module._STARTUPINFOEXW)
        ).contents
        self.startup_std_handles = (
            _native_handle_value(startup.StartupInfo.hStdInput),
            _native_handle_value(startup.StartupInfo.hStdOutput),
            _native_handle_value(startup.StartupInfo.hStdError),
        )
        process_information = ctypes.cast(
            process_information_pointer,
            ctypes.POINTER(native_module._PROCESS_INFORMATION),
        ).contents
        process_information.hProcess = self.process_handle
        process_information.hThread = self.thread_handle
        process_information.dwProcessId = 703
        process_information.dwThreadId = 704
        return True

    def AssignProcessToJobObject(self, _job: object, _process: object) -> bool:
        self.calls.append("AssignProcessToJobObject")
        return self.assign_succeeds

    def ResumeThread(self, _thread: object) -> int:
        self.calls.append("ResumeThread")
        return self.resume_result

    def TerminateProcess(self, _process: object, _exit_code: int) -> bool:
        self.calls.append("TerminateProcess")
        if self.terminate_process_succeeds:
            self.active = 0
        return self.terminate_process_succeeds

    def TerminateJobObject(self, _job: object, _exit_code: int) -> bool:
        self.calls.append("TerminateJobObject")
        if self.terminate_job_succeeds:
            self.active = 0
        return self.terminate_job_succeeds

    def WaitForSingleObject(self, _process: object, _milliseconds: int) -> int:
        self.calls.append("WaitForSingleObject")
        return self.wait_result

    def QueryInformationJobObject(
        self,
        _job: object,
        information_class: int,
        information: object,
        size: int,
        returned_pointer: object,
    ) -> bool:
        self.calls.append("QueryInformationJobObject")
        assert (
            information_class == native_module._JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION
        )
        assert size == ctypes.sizeof(
            native_module._JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        )
        accounting = ctypes.cast(
            information,
            ctypes.POINTER(native_module._JOBOBJECT_BASIC_ACCOUNTING_INFORMATION),
        ).contents
        accounting.ActiveProcesses = self.active
        returned = size if self.returned_size is None else self.returned_size
        ctypes.cast(
            returned_pointer, ctypes.POINTER(native_module._DWORD)
        ).contents.value = returned
        return True

    def CloseHandle(self, handle: object) -> bool:
        self.calls.append("CloseHandle")
        self.closed.append(_native_handle_value(handle))
        return True


def _shim_native_api(
    shim: _Kernel32ProcessShim,
    monkeypatch: pytest.MonkeyPatch,
) -> object:
    monkeypatch.setattr(
        native_module.ctypes, "set_last_error", shim.set_last_error, raising=False
    )
    monkeypatch.setattr(
        native_module.ctypes, "get_last_error", shim.get_last_error, raising=False
    )
    api = object.__new__(native_module._NativeWindowsProcessApi)
    api._kernel32 = shim
    return api


def _native_request() -> object:
    return command_module.CommandProcessRequest(
        executable_path=PureWindowsPath(_COMPOSE_FINAL),
        arguments=("version", "--short"),
        environment=(
            ("SystemRoot", _WINDOWS_DIRECTORY),
            ("WINDIR", _WINDOWS_DIRECTORY),
        ),
        working_directory=PureWindowsPath(_SYSTEM_DIRECTORY),
        timeout_ms=15_000,
        stdout_limit_bytes=64 * 1024,
        stderr_limit_bytes=16 * 1024,
    )


def _native_backend(api: _NativeProcessApi):
    clock = _NativeClock()
    api.clock = clock
    return native_module.NativeWindowsCommandVersionBackend(
        api=api,  # type: ignore[arg-type]
        clock=clock,
    )


def test_native_process_api_uses_exact_containment_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = _Kernel32ProcessShim()
    api = _shim_native_api(shim, monkeypatch)
    request = _native_request()

    process = api.start(request)  # type: ignore[attr-defined]

    assert process == native_module._NativeProcess(601, 701, 101, 103)
    assert shim.noninheritable == [
        (101, native_module.HANDLE_FLAG_INHERIT, 0),
        (103, native_module.HANDLE_FLAG_INHERIT, 0),
        (106, native_module.HANDLE_FLAG_INHERIT, 0),
    ]
    assert shim.inherited_handles == (105, 102, 104)
    assert shim.startup_std_handles == (105, 102, 104)
    assert shim.job_limit_flags == native_module.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert shim.application_name == _COMPOSE_FINAL
    assert shim.command_line == subprocess.list2cmdline(
        (_COMPOSE_FINAL, "version", "--short")
    )
    assert shim.environment_block == (
        "SystemRoot=C:\\Windows\x00WINDIR=C:\\Windows\x00\x00"
    )
    assert shim.current_directory == _SYSTEM_DIRECTORY
    assert shim.inherit_handles is True
    assert shim.creation_flags == (
        native_module.CREATE_SUSPENDED
        | native_module.CREATE_NO_WINDOW
        | native_module.CREATE_UNICODE_ENVIRONMENT
        | native_module.EXTENDED_STARTUPINFO_PRESENT
    )
    assert (
        shim.calls.index("CreateProcessW")
        < shim.calls.index("AssignProcessToJobObject")
        < shim.calls.index("ResumeThread")
    )
    assert shim.closed == [105, 102, 104, 106, 702]

    api.close_process(process)  # type: ignore[attr-defined]

    assert shim.closed == [105, 102, 104, 106, 702, 101, 103, 701, 601]


def test_native_process_api_cleans_successful_assignment_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = _Kernel32ProcessShim(assign_succeeds=False)
    api = _shim_native_api(shim, monkeypatch)
    backend = native_module.NativeWindowsCommandVersionBackend(api=api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.START_FAILED
    assert "TerminateProcess" in shim.calls
    assert "WaitForSingleObject" in shim.calls
    assert "TerminateJobObject" not in shim.calls
    assert set(shim.closed) == {101, 102, 103, 104, 105, 106, 601, 701, 702}


@pytest.mark.parametrize("terminate_succeeds", (True, False))
def test_native_process_api_recovers_raw_handles_after_capture_interruption(
    monkeypatch: pytest.MonkeyPatch,
    terminate_succeeds: bool,
) -> None:
    shim = _Kernel32ProcessShim(
        terminate_process_succeeds=terminate_succeeds,
    )
    api = _shim_native_api(shim, monkeypatch)
    backend = native_module.NativeWindowsCommandVersionBackend(api=api)
    original_handle_value = native_module._handle_value

    def interrupt_process_capture(value: object) -> int:
        if _native_handle_value(value) == shim.process_handle:
            raise KeyboardInterrupt
        return original_handle_value(value)

    monkeypatch.setattr(native_module, "_handle_value", interrupt_process_capture)

    expected_error: type[BaseException]
    if terminate_succeeds:
        expected_error = KeyboardInterrupt
    else:
        expected_error = CommandExecutionError
    with pytest.raises(expected_error) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    if not terminate_succeeds:
        assert isinstance(captured.value, CommandExecutionError)
        assert captured.value.code is CommandExecutionErrorCode.CONTAINMENT_FAILED
    assert "TerminateProcess" in shim.calls
    if terminate_succeeds:
        assert "WaitForSingleObject" in shim.calls
    assert set(shim.closed) == {101, 102, 103, 104, 105, 106, 601, 701, 702}
    assert len(shim.closed) == 9


@pytest.mark.parametrize(
    ("terminate_succeeds", "wait_result"),
    (
        (False, native_module._WAIT_OBJECT_0),
        (True, native_module._WAIT_TIMEOUT),
    ),
)
def test_native_process_api_surfaces_unverified_unassigned_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    terminate_succeeds: bool,
    wait_result: int,
) -> None:
    shim = _Kernel32ProcessShim(
        assign_succeeds=False,
        terminate_process_succeeds=terminate_succeeds,
        wait_result=wait_result,
    )
    api = _shim_native_api(shim, monkeypatch)
    backend = native_module.NativeWindowsCommandVersionBackend(api=api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.CONTAINMENT_FAILED
    assert "TerminateProcess" in shim.calls
    assert set(shim.closed) == {101, 102, 103, 104, 105, 106, 601, 701, 702}


def test_native_process_api_terminates_assigned_job_on_resume_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = _Kernel32ProcessShim(resume_result=0xFFFFFFFF)
    api = _shim_native_api(shim, monkeypatch)
    backend = native_module.NativeWindowsCommandVersionBackend(api=api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.START_FAILED
    assert "TerminateJobObject" in shim.calls
    assert "QueryInformationJobObject" in shim.calls
    assert "TerminateProcess" not in shim.calls
    assert set(shim.closed) == {101, 102, 103, 104, 105, 106, 601, 701, 702}


@pytest.mark.parametrize(
    ("terminate_job_succeeds", "returned_size"),
    (
        (False, None),
        (True, 0),
        (
            True,
            ctypes.sizeof(native_module._JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) - 1,
        ),
    ),
)
def test_native_process_api_surfaces_unverified_assigned_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    terminate_job_succeeds: bool,
    returned_size: int | None,
) -> None:
    shim = _Kernel32ProcessShim(
        resume_result=0xFFFFFFFF,
        terminate_job_succeeds=terminate_job_succeeds,
        returned_size=returned_size,
    )
    api = _shim_native_api(shim, monkeypatch)
    backend = native_module.NativeWindowsCommandVersionBackend(api=api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.CONTAINMENT_FAILED
    assert "TerminateJobObject" in shim.calls
    if terminate_job_succeeds:
        assert "QueryInformationJobObject" in shim.calls
    assert set(shim.closed) == {101, 102, 103, 104, 105, 106, 601, 701, 702}


@pytest.mark.parametrize(
    "returned_size",
    (0, ctypes.sizeof(native_module._JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) - 1),
)
def test_native_process_api_rejects_inconsistent_job_accounting_length(
    monkeypatch: pytest.MonkeyPatch,
    returned_size: int,
) -> None:
    shim = _Kernel32ProcessShim(returned_size=returned_size)
    api = _shim_native_api(shim, monkeypatch)

    with pytest.raises(OSError):
        api.active_processes(shim.job_handle)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "executable_path",
    (
        PureWindowsPath(r"relative\docker-compose.exe"),
        PureWindowsPath(r"C:\?bad\docker-compose.exe"),
        PureWindowsPath(r"\\server\share\docker-compose.exe"),
    ),
)
def test_native_request_rejects_noncanonical_or_nonlocal_paths(
    executable_path: PureWindowsPath,
) -> None:
    with pytest.raises(ValueError):
        command_module.CommandProcessRequest(
            executable_path=executable_path,
            arguments=("version", "--short"),
            environment=(
                ("SystemRoot", _WINDOWS_DIRECTORY),
                ("WINDIR", _WINDOWS_DIRECTORY),
            ),
            working_directory=PureWindowsPath(_SYSTEM_DIRECTORY),
            timeout_ms=15_000,
            stdout_limit_bytes=64 * 1024,
            stderr_limit_bytes=16 * 1024,
        )


def test_native_backend_streams_bounded_output_and_waits_for_empty_job() -> None:
    api = _NativeProcessApi(stdout=b"5.3.1\n")
    backend = _native_backend(api)

    result = backend.execute(_native_request())  # type: ignore[arg-type]

    assert result.stdout == b"5.3.1\n"
    assert result.stderr == b""
    assert result.stdin_closed is True
    assert result.process_tree_contained is True
    assert result.process_tree_empty is True
    assert api.terminate_count == 0
    assert api.close_count == 1


def test_native_backend_terminates_and_verifies_tree_on_stream_overflow() -> None:
    api = _NativeProcessApi(stdout=b"x" * (64 * 1024 + 1), active=1)
    backend = _native_backend(api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.OUTPUT_LIMIT
    assert api.terminate_count >= 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_backend_terminates_and_verifies_tree_on_timeout() -> None:
    api = _NativeProcessApi(active=1, wait_advance=16.0)
    backend = _native_backend(api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.TIMEOUT
    assert api.terminate_count >= 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_backend_rejects_unverified_process_tree_termination() -> None:
    api = _NativeProcessApi(
        active=1,
        wait_advance=16.0,
        terminate_clears=False,
    )
    backend = _native_backend(api)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.CONTAINMENT_FAILED
    assert api.terminate_count >= 1
    assert api.active == 1
    assert api.close_count == 1


def test_native_backend_cleans_up_when_first_reader_cannot_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _NativeProcessApi(active=1)
    backend = _native_backend(api)

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("injected reader start failure")

    monkeypatch.setattr(threading.Thread, "start", fail_start)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.START_FAILED
    assert api.terminate_count >= 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_backend_cleans_up_when_reader_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _NativeProcessApi(active=1)
    backend = _native_backend(api)

    def fail_reader(*_args: object, **_kwargs: object) -> object:
        raise MemoryError("injected reader allocation failure")

    monkeypatch.setattr(native_module, "_BoundedReader", fail_reader)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.START_FAILED
    assert api.terminate_count >= 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_backend_cleans_up_live_reader_when_second_cannot_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _NativeProcessApi(stdout=b"5.3.1\n", active=1, block_stdout=True)
    backend = _native_backend(api)
    original_start = threading.Thread.start
    calls = 0

    def fail_second_start(thread: threading.Thread) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            assert api.stdout_read_entered.wait(1.0)
            raise RuntimeError("injected second-reader start failure")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_second_start)

    with pytest.raises(CommandExecutionError) as captured:
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert captured.value.code is CommandExecutionErrorCode.START_FAILED
    assert api.stdout_release.is_set()
    assert api.terminate_count >= 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_backend_preserves_interruption_after_reader_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _NativeProcessApi(active=1)
    backend = _native_backend(api)

    def interrupt_start(_thread: threading.Thread) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(threading.Thread, "start", interrupt_start)

    with pytest.raises(KeyboardInterrupt):
        backend.execute(_native_request())  # type: ignore[arg-type]

    assert api.terminate_count == 1
    assert api.active == 0
    assert api.close_count == 1


def test_native_ctypes_layouts_and_environment_block_match_x64_contract() -> None:
    import ctypes

    assert ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(native_module._SECURITY_ATTRIBUTES) == 24
    assert ctypes.sizeof(native_module._STARTUPINFOW) == 104
    assert ctypes.sizeof(native_module._STARTUPINFOEXW) == 112
    assert ctypes.sizeof(native_module._PROCESS_INFORMATION) == 24
    assert ctypes.sizeof(native_module._JOBOBJECT_BASIC_LIMIT_INFORMATION) == 64
    assert ctypes.sizeof(native_module._JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144
    assert ctypes.sizeof(native_module._JOBOBJECT_BASIC_ACCOUNTING_INFORMATION) == 48
    assert (
        native_module._NativeWindowsProcessApi._environment_block(
            (
                ("SystemRoot", _WINDOWS_DIRECTORY),
                ("WINDIR", _WINDOWS_DIRECTORY),
            )
        )
        == "SystemRoot=C:\\Windows\x00WINDIR=C:\\Windows\x00"
    )


def test_native_environment_block_rejects_ambient_or_reordered_entries() -> None:
    invalid = (
        (("PATH", r"C:\untrusted"),),
        (
            ("WINDIR", _WINDOWS_DIRECTORY),
            ("SystemRoot", _WINDOWS_DIRECTORY),
        ),
        (
            ("SystemRoot", _WINDOWS_DIRECTORY),
            ("SystemRoot", _WINDOWS_DIRECTORY),
        ),
    )
    for environment in invalid:
        with pytest.raises(ValueError):
            native_module._NativeWindowsProcessApi._environment_block(environment)


def test_native_backend_source_contains_required_windows_containment_primitives() -> (
    None
):
    source = (
        LAUNCHER_ROOT / "towerscout_launcher" / "runtime_command_native.py"
    ).read_text(encoding="utf-8")
    for required in (
        "CreateProcessW",
        "CreateJobObjectW",
        "AssignProcessToJobObject",
        "TerminateJobObject",
        "QueryInformationJobObject",
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
        "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        "CREATE_SUSPENDED",
    ):
        assert required in source
    assert "os.environ" not in source
    assert "subprocess.run" not in source
    assert "subprocess.Popen" not in source
