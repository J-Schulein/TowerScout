from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_ROOT = ROOT / "launcher"
if str(LAUNCHER_ROOT) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_ROOT))

from towerscout_launcher.windows_mutex import (
    MUTEX_ACCESS_MASK,
    SYSTEM_SID,
    CreatedMutex,
    HeldCrossSessionMutex,
    HeldRuntimeTransactionLocks,
    MutexAccessAllowedAce,
    MutexSecurityFacts,
    MutexWaitOutcome,
    RuntimeTransactionLockBinding,
    RuntimeTransactionLockError,
    RuntimeTransactionLockErrorCode,
    WindowsMutexError,
    acquire_ordered_runtime_transaction_locks,
    acquire_secured_cross_session_mutex,
)

_USER_SID = "S-1-5-21-1000-1001-1002-1003"
_NAME = "Global\\TowerScoutEnv-v1-" + ("a" * 64)
_TARGET_NAME = "Global\\TowerScoutRepair-v1-" + ("b" * 64)


def _security() -> MutexSecurityFacts:
    return MutexSecurityFacts(
        owner_sid=_USER_SID,
        dacl_present=True,
        dacl_protected=True,
        ace_count=2,
        allowed_aces=(
            MutexAccessAllowedAce(SYSTEM_SID, MUTEX_ACCESS_MASK, 0),
            MutexAccessAllowedAce(_USER_SID, MUTEX_ACCESS_MASK, 0),
        ),
    )


class _FakeMutexApi:
    supported = True

    def __init__(self, *, created: bool = True) -> None:
        self.created = created
        self.handle = object()
        self.security = _security()
        self.wait_outcome = MutexWaitOutcome.ACQUIRED
        self.created_arguments: list[tuple[str, str, int]] = []
        self.wait_arguments: list[tuple[object, int]] = []
        self.released: list[object] = []
        self.closed: list[object] = []
        self.create_error: Exception | None = None
        self.query_error: Exception | None = None
        self.wait_error: Exception | None = None
        self.release_error: Exception | None = None
        self.close_error: Exception | None = None

    def current_user_sid(self) -> str:
        return _USER_SID

    def create_mutex(
        self, name: str, *, owner_sid: str, access_mask: int
    ) -> CreatedMutex:
        self.created_arguments.append((name, owner_sid, access_mask))
        if self.create_error is not None:
            raise self.create_error
        return CreatedMutex(self.handle, self.created)

    def query_security(self, handle: object) -> MutexSecurityFacts:
        assert handle is self.handle
        if self.query_error is not None:
            raise self.query_error
        return self.security

    def wait(self, handle: object, timeout_ms: int) -> MutexWaitOutcome:
        self.wait_arguments.append((handle, timeout_ms))
        if self.wait_error is not None:
            raise self.wait_error
        return self.wait_outcome

    def release_mutex(self, handle: object) -> None:
        self.released.append(handle)
        if self.release_error is not None:
            raise self.release_error

    def close_handle(self, handle: object) -> None:
        self.closed.append(handle)
        if self.close_error is not None:
            raise self.close_error


def _binding(
    *,
    environment_name: str = _NAME,
    target_name: str = _TARGET_NAME,
    target_digest: str = "c" * 64,
    environment_digest: str = "d" * 64,
) -> RuntimeTransactionLockBinding:
    return RuntimeTransactionLockBinding(
        environment_mutex_name=environment_name,
        target_mutex_name=target_name,
        target_token_sha256=target_digest,
        environment_sha256=environment_digest,
    )


class _OrderedMutexApi:
    supported = True

    def __init__(self) -> None:
        self.created: dict[str, bool] = {}
        self.wait_outcomes: dict[str, MutexWaitOutcome] = {}
        self.release_errors: set[str] = set()
        self.events: list[tuple[str, str]] = []
        self._handles: dict[object, str] = {}

    def current_user_sid(self) -> str:
        self.events.append(("sid", ""))
        return _USER_SID

    def create_mutex(
        self, name: str, *, owner_sid: str, access_mask: int
    ) -> CreatedMutex:
        assert owner_sid == _USER_SID
        assert access_mask == MUTEX_ACCESS_MASK
        self.events.append(("create", name))
        handle = object()
        self._handles[handle] = name
        return CreatedMutex(handle, self.created.get(name, True))

    def query_security(self, handle: object) -> MutexSecurityFacts:
        self.events.append(("security", self._handles[handle]))
        return _security()

    def wait(self, handle: object, timeout_ms: int) -> MutexWaitOutcome:
        name = self._handles[handle]
        self.events.append(("wait", name))
        assert timeout_ms == 2750
        return self.wait_outcomes.get(name, MutexWaitOutcome.ACQUIRED)

    def release_mutex(self, handle: object) -> None:
        name = self._handles[handle]
        self.events.append(("release", name))
        if name in self.release_errors:
            raise OSError(r"C:\Users\private\secret")

    def close_handle(self, handle: object) -> None:
        name = self._handles[handle]
        self.events.append(("close", name))


def _event_names(api: _OrderedMutexApi, event: str) -> list[str]:
    return [name for kind, name in api.events if kind == event]


def test_new_secured_mutex_is_initially_owned_and_released() -> None:
    api = _FakeMutexApi(created=True)

    with acquire_secured_cross_session_mutex(_NAME, api=api) as held:
        assert type(held) is HeldCrossSessionMutex
        assert held.abandoned is False
        assert held.closed is False
        assert api.created_arguments == [(_NAME, _USER_SID, MUTEX_ACCESS_MASK)]
        assert api.wait_arguments == []

    assert held.closed is True
    assert api.released == [api.handle]
    assert api.closed == [api.handle]


def test_existing_secured_mutex_waits_with_bounded_timeout() -> None:
    api = _FakeMutexApi(created=False)

    held = acquire_secured_cross_session_mutex(_NAME, api=api, timeout_ms=2750)

    assert held.abandoned is False
    assert api.wait_arguments == [(api.handle, 2750)]
    held.close()


def test_abandoned_mutex_is_returned_as_explicit_recovery_signal() -> None:
    api = _FakeMutexApi(created=False)
    api.wait_outcome = MutexWaitOutcome.ABANDONED

    held = acquire_secured_cross_session_mutex(_NAME, api=api)

    assert held.abandoned is True
    held.close()


@pytest.mark.parametrize(
    ("security", "category"),
    (
        (replace(_security(), owner_sid="S-1-5-18"), "mutex_security_mismatch"),
        (replace(_security(), dacl_present=False), "mutex_security_mismatch"),
        (replace(_security(), dacl_protected=False), "mutex_security_mismatch"),
        (replace(_security(), ace_count=3), "mutex_security_mismatch"),
        (
            replace(
                _security(),
                allowed_aces=(
                    *_security().allowed_aces,
                    MutexAccessAllowedAce("S-1-1-0", MUTEX_ACCESS_MASK, 0),
                ),
                ace_count=3,
            ),
            "mutex_security_mismatch",
        ),
        (
            replace(
                _security(),
                allowed_aces=(
                    MutexAccessAllowedAce(SYSTEM_SID, MUTEX_ACCESS_MASK, 0),
                    MutexAccessAllowedAce(_USER_SID, MUTEX_ACCESS_MASK | 2, 0),
                ),
            ),
            "mutex_security_mismatch",
        ),
        (
            replace(
                _security(),
                allowed_aces=(
                    MutexAccessAllowedAce(SYSTEM_SID, MUTEX_ACCESS_MASK, 0),
                    MutexAccessAllowedAce(_USER_SID, MUTEX_ACCESS_MASK, 2),
                ),
            ),
            "mutex_security_mismatch",
        ),
    ),
)
def test_mutex_security_must_match_exact_owner_and_dacl(
    security: MutexSecurityFacts, category: str
) -> None:
    api = _FakeMutexApi(created=True)
    api.security = security

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=api)

    assert failure.value.category == category
    assert api.released == [api.handle]
    assert api.closed == [api.handle]


def test_existing_busy_mutex_closes_without_release() -> None:
    api = _FakeMutexApi(created=False)
    api.wait_outcome = MutexWaitOutcome.TIMEOUT

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=api)

    assert failure.value.category == "mutex_busy"
    assert api.released == []
    assert api.closed == [api.handle]


@pytest.mark.parametrize("wait_outcome", (MutexWaitOutcome.FAILED, object()))
def test_invalid_wait_outcome_fails_closed_and_closes(wait_outcome: object) -> None:
    api = _FakeMutexApi(created=False)
    api.wait_outcome = wait_outcome  # type: ignore[assignment]

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=api)

    assert failure.value.category == "mutex_unavailable"
    assert api.released == []
    assert api.closed == [api.handle]


@pytest.mark.parametrize(
    "error_field",
    ("create_error", "query_error", "wait_error"),
)
def test_native_failures_are_sanitized(error_field: str) -> None:
    api = _FakeMutexApi(created=error_field != "wait_error")
    setattr(api, error_field, OSError(r"C:\Users\private\secret"))

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=api)

    assert failure.value.category == "mutex_unavailable"
    assert "private" not in str(failure.value).lower()
    assert failure.value.__suppress_context__ is True
    if error_field != "create_error":
        assert api.closed == [api.handle]


def test_invalid_or_non_global_name_is_rejected_before_native_use() -> None:
    api = _FakeMutexApi()

    for name in (
        "Local\\TowerScoutEnv-v1-" + ("a" * 64),
        "Global\\Other-v1-" + ("a" * 64),
        "Global\\TowerScoutEnv-v1-" + ("A" * 64),
        _NAME + "\\extra",
    ):
        with pytest.raises(WindowsMutexError) as failure:
            acquire_secured_cross_session_mutex(name, api=api)
        assert failure.value.category == "mutex_invalid"

    assert api.created_arguments == []


def test_unsupported_platform_fails_closed() -> None:
    api = _FakeMutexApi()
    api.supported = False

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=api)

    assert failure.value.category == "mutex_unavailable"
    assert api.created_arguments == []


def test_same_process_duplicate_name_is_rejected_before_second_native_open() -> None:
    first_api = _FakeMutexApi()
    second_api = _FakeMutexApi()
    held = acquire_secured_cross_session_mutex(_NAME, api=first_api)

    with pytest.raises(WindowsMutexError) as failure:
        acquire_secured_cross_session_mutex(_NAME, api=second_api)

    assert failure.value.category == "mutex_busy"
    assert second_api.created_arguments == []
    held.close()


def test_wrong_thread_cannot_release_owned_mutex() -> None:
    api = _FakeMutexApi()
    held = acquire_secured_cross_session_mutex(_NAME, api=api)
    failures: list[BaseException] = []

    def close_from_other_thread() -> None:
        try:
            held.close()
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=close_from_other_thread)
    worker.start()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], WindowsMutexError)
    assert failures[0].category == "mutex_wrong_thread"
    assert held.closed is False
    assert api.released == []
    held.close()


def test_release_failure_still_closes_handle_and_unreserves_name() -> None:
    api = _FakeMutexApi()
    api.release_error = OSError(r"C:\Users\private\secret")
    held = acquire_secured_cross_session_mutex(_NAME, api=api)

    with pytest.raises(WindowsMutexError) as failure:
        held.close()

    assert failure.value.category == "mutex_release_failed"
    assert "private" not in str(failure.value).lower()
    assert held.closed is True
    assert api.closed == [api.handle]

    retry_api = _FakeMutexApi()
    retry = acquire_secured_cross_session_mutex(_NAME, api=retry_api)
    retry.close()


def test_repr_does_not_expose_name_or_user_sid() -> None:
    api = _FakeMutexApi()
    held = acquire_secured_cross_session_mutex(_NAME, api=api)

    rendered = repr(held)

    assert _NAME not in rendered
    assert _USER_SID not in rendered
    assert "<redacted>" in rendered
    held.close()


def test_ordered_transaction_locks_acquire_environment_then_target() -> None:
    api = _OrderedMutexApi()
    expected = _binding()

    def revalidate() -> RuntimeTransactionLockBinding:
        api.events.append(("revalidate", ""))
        return expected

    held = acquire_ordered_runtime_transaction_locks(
        expected,
        revalidate,
        api=api,
        timeout_ms=2750,
    )

    assert type(held) is HeldRuntimeTransactionLocks
    assert held.environment_abandoned is False
    assert held.target_abandoned is False
    assert [kind for kind, _name in api.events if kind in {"create", "revalidate"}] == [
        "create",
        "revalidate",
        "create",
        "revalidate",
    ]
    assert _event_names(api, "create") == [_NAME, _TARGET_NAME]

    held.close()

    assert held.closed is True
    assert _event_names(api, "release") == [_TARGET_NAME, _NAME]
    assert _event_names(api, "close") == [_TARGET_NAME, _NAME]


def test_binding_drift_under_environment_lock_prevents_target_acquisition() -> None:
    api = _OrderedMutexApi()
    expected = _binding()

    with pytest.raises(RuntimeTransactionLockError) as failure:
        acquire_ordered_runtime_transaction_locks(
            expected,
            lambda: _binding(environment_digest="e" * 64),
            api=api,
            timeout_ms=2750,
        )

    assert failure.value.code is RuntimeTransactionLockErrorCode.BINDING_CHANGED
    assert _event_names(api, "create") == [_NAME]
    assert _event_names(api, "release") == [_NAME]
    assert _event_names(api, "close") == [_NAME]


def test_binding_drift_under_both_locks_releases_in_reverse_order() -> None:
    api = _OrderedMutexApi()
    expected = _binding()
    revalidations = iter((expected, _binding(target_digest="e" * 64)))

    with pytest.raises(RuntimeTransactionLockError) as failure:
        acquire_ordered_runtime_transaction_locks(
            expected,
            lambda: next(revalidations),
            api=api,
            timeout_ms=2750,
        )

    assert failure.value.code is RuntimeTransactionLockErrorCode.BINDING_CHANGED
    assert _event_names(api, "create") == [_NAME, _TARGET_NAME]
    assert _event_names(api, "release") == [_TARGET_NAME, _NAME]
    assert _event_names(api, "close") == [_TARGET_NAME, _NAME]


def test_target_lock_contention_releases_environment_lock() -> None:
    api = _OrderedMutexApi()
    api.created[_TARGET_NAME] = False
    api.wait_outcomes[_TARGET_NAME] = MutexWaitOutcome.TIMEOUT
    expected = _binding()

    with pytest.raises(RuntimeTransactionLockError) as failure:
        acquire_ordered_runtime_transaction_locks(
            expected,
            lambda: expected,
            api=api,
            timeout_ms=2750,
        )

    assert failure.value.code is RuntimeTransactionLockErrorCode.BUSY
    assert _event_names(api, "create") == [_NAME, _TARGET_NAME]
    assert _event_names(api, "release") == [_NAME]
    assert _event_names(api, "close") == [_TARGET_NAME, _NAME]


def test_ordered_transaction_locks_preserve_both_abandoned_signals() -> None:
    api = _OrderedMutexApi()
    api.created = {_NAME: False, _TARGET_NAME: False}
    api.wait_outcomes = {
        _NAME: MutexWaitOutcome.ABANDONED,
        _TARGET_NAME: MutexWaitOutcome.ABANDONED,
    }
    expected = _binding()

    held = acquire_ordered_runtime_transaction_locks(
        expected,
        lambda: expected,
        api=api,
        timeout_ms=2750,
    )

    assert held.environment_abandoned is True
    assert held.target_abandoned is True
    held.close()


def test_distinct_packages_still_conflict_on_the_same_runtime_target() -> None:
    first_api = _OrderedMutexApi()
    second_api = _OrderedMutexApi()
    first_binding = _binding()
    second_binding = _binding(environment_name="Global\\TowerScoutEnv-v1-" + ("e" * 64))
    first = acquire_ordered_runtime_transaction_locks(
        first_binding,
        lambda: first_binding,
        api=first_api,
        timeout_ms=2750,
    )

    with pytest.raises(RuntimeTransactionLockError) as failure:
        acquire_ordered_runtime_transaction_locks(
            second_binding,
            lambda: second_binding,
            api=second_api,
            timeout_ms=2750,
        )

    assert failure.value.code is RuntimeTransactionLockErrorCode.BUSY
    assert _event_names(second_api, "create") == [second_binding.environment_mutex_name]
    assert _event_names(second_api, "release") == [
        second_binding.environment_mutex_name
    ]
    first.close()


def test_distinct_packages_and_targets_can_hold_independent_lock_pairs() -> None:
    first_api = _OrderedMutexApi()
    second_api = _OrderedMutexApi()
    first_binding = _binding()
    second_binding = _binding(
        environment_name="Global\\TowerScoutEnv-v1-" + ("e" * 64),
        target_name="Global\\TowerScoutRepair-v1-" + ("f" * 64),
    )

    first = acquire_ordered_runtime_transaction_locks(
        first_binding,
        lambda: first_binding,
        api=first_api,
        timeout_ms=2750,
    )
    second = acquire_ordered_runtime_transaction_locks(
        second_binding,
        lambda: second_binding,
        api=second_api,
        timeout_ms=2750,
    )

    second.close()
    first.close()


def test_ordered_lock_revalidation_failure_is_sanitized() -> None:
    api = _OrderedMutexApi()
    expected = _binding()

    def fail_revalidation() -> RuntimeTransactionLockBinding:
        raise RuntimeError(r"C:\Users\private\secret")

    with pytest.raises(RuntimeTransactionLockError) as failure:
        acquire_ordered_runtime_transaction_locks(
            expected,
            fail_revalidation,
            api=api,
            timeout_ms=2750,
        )

    assert failure.value.code is RuntimeTransactionLockErrorCode.BINDING_CHANGED
    assert "private" not in str(failure.value).lower()
    assert failure.value.__suppress_context__ is True
    assert _event_names(api, "release") == [_NAME]


def test_ordered_lock_cleanup_runs_for_process_level_interruption() -> None:
    api = _OrderedMutexApi()
    expected = _binding()

    class _Interrupted(BaseException):
        pass

    def interrupt_revalidation() -> RuntimeTransactionLockBinding:
        raise _Interrupted()

    with pytest.raises(_Interrupted):
        acquire_ordered_runtime_transaction_locks(
            expected,
            interrupt_revalidation,
            api=api,
            timeout_ms=2750,
        )

    assert _event_names(api, "release") == [_NAME]
    assert _event_names(api, "close") == [_NAME]


def test_ordered_lock_cleanup_does_not_mask_process_level_interruption() -> None:
    api = _OrderedMutexApi()
    api.release_errors.add(_NAME)
    expected = _binding()

    class _Interrupted(BaseException):
        pass

    def interrupt_revalidation() -> RuntimeTransactionLockBinding:
        raise _Interrupted()

    with pytest.raises(_Interrupted):
        acquire_ordered_runtime_transaction_locks(
            expected,
            interrupt_revalidation,
            api=api,
            timeout_ms=2750,
        )

    assert _event_names(api, "release") == [_NAME]
    assert _event_names(api, "close") == [_NAME]


def test_ordered_lock_owner_rejects_release_from_another_thread() -> None:
    api = _OrderedMutexApi()
    expected = _binding()
    held = acquire_ordered_runtime_transaction_locks(
        expected,
        lambda: expected,
        api=api,
        timeout_ms=2750,
    )
    failures: list[BaseException] = []

    def close_from_other_thread() -> None:
        try:
            held.close()
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=close_from_other_thread)
    worker.start()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], RuntimeTransactionLockError)
    assert failures[0].code is RuntimeTransactionLockErrorCode.WRONG_THREAD
    assert held.closed is False
    assert _event_names(api, "release") == []
    held.close()


def test_ordered_lock_release_failure_still_releases_both_locks() -> None:
    api = _OrderedMutexApi()
    api.release_errors.add(_TARGET_NAME)
    expected = _binding()
    held = acquire_ordered_runtime_transaction_locks(
        expected,
        lambda: expected,
        api=api,
        timeout_ms=2750,
    )

    with pytest.raises(RuntimeTransactionLockError) as failure:
        held.close()

    assert failure.value.code is RuntimeTransactionLockErrorCode.RELEASE_FAILED
    assert "private" not in str(failure.value).lower()
    assert held.closed is True
    assert _event_names(api, "release") == [_TARGET_NAME, _NAME]
    assert _event_names(api, "close") == [_TARGET_NAME, _NAME]


def test_ordered_lock_repr_redacts_names_and_digests() -> None:
    api = _OrderedMutexApi()
    expected = _binding()
    held = acquire_ordered_runtime_transaction_locks(
        expected,
        lambda: expected,
        api=api,
        timeout_ms=2750,
    )

    rendered = repr(held)

    assert _NAME not in rendered
    assert _TARGET_NAME not in rendered
    assert expected.target_token_sha256 not in rendered
    assert expected.environment_sha256 not in rendered
    assert "<redacted>" in rendered
    held.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows mutex APIs")
def test_native_global_mutex_reports_abandoned_owner_from_another_process() -> None:
    digest = hashlib.sha256(
        f"task087-mutex-{os.getpid()}-{time.time_ns()}".encode("ascii")
    ).hexdigest()
    name = f"Global\\TowerScoutRepair-v1-{digest}"
    child_code = (
        "import os,sys,time; "
        "sys.path.insert(0,sys.argv[1]); "
        "from towerscout_launcher.windows_mutex import "
        "acquire_secured_cross_session_mutex; "
        "held=acquire_secured_cross_session_mutex(sys.argv[2]); "
        "print('ready',flush=True); "
        "time.sleep(1); "
        "os._exit(0)"
    )
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-u", "-c", child_code, str(LAUNCHER_ROOT), name],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        held = acquire_secured_cross_session_mutex(name, timeout_ms=5000)
        assert held.abandoned is True
        held.close()
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
