from __future__ import annotations

import ctypes
import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


ERROR_ALREADY_EXISTS = 183


@dataclass
class SingleInstance:
    acquired: bool
    _handle: int | None = None

    def close(self) -> None:
        if self._handle and os.name == "nt":
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> "SingleInstance":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        self.close()


def acquire_single_instance(package_identity: str) -> SingleInstance:
    """Acquire a package-scoped session mutex without a listener or worker."""
    if os.name != "nt":
        return SingleInstance(True)
    token = hashlib.sha256(package_identity.encode("utf-8")).hexdigest()[:24]
    mutex_name = f"Local\\TowerScoutLauncher-{token}"
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    if not handle:
        return SingleInstance(False)
    if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return SingleInstance(False)
    return SingleInstance(True, int(handle))


class OperationGuard:
    def __init__(self) -> None:
        self.active = False

    @contextmanager
    def begin(self) -> Iterator[bool]:
        if self.active:
            yield False
            return
        self.active = True
        try:
            yield True
        finally:
            self.active = False
