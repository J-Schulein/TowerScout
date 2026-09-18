from __future__ import annotations

from towerscout_launcher.app import (
    run_app,
    show_duplicate_instance_message,
    show_startup_recovery_message,
)
from towerscout_launcher.coordination import acquire_single_instance
from towerscout_launcher.discovery import load_package_identity, locate_package_root
from towerscout_launcher.windows_recovery_front_door import (
    WindowsRecoveryFrontDoorError,
    WindowsRecoveryFrontDoorOutcome,
    recover_native_windows_pending_repair,
)

_RECOVERY_COMPLETED_MESSAGE = (
    "TowerScout verified and rolled back the interrupted repair. No new repair "
    "was started. Refresh status before trying again."
)
_RECOVERY_PENDING_MESSAGE = (
    "The interrupted repair still requires recovery. No new repair was started. "
    "Use the Task-086 manual recovery path or contact support."
)


def main() -> int:
    try:
        package = load_package_identity(locate_package_root())
        identity = f"{package.release_version}:{package.compose_project}:{package.image_digest}"
    except RuntimeError:
        identity = "package-unavailable"
    with acquire_single_instance(identity) as instance:
        if not instance.acquired:
            show_duplicate_instance_message()
            return 2
        try:
            recovery = recover_native_windows_pending_repair()
        except WindowsRecoveryFrontDoorError:
            show_startup_recovery_message(_RECOVERY_PENDING_MESSAGE, failed=True)
            return 3
        if recovery is WindowsRecoveryFrontDoorOutcome.RECOVERED:
            show_startup_recovery_message(_RECOVERY_COMPLETED_MESSAGE, failed=False)
        return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
