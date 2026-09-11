from __future__ import annotations

from towerscout_launcher.app import run_app, show_duplicate_instance_message
from towerscout_launcher.coordination import acquire_single_instance
from towerscout_launcher.discovery import load_package_identity, locate_package_root


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
        return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
