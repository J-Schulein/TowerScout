"""
Legacy end-to-end integration harness.

This file targeted older routes and event helpers that are no longer present in
the current Flask app. Keep it quarantined until it is rebuilt against the
active endpoint surface.
"""

import pytest

pytest.skip(
    "Legacy end-to-end harness targets removed routes (/draw_polygon, "
    "/get_status, /cancel_detection) and the old ts_events helper API. "
    "Rebuild it against the current Flask endpoints before re-enabling.",
    allow_module_level=True,
)
