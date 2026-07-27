# TowerScout Host Helper

**Applies to**: Task-087 helper scaffolding shipped with the current release baseline
**Last reviewed**: 2026-07-27
**Audience**: Release maintainers, support staff, and reviewers of the Task-087 control plane

## What it is

TowerScout ships package-local Windows host-helper scaffolding intended for a
future guided "repair TLS trust and restart" flow. The helper exists because a
browser app running inside the TowerScout container cannot safely inspect the
Windows certificate store or execute trusted host-side restart commands by
itself.

The packaged helper code is designed to mediate a very small allowlisted set of
TowerScout-owned host actions such as provider TLS repair and restart, while
preserving the selected runtime profile.

## Current release status

The host-helper control plane is shipped **disabled** in the current release
baseline.

Two independent gates keep the browser-triggered mutation path dark:

- Public helper capability gate: `webapp/ts_host_helper.py`
- Frontend browser-mutation gate: `webapp/js/src/setup-wizard.js` and the built
  `webapp/js/towerscout.js`

The Windows launcher also leaves the review transport disabled unless
`TOWERSCOUT_HOST_HELPER_REVIEW_ENABLED=1` is explicitly set for that launch.
Because all release-facing gates remain off, the supported release path is
still the manual script workflow documented in the Quick Start and Package
Guide:

```powershell
.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off -Apply
.\scripts\stop.cmd -Engine docker
.\start.bat -Engine docker -Gpu off
```

## Security model

The shipped helper scaffolding is intended to follow these constraints when it
is eventually enabled:

- package-local only
- loopback-only listener
- durable helper token retained in the package-local host state directory
- separate per-launch HMAC key used only to issue narrow, short-lived browser
  authorizations
- allowlisted operations only
- validated enum-style arguments, not browser-provided command strings
- sanitized public operation states rather than raw subprocess output

The helper command map is limited to TowerScout-owned scripts such as repair,
stop, and start operations. The goal is support-safe orchestration, not general
host command execution.

## Files shipped with the package

Current package/runtime support files include:

- `scripts/host-helper.cmd`
- `scripts/host-helper.ps1`
- `scripts/host-helper-visible.cmd`
- `scripts/lib/TowerScoutHostHelper.ps1`
- `scripts/lib/TowerScoutCertificateStore.ps1`

These files being present does **not** mean the browser helper flow is active.

## Review-only transport checkpoint

The source tree includes an opt-in Gate 3 review path. When a maintainer sets
`TOWERSCOUT_HOST_HELPER_REVIEW_ENABLED=1` before using the Windows launcher,
the launcher creates a per-launch helper session, starts the visible
loopback-only helper, and passes only that session's bridge values to the app
container.

Do not put the generated session id, session key, or helper port in `.env`.
They are launcher-generated runtime values. The browser receives only
scope-bound, expiring authorizations for helper discovery, repair planning,
and operation polling. It never receives the durable helper token.

This checkpoint supports non-mutating contract review. The helper continues to
advertise `provider_tls_repair: false`, its controlled execution default is
false, and the browser mutation constant remains false.

## What enabling would require

Enabling the browser-triggered helper path is later Task-087 work and requires
more than code presence in the package.

Minimum gates before release exposure:

- release-owner sign-off on the helper-availability and browser-mutation gates
- managed-network package validation of helper discovery and live polling
- explicit review of lifecycle cleanup, restart behavior, and rollback evidence
- confirmation that the documented manual fallback remains intact

Until those gates pass, treat the host helper as shipped scaffolding rather
than a supported end-user feature.
