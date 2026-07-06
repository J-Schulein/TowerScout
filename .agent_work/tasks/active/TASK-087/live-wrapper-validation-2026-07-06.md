# TASK-087 Live Wrapper Validation Evidence - 2026-07-06

## Purpose

Prepare the first explicit internal live-wrapper validation window for Task-087
after reviewer approval of PR #45 at `0132b13`.

This note is task-local evidence. Record sanitized states only. Do not record
raw subprocess output, helper tokens, operation credentials, `.env` contents,
certificate subjects, certificate thumbprints, provider keys, full local paths,
browser network traces, screenshots, or support logs.

## Planned Run Scope

- PR / branch head: `0132b13`
- Branch: `feature/task-087-helper-transport`
- Package / checkout label: local PR #45 source checkout, path omitted
- Validation mode: internal live-wrapper controlled validation
- Runtime engine: `docker`
- GPU mode: `off`
- App port: `5000`
- Provider: `google`
- Package flavor label: source-checkout Docker CPU/off validation
- Product UI repair path: blocked
- `provider_tls_repair=true`: blocked
- Browser-triggered default mutation: blocked
- Podman remediation: blocked
- Tester-facing guided repair packaging: blocked

## Planned Wrapper Sequence

Expected helper-controlled step order:

1. `repair`
2. `stop`
3. `start`

No other wrapper or shell command is in scope for the first live run.

Expected timeout budget:

- Repair: 300 seconds
- Stop: 120 seconds
- Start/readiness: 180 seconds
- Overall operation timeout and operation-lock behavior remain unchanged.

## Manual Fallback Commands

Use these only as the audited fallback path if the live validation leaves the
runtime stopped, degraded, or blocked:

```powershell
.\scripts\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off -Apply
.\scripts\stop.cmd -Engine docker
.\start.bat -Engine docker -Gpu off -Port 5000 -NoBrowser -TimeoutSeconds 180
```

If the selected port changes before execution, update the fallback start
command here before running the live sequence.

## Pre-Run Checklist

- [x] Reviewer cleared `0132b13` for internal live-wrapper validation only.
- [x] First live run is Docker CPU/off only.
- [x] Product UI, advertised helper capability, default browser-triggered
  mutation, Podman remediation, and tester-facing packaging remain blocked.
- [ ] Release owner confirms the validation window and accepts that the run may
  change TLS trust material and stop/restart the Docker runtime.
- [x] Confirm no other TowerScout package instance is using port `5000`:
  readiness was not reachable on port `5000` during the pre-run status check.
- [x] Confirm the current runtime initial state immediately before execution:
  stopped / not reachable.
- [ ] Confirm the internal execution path, not browser input, supplies
  `ExecutionEnabled=true`.
- [ ] Confirm the manual fallback commands above are available.

## Sanitized Evidence To Record After Execution

- Run result: PASS / FAIL / PARTIAL / BLOCKED
- Runtime initial state: running / stopped / degraded / unknown
- Operation states observed:
  - `tls_repair_completed`
  - `runtime_stopped`
  - `ready`
  - `readiness_timeout`
  - `tls_repair_failed`
  - `runtime_stop_failed`
  - `runtime_start_failed`
  - `operation_timeout`
- Actual terminal state:
- Step order observed:
- Terminal classification:
- Readiness returned: yes / no / partial
- Provider setup could be retried: yes / no / not tested
- Fallback command needed: yes / no
- Sanitization check: confirm no raw subprocess output, helper token,
  operation credential, `.env` content, certificate subject, certificate
  thumbprint, provider key, full local path, browser network trace, screenshot,
  or support log was recorded.

## Abort Conditions

Abort and record `BLOCKED` or `PARTIAL` if any of these occur:

- The wrapper contract differs from repair, stop, start.
- Browser input can enable execution or change wrapper paths, arguments,
  interpreter, GPU mode, engine, port, or timeouts.
- Public status, task evidence, PR evidence, or helper output includes raw
  subprocess output, helper credentials, certificate details, provider keys,
  `.env` values, or full local paths.
- The runtime profile is stale, ambiguous, wrong-package, or wrong-port.
- Endpoint protection blocks helper execution in a way that would require
  bypassing the security model.

## Post-Run Gate

Keep product UI, `provider_tls_repair=true`, browser-triggered default mutation,
Podman remediation, and tester-facing guided repair packaging blocked until the
live evidence is reviewed.

Ask the reviewer to evaluate the sanitized evidence before any Gate 3 product
integration design begins.
