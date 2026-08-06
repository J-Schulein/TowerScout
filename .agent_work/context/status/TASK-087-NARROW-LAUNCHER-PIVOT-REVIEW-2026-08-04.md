# Task-087 Narrow Launcher Pivot - Follow-Up Review Request

**Status**: REVIEW REQUESTED - this is a proposed direction, not an approved
implementation or release decision
**Date**: August 4, 2026
**Audience**: Architecture, security, Windows deployment, product, release, and
support reviewers
**Decision Needed**: Determine whether TowerScout should replace the planned
browser-controlled repair helper with a small, user-launched Windows
maintenance application
**Release Effect**: None. Browser-triggered repair remains disabled, no repair
or certificate change was performed, and the manual repair remains available.

## Purpose Of This Follow-Up

The earlier
[`Task-087 Windows Helper Pivot Review`](./TASK-087-WINDOWS-HELPER-PIVOT-REVIEW-2026-08-04.md)
compared TowerScout's existing browser-to-Windows helper with the separate
`towerscout-windows-helpers` project. A subsequent architecture review agreed
that a desktop launcher may be the cleaner long-term direction and asked for
developer feedback.

This follow-up records the recommended path in simpler language, incorporates
what was learned from a careful non-mutating checkpoint, and asks reviewers to
challenge the recommendation. The goal is to uncover security, deployment,
support, recovery, usability, ownership, or schedule considerations that may
still be missing.

## Current Situation

Task-087 is currently **in progress**. The Tasks 090/098 dependency-security
gate is complete, and the dormant authenticated control-plane checkpoint was
merged at TowerScout commit `4b93caf`.

The merged code is not an active end-user feature:

- Browser-triggered repair is disabled.
- The helper's public repair capability is disabled.
- The launcher review switch is off by default.
- No release candidate is authorized to perform the repair from the browser.
- Managed-network, certificate-change, Docker/Podman, CPU/GPU, browser, and
  packaged-release qualification remain incomplete.
- The Task-086 manual repair command remains the supported fallback.

The canonical execution record remains
[`TASK-087-host-side-tls-repair-control-plane.md`](../../tasks/active/TASK-087-host-side-tls-repair-control-plane.md).
Its status wording should be reconciled separately because parts of the record
still describe the now-merged PR as awaiting merge.

## Recommendation In Plain Language

Stop trying to make the browser directly control the Windows repair process.

Instead, give TowerScout a small, visible Windows launcher with a clearly
labeled **Check/Repair Map Connections** action. When the browser detects the
certificate problem, it should tell the user to return to the TowerScout
launcher. The launcher should explain the proposed action, request explicit
confirmation, perform only fixed TowerScout operations, restart the same
TowerScout runtime, and report whether Google and Azure connections recovered.

The launcher should also become the natural place for the required Task-096
**Stop TowerScout** action after the repair workflow is proven.

This is a narrow pivot. It is not a proposal to replace TowerScout's container,
browser application, provider setup, detection workflow, or release model.

## What Would Stay The Same

- TowerScout would remain containerized.
- The existing Flask application and normal browser interface would remain.
- Google Maps and Azure Maps would remain first-class providers.
- Docker and Podman would remain required final runtime paths.
- CPU/GPU mode, port, package identity, image identity, and persistent data
  would be preserved.
- TowerScout's current certificate-selection and repair logic would remain the
  starting point.
- The repair would require explicit confirmation.
- The manual Task-086 command would remain the support and recovery fallback.
- No provider key would be given to or stored by the launcher.

## What Would Change

| Original Task-087 direction | Recommended direction |
| --- | --- |
| The browser requests a Windows repair. | The user requests it in the TowerScout launcher. |
| A second local HTTP service listens for approved browser requests. | No additional browser-to-Windows listener is needed. |
| Tokens and short-lived browser permissions protect the request. | The launcher directly owns the approved operation. |
| A long-running PowerShell helper coordinates the work. | A signed, visible TowerScout application coordinates it. |
| A hidden PowerShell worker performs the fixed sequence. | Hidden PowerShell behavior is removed or replaced. |
| The browser can eventually offer one-click repair. | The user follows a short browser-to-launcher handoff. |

The new design gives up literal one-click browser repair. In exchange, it
creates a simpler consent boundary and removes the need for a browser page to
control Windows certificate and container operations through another local
service.

## What The Safe Checkpoint Established

A short pre-execution checkpoint was performed against the Task-087 worktree
that matches the merged runtime files. It deliberately did not execute the
helper.

The checkpoint confirmed:

- All product repair and browser-mutation gates remain disabled.
- The relevant PowerShell files parse successfully.
- No helper session state existed before or after the check.
- No TowerScout loopback listener was created.
- No browser, container, certificate, provider, stop, start, or repair action
  ran.
- No Defender detection, remediation, or Attack Surface Reduction event was
  observed in the sanitized before/after window.
- No repository file was changed.

The checkpoint also found that the current path still contains the main
patterns of concern:

- The PowerShell scripts are unsigned.
- The workstation's effective PowerShell execution policy is restricted.
- The helper launcher uses an execution-policy bypass.
- The repair worker is started as a hidden PowerShell process.
- Loading the helper for its normal self-test would expose the complete helper
  library to AMSI even though the self-test does not perform a real repair.

For that reason, the executable self-test was not run. A non-mutating
self-test could still generate an endpoint-security notification, and its
success would not prove that the hidden repair worker is acceptable.

This evidence does not prove that the current helper will be blocked. It shows
that running it without a monitored security window would not meet the goal of
avoiding further security notifications.

## Why A Narrow Pivot Is Recommended

The known endpoint-protection event was originally associated with a hidden
PowerShell child-process pattern, not conclusively with the loopback listener.
The current implementation is more mature and security-conscious than that
early experiment. However, it still relies on unsigned scripts, execution
policy bypass, and a hidden PowerShell worker.

Continuing the browser-helper path therefore requires both:

1. completing its remaining browser, lifecycle, runtime, and managed-network
   qualification; and
2. proving that the PowerShell process model is acceptable to the target
   endpoint policies.

A desktop coordinator removes the entire browser-control layer and makes the
user's consent more obvious. It is not automatically trusted, but it gives the
project a clearer route to normal application signing, visible operation
ownership, and managed deployment.

## Will This Resolve The Problems?

| Problem | Expected result | Confidence and condition |
| --- | --- | --- |
| Users must type repair/stop/start commands | The launcher can guide and automate the fixed sequence. | High, after functional validation. |
| Users may restart with the wrong engine, GPU mode, or port | The launcher can preserve the current runtime profile. | High, if package/runtime identity checks are retained. |
| Browser needs authority to control Windows | The browser would only direct the user to the launcher. | High; the browser control channel is removed. |
| Extra local helper listener creates review concern | The launcher design does not need that listener. | High for the proposed design. |
| Defender/AMSI may flag the current process pattern | Removing hidden PowerShell and bypass behavior should reduce the risk. | Medium until the signed package passes target-policy testing. |
| Exact one-click repair inside the browser | The proposed design does not provide it. | Deliberate tradeoff. |
| Docker/Podman is not approved on a workstation | The launcher cannot make an unapproved runtime acceptable. | Not solved; this remains an IT prerequisite. |
| Managed network has a different TLS or proxy failure | Only narrowly classified certificate-trust failures should be repaired. | Requires real managed-network validation. |

The most important qualification is that a launcher will **not** solve the
security problem if it merely hides or repackages the same unsigned PowerShell
scripts and execution-policy bypass. The process behavior must actually be
changed, signed, or moved behind an endpoint-policy-approved mechanism.

## Proposed Release Scope

Because the project reaches code complete on September 18 and ends October 31,
the release-oriented launcher scope should be limited to:

1. Start TowerScout.
2. Open TowerScout after readiness succeeds.
3. Show current status.
4. Check the known Google and Azure map connections without provider keys.
5. Explain and confirm a narrowly classified repair.
6. Repair, restart, wait for readiness, and verify the result.
7. Stop TowerScout safely without deleting persistent data, after the repair
   coordinator is proven.

The following should be deferred:

- automatic release discovery or self-update
- Docker, Podman, WSL, virtualization, or Compose-provider installation
- destructive cleanup or volume deletion
- embedded WebView2 browser
- a fully native no-container TowerScout build
- broad diagnostics or evidence export without separate privacy review
- package download and staged installation
- a comprehensive setup wizard outside the existing browser application

Task-058 and Task-059 should be considered deferred under this plan. Task-094
should remain evidence-gated.

## Proposed Proof Sequence

### Gate 1 - Decision And Ownership

- Confirm that the browser-to-launcher handoff is acceptable to product and
  support owners.
- Confirm who owns the code-signing certificate and signing process.
- Confirm the managed deployment path and the endpoint policies that will be
  used for acceptance.
- Record the external helper owner's reuse permission through a clear license
  or written contribution/reuse agreement.
- Select a narrow launcher technology without committing to a larger installer
  platform.

### Gate 2 - Non-Mutating Launcher Proof

- Detect the intended TowerScout package and runtime profile.
- Read readiness and current status.
- Check Google and Azure TLS connectivity without provider keys.
- Produce a fixed repair plan without executing it.
- Demonstrate no listener, arbitrary command, hidden process, policy bypass,
  or sensitive output.
- Prove multiple launcher instances and duplicate clicks cannot start two
  operations.

### Gate 3 - Controlled Repair Proof

- Run only TowerScout-owned fixed operations.
- Show the proposed trust change privately and request exact confirmation.
- Repair and restart the same package/runtime profile.
- Verify readiness and Google/Azure outcomes independently.
- Exercise repair failure, stop failure, start failure, readiness timeout,
  launcher closure, and recovery.
- Preserve the manual fallback.

### Gate 4 - Managed Endpoint And Candidate Qualification

- Sign and timestamp the launcher and any scripts that remain in the normal
  path.
- Validate under the target Defender, AMSI, Attack Surface Reduction,
  application-control, and deployment policies.
- Validate required Docker/Podman and CPU/GPU profiles.
- Validate release manifest, image identity, checksums, provenance, dependency
  inventory, and package contents.
- Validate documentation, rollback, uninstall or package removal, persistent
  data behavior, and owner-operated recovery.

## Schedule Guardrails

| Date | Required decision or outcome |
| --- | --- |
| August 7 | Architecture, guided-handoff, signing-owner, and proof-scope decision |
| August 14 | Selected architecture passes a non-mutating managed-endpoint proof |
| August 21 | Docker CPU managed-network Google/Azure repair evidence |
| August 28 | Task-087 closes or receives an explicit fallback/scope disposition |
| September 4 | Task-096 complete and Task-097 qualification underway |
| September 11 | Required Podman/four-profile blockers resolved or explicitly escalated |
| September 18 | Code complete; no new architecture work |
| September 25 | Feature, package, documentation, external guide, and video complete |
| October 9 | Final candidate frozen; blocker-only changes begin |
| October 16 | Acceptance complete |
| October 23 | Owner-operated handoff rehearsal complete |
| October 30 | Operational closeout |
| October 31 | Hard project end |

These dates are controls, not predictions. If signing, managed-endpoint access,
Podman/GPU availability, or owner review cannot support them, the project must
reduce scope or explicitly accept the command-based fallback rather than allow
the launcher effort to consume qualification and handoff time.

## Specific Questions For The Reviewer

Please challenge both the recommendation and its assumptions. For each concern,
classify it as **release blocker**, **proof requirement**, **acceptable risk**,
or **post-project backlog**.

### User Experience And Accessibility

1. Is directing the user from the browser back to the launcher understandable
   enough for the intended non-technical audience?
2. How should the launcher make the handoff obvious if the window was closed,
   minimized, or opened by another user session?
3. Are there accessibility, keyboard navigation, screen-reader, display-scaling,
   localization, or error-message requirements missing from the proposal?
4. Should TowerScout reopen/focus the browser automatically after repair, or is
   that likely to cause confusing duplicate tabs or session problems?
5. Is **Check/Repair Map Connections** the right user-facing terminology?

### Security And Trust

6. Does the proposed launcher remove enough attack surface, or does direct
   container/certificate control create a different unacceptable boundary?
7. Which operations must remain PowerShell, and which should be implemented in
   the signed launcher to satisfy endpoint policy?
8. Can the normal user path avoid execution-policy bypass entirely?
9. What code-signing, certificate-custody, timestamping, revocation, and key
   rotation controls are required?
10. How should the launcher present certificate information for informed
    consent without leaking it into logs, screenshots, clipboard content, or
    support evidence?
11. Is per-user state sufficient, or is any machine-wide coordination required
    to prevent two users or two package copies from changing the same runtime?
12. Are there unconsidered spoofing risks—for example, another process
    impersonating TowerScout, replacing a package script, or presenting a fake
    repair dialog?

### Windows Deployment And Operations

13. Is a signed one-directory application inside the release ZIP acceptable
    for the next candidate, or is MSI/MSIX/managed Win32 packaging mandatory?
14. Where should writable launcher state live, and what should uninstall or
    package replacement do with it?
15. What happens when TowerScout is installed under a read-only location such
    as `Program Files`?
16. How should upgrades find and safely migrate an existing package, local
    settings, operation state, and persistent container data?
17. What happens when Docker Desktop or Podman requires elevation, a machine
    restart, user sign-in, or administrator action?
18. Does the organization permit Python/PyInstaller applications, or is a
    project-supported .NET technology required?

### Runtime And Recovery

19. How should the launcher prove it is operating on the correct package,
    image digest, Compose project, service, container, port, engine, and GPU
    profile?
20. What recovery state is required if the launcher closes or Windows restarts
    after repair but before TowerScout becomes ready?
21. Should cancellation be permitted after trust material has changed or after
    the container stop has begun?
22. What is the safe fallback if repair succeeds but restart fails?
23. How should Docker and Podman differences be represented without making the
    normal user choose technical details they do not understand?
24. Which tests must run on all four final profiles, and which may be proven
    once at the operation-contract level?

### Provider And Certificate Behavior

25. Is a key-free connection check against the known Google/Azure endpoints an
    adequate TLS-only proof, and how should non-TLS HTTP results be classified?
26. Could an enterprise proxy require authentication or present different
    certificates by user, process, browser, container engine, or network
    location?
27. Could repairing both providers after a failure in one provider create
    unnecessary trust changes or confusing results?
28. What is the correct behavior when certificate selection is ambiguous or
    the expected organization certificate is absent from the Windows stores?
29. Are certificate expiry, rotation, revocation, or organization CA rollover
    scenarios missing from the proposed verification flow?

### Supply Chain, Ownership, And Project End

30. What third-party notices, license terms, contribution records, and source
    provenance are required before reusing external launcher code?
31. Who owns launcher maintenance, signing, release, incident response, and
    endpoint-policy requalification after October 31?
32. Can the cdcai owner independently build, sign, test, and release this
    component after handoff?
33. Which launcher functions should be cut first if the August or September
    gates slip?
34. At what date should the project stop launcher work and accept the manual
    fallback to protect Task-097, qualification, documentation, recovery, and
    handoff?
35. If the new launcher succeeds, should the dormant browser helper be removed
    from release packages, retained disabled for one candidate, or preserved
    only in source history?

## Proposed Stop Rules

Pause the pivot and request an owner decision if any of these occurs:

- No signing owner or endpoint-policy acceptance path is available by the
  architecture decision gate.
- The proof requires antivirus exclusions, security-policy suppression, or
  silent trust changes.
- The launcher cannot identify the exact package/runtime target reliably.
- The approach requires a new installer, updater, embedded browser, or native
  TowerScout runtime to satisfy the first repair use case.
- Docker/Podman or CPU/GPU support would be deferred without owner approval.
- Task-087 remains unresolved after August 28 in a way that threatens
  September 18 code complete.
- Required qualification, documentation, recovery, or owner-handoff work loses
  its reserved schedule margin.

## Requested Reviewer Output

Please return:

1. **Recommendation**: proceed, proceed with conditions, retain the existing
   helper, or use another approach.
2. **Release blockers**: issues that must be solved before implementation or
   candidate inclusion.
3. **Missing proof**: tests or evidence not covered above.
4. **Scope cuts**: features that should be deferred to protect the end date.
5. **Ownership gaps**: signing, deployment, maintenance, support, or handoff
   responsibilities that lack an owner.
6. **Residual risks**: problems the launcher will not solve even if implemented
   correctly.
7. **Recommended decision date**: the latest safe date to commit to or abandon
   the pivot.

## Proposed Disposition Pending Review

Keep all existing Task-087 product activation gates off. Do not run the current
helper on the managed endpoint merely to see whether it triggers an alert. Do
not begin a full installer, updater, WebView2 shell, or no-container build.

Approve only a time-boxed, non-mutating launcher proof after signing ownership,
guided-handoff acceptance, permission to reuse external work, and target
endpoint-policy expectations are known. Require a separate approval before any
certificate change, runtime stop/restart, release packaging, or removal of the
dormant helper.

## Evidence And Privacy Boundary

This follow-up uses sanitized conclusions only. It does not record Defender
messages, local security configuration details beyond the effective restricted
script policy, local file paths, provider keys, helper credentials, certificate
identity, listener ports, raw subprocess output, browser traces, screenshots,
or support logs.

No application, runtime, certificate, provider, container, release, or external
repository state was changed while preparing this review request.
