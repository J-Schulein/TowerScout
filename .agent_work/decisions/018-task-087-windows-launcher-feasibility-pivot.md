# ADR-018: Task-087 Windows Launcher Feasibility Pivot

**Status**: Accepted - time-boxed feasibility decision
**Date**: August 5, 2026
**Decision Owner**: Project lead
**Review Date**: August 14, 2026

## Decision

Authorize a narrow, reversible Task-087 prototype of a visible package-local
Windows launcher/coordinator. The prototype will test whether TowerScout can
provide guided application-provider TLS repair and later support Task-096
Exit/Stop without the dormant browser-to-loopback-helper control plane.

Development may begin before every deployment and signing detail is complete,
but signing-path coordination starts in parallel. Functional success from an
unsigned development build is not release validation. Candidate inclusion
requires the production-shaped package to pass the approved signing and
managed-endpoint security checks.

Keep the Task-086 user-run command repair available throughout the prototype.
Keep all existing browser/helper activation gates off. Place PR #64 on hold:
do not merge, close, discard, or extend its activation path until the August 14
decision records whether evidence should be retained, adapted, or superseded.

## Prototype Boundary

The prototype may implement a thin end-to-end pathway in one selected and
maintainable technology. It should begin with visible, non-mutating status and
repair-preview behavior, then add only the minimum controlled operations needed
to prove feasibility.

The prototype must not:

- bind a new local listener or accept browser-issued host operations
- import or start the dormant Task-087 host helper
- use hidden workers or normal-path PowerShell execution-policy bypasses
- accept arbitrary commands, executable paths, or free-form operation arguments
- expose Docker or Podman control sockets to the application container
- modify the Windows trust store
- remove named volumes or replace the Task-086 manual fallback

Before copying material source from `wcedens/towerscout-windows-helpers`, record
the approved reuse/license basis and preserve required provenance. Its user
flow, tests, and runtime-discovery ideas may inform the prototype, but its
packaging and command-execution choices are not accepted without TowerScout
review.

## Validation Gates

### Functional Gate

- The launcher is visible and limited to fixed TowerScout operations.
- It identifies the exact package, engine, runtime profile, and target before
  proposing an action.
- It provides non-mutating status and TLS repair preview without loading the
  dormant helper.
- It prevents duplicate launcher operations.
- If mutation is exercised after the non-mutating proof, backup, verification,
  recovery, confirmation, and named-volume preservation are demonstrated.

### Operational Security Gate

- Signing ownership and the intended production signing path are known.
- The production-shaped artifact is signed through an organization-approved
  pathway before representative managed-endpoint validation.
- The signed artifact runs without Defender/AMSI exclusions, execution-policy
  bypasses, unusual endpoint-policy changes, or administrator-only setup.
- Packaging, deployment, and maintenance ownership are supportable through the
  October closeout.

An unsigned or self-signed development test can establish functional behavior
or signing mechanics only; it cannot satisfy the operational security gate.

## August 14 Outcomes

1. **Proceed**: Functional and operational security gates pass. Finalize the
   launcher architecture and continue the bounded Task-087 implementation.
2. **Conditional**: Functional proof passes, but approved signing or managed-
   endpoint testing is incomplete. Do not merge or ship the launcher; the
   project lead must set a short final disposition date without moving the
   September/October milestones.
3. **Stop**: Functional behavior fails, endpoint security rejects the signed
   production-shaped artifact, or ordinary use requires unsupported exclusions
   or bypasses. Retain Task-086 as the supported repair path and disposition
   the dormant Task-087 activation work.

## Rationale

Building a narrow prototype now answers functional questions faster than
settling every packaging detail first. Running signing coordination in parallel
avoids confusing an unsigned technical success with proof that the result can
be deployed on its intended managed Windows endpoints.

The separate prototype and unchanged Task-086 fallback make the experiment
reversible and protect the September 18 code-complete and October closeout
dates.

## Impact

- Task-087 changes from “finish the existing loopback helper” to a time-boxed
  launcher feasibility prototype.
- Browser-to-host mutation remains disabled during the prototype.
- Task-096 Stop becomes the preferred first controlled mutation after the
  non-mutating launcher proof passes.
- No released `v0.1.2` asset or `cdcai/TowerScout` state changes.
- The four-profile runtime requirement and existing final milestones do not
  move.

## Review

Review on August 14, 2026, or earlier if a functional or endpoint-security
failure makes the outcome clear. If the result is conditional, record the
short final disposition date and owner explicitly rather than allowing the
uncertainty to drift into September.
