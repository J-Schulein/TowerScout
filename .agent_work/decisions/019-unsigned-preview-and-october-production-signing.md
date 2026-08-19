# ADR-019: Unsigned Preview Iteration And October Production Signing

**Status**: Accepted
**Date**: August 19, 2026
**Decision Owner**: Project lead
**Review Date**: At Task-100 start and no later than October 16, 2026
**Supersedes In Part**:
[`ADR-018`](./018-task-087-windows-launcher-feasibility-pivot.md)

## Decision

Refine TowerScout through explicitly unsigned fork-side preview releases before
spending effort on production signing. Complete signing and representative
managed-endpoint qualification as the separately tracked `TASK-100` in
October, after the project lead records that the release package is
satisfactory.

The release identities and boundaries are:

1. Keep the published `v0.1.2` pilot bytes immutable.
2. Publish iterative packages only as immutable GitHub **prereleases** named
   `v0.1.3-preview.N` from `J-Schulein/TowerScout`. Do not mark them `Latest`.
3. Label every preview as unsigned, not production-approved, and not qualified
   for managed endpoints. Limit execution to explicitly approved unmanaged
   clean Windows test machines; never instruct a tester to disable Defender,
   SmartScreen, application control, or other security controls.
4. Keep all existing `Task-087-validation-<short-SHA>` artifacts
   validation-only. A preview must be a newly assembled normal-user package;
   no existing validation ZIP may be renamed, retagged, or uploaded.
5. Permit normal technical/security review, source merge, preview-package
   integration, and clean-machine feedback before production signing. Passing
   those gates is not evidence that the package is accepted on a managed
   endpoint.
6. Reserve `v0.1.3-rc.N` for the production-shaped **signed** candidate line.
   No unsigned package may use an RC identity.
7. Rebuild the official cdcai image and package under the owner-selected final
   identity; do not rename preview or candidate ZIPs.

## Satisfactory Release Package Gate

Task-100 may start only in October and only after the project lead records that
the unsigned package is satisfactory. That decision requires:

- a normal release-package path that includes the launcher and intended
  end-user entry points, rather than the Task-087 validation assembler;
- exact committed source, a fresh digest-pinned image, complete manifests and
  SHA-256 checksums, required assets, and current source/SBOM/third-party notice
  material;
- accurate preview release notes, installation instructions, unsigned-warning
  guidance, supported-profile boundaries, and troubleshooting;
- a test of the actual GitHub download, extraction, setup, launch, provider,
  detection/export, persistence, TLS repair, recovery, status, and stop path on
  an approved clean unmanaged Windows machine;
- required runtime/profile qualification completed, or every remaining
  limitation explicitly accepted and documented; and
- no unresolved blocker that would predictably change the package's executable
  or normal user-facing launch surface after signing.

Preview releases may precede this gate so normal-user feedback can refine the
package. Each preview records its own narrower tested scope and known limits.

## Task-100 October Scope

`TASK-100: Production Signing And Managed-Endpoint Qualification` is required
after the satisfactory-package decision and before final candidate acceptance
or official cdcai publication. Its scope is to:

1. Confirm the approved signing service, authorized operator, certificate/key
   custody, timestamp service, and revocation/rotation procedure.
2. Decide the signed-file boundary for the launcher and any project-owned
   scripts or binaries that remain in the normal user path. Remove, redesign,
   or explicitly disposition normal-path execution-policy bypass behavior that
   representative endpoint policy will not accept.
3. Build from the accepted clean source in a controlled Windows build job,
   sign and timestamp before final archive assembly, then generate the final
   manifest and checksums from the signed bytes.
4. Verify required signatures after packaging and after clean extraction;
   preserve source, image-digest, dependency, SBOM, notice, and checksum
   provenance without recording sensitive certificate identifiers.
5. Run the signed production-shaped package under representative Defender,
   AMSI, ASR, SmartScreen/reputation, and application-control policy without
   exclusions, bypasses, or unusual endpoint-policy changes.
6. Build and name the signed package as `v0.1.3-rc.N`, qualify those exact
   bytes, and publish/freeze the candidate only after the Task-100 gates pass.
   Document any accepted endpoint boundary and hand the reproducible
   signing/release procedure to the cdcai owner.

Target Task-100 completion is the October 16 acceptance milestone. October 9
remains the blocker-only source/package freeze; signing changes package bytes
and hashes by design but must not introduce unreviewed product behavior.

## Rationale

Unsigned previews let the project evaluate the package as a normal user would
and make inexpensive iterative corrections before each signature would have to
be regenerated. Deferring the production signature also lets the cdcai owner
participate in the final identity and custody decisions.

A separate October task keeps signing visible as required work instead of an
informal handoff note. It also preserves time to discover PyInstaller,
PowerShell, SmartScreen, or application-control incompatibilities before the
October 23 owner rehearsal and October 30 closeout.

## Impact

- Task-087 can proceed through review, merge, and unsigned preview-package
  integration without claiming managed-endpoint readiness.
- Existing validation artifacts and evidence retain their original meaning.
- Preview and signed-candidate identities cannot be confused or reused.
- Signing is not repeated for each refinement cycle, but the first signed
  production-shaped proof remains a required project deliverable in October.
- `cdcai/TowerScout` remains unchanged until qualification and explicit owner
  adoption approval.

## Review

Reconfirm the satisfactory-package evidence, signing owner/service access, and
October schedule when Task-100 is selected. If Task-100 cannot complete by the
acceptance milestone, do not describe any preview as production-signed or
managed-endpoint-qualified; record the blocker and rebaseline adoption before
any official cdcai release.
