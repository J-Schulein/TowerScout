# TASK-087 Activation Validation Isolation - 2026-07-31

## Purpose

Define the workstation-isolation contract for the remaining Task-087 live
validation. The goal is to prove that provider setup, TLS repair, restart, and
browser recovery use the candidate under test rather than configuration,
certificates, assets, sessions, caches, helper state, or images retained from
an older TowerScout run.

This inventory was read-only. It did not inspect provider keys, helper tokens,
certificate details, uploaded data, or private application content, and it did
not remove any runtime or filesystem state.

## Workstation Inventory

- Docker Desktop is running; its client/engine report 29.5.3 and Docker
  Compose reports 5.1.4.
- Docker has one unrelated healthy TowerScout release project running on host
  port 5005. It uses project name `extracted-cpu` and must remain untouched.
- Docker retains eight TowerScout Compose volume sets, each with the standard
  config, model, data, log, Flask-session, session-temp, upload, and cache
  volumes. No volume name matched Task-087, PR 63, Gate 3, or the re-review
  project names.
- Docker retains multiple older TowerScout images and build-cache layers.
  Those objects do not carry runtime configuration, but an unverified mutable
  image tag could select old application code.
- The running Podman WSL machine has no containers. It retains two older
  TowerScout CPU volume sets and two untagged TowerScout images.
- The workstation has several older portable source/build trees, extracted
  release-validation folders, and v0.1.0-v0.1.2 control and asset ZIPs.
  TowerScout has no Windows uninstall-registry entry; these are portable files,
  not a system-installed application.
- The repository root has a local `.env` and one historical helper
  `launch-profile.json`. No Task-087 helper process is running. The prior PR 63
  worktree's helper-state directory is empty.
- No Task-087 browser-profile directory was found in the Windows temporary
  directory. The committed Edge observer creates a unique temporary profile.
- The new `feature/task-087-activation-readiness` worktree starts without a
  local `.env`, staged `assets`, helper runtime state, webapp config, cache,
  temp, or log directory.

## Contamination Decision

A workstation-wide purge is not required and would risk deleting unrelated
or user-owned data. The old resources must instead be excluded by identity and
confirmed absent from the validation path.

The following state can produce a false pass if reused and therefore must be
isolated:

- Compose config volumes, because they can retain provider configuration and a
  previously imported TLS CA bundle.
- Compose model and data volumes, because they can make asset readiness pass
  without a candidate asset import.
- Session, upload, temp, and cache volumes, because they can retain browser or
  application workflow state.
- Package `.env` files, because they select the image, digest, project name,
  TLS bundle paths, and runtime behavior.
- Package-local `.towerscout-runtime` state, because it binds the helper to a
  package identity, runtime profile, and live authorization session.
- Browser profiles, because local/session storage and cached frontend files
  can preserve state across runs.
- Mutable or ambiguous image tags, because they do not prove which source tree
  is running.
- Asset ZIPs placed beside a package, because first setup can discover a local
  bundle automatically. Only the release-manifest-selected filename and
  checksum are valid for candidate qualification.

The following existing state does not need to be deleted when the isolation
contract below is followed:

- Older portable package folders and release archives.
- Docker or Podman images not referenced by the test package.
- Docker build cache, provided the activation image is built from the exact
  worktree without cache or the candidate uses an immutable published digest.
- Old named volumes whose project names do not match the validation project.
- The unrelated running `extracted-cpu` project on port 5005.
- Enterprise certificates already managed in the Windows trust store. The
  Task-087 repair must copy only the selected CA material into the new
  container config volume; it must not remove or replace enterprise host
  trust.

## Required Preflight

For each Docker or Podman scenario:

1. Start from a clean worktree at the reviewed activation commit and record
   that full commit id.
2. Use a new lowercase Compose project name in the form
   `towerscout-task087-<engine>-<run-id>`. Confirm there are no containers,
   networks, or volumes with that exact project label before launch.
3. Use a checked, nonconflicting loopback port. Do not use port 5005 while the
   unrelated release project is running.
4. Use a clean package or worktree root with no pre-existing `.env`, `assets`,
   `.towerscout-runtime`, webapp config, cache, temp, or log state.
5. Build the pre-candidate activation image from that exact worktree with a
   unique tag, `--pull`, `--no-cache`, and OCI revision metadata. For a real
   release candidate, use the immutable digest recorded by the control
   package instead. Record and verify the running image id/revision or digest.
6. Launch with the explicit project name, image identity, runtime, GPU mode,
   and host port. Verify the container's Compose project/service labels and
   its eight volume names before continuing.
7. Use a newly created browser profile. Reuse that profile only inside the
   one scenario that intentionally proves stop/restart or sleep/resume state
   preservation.
8. Prove the clean baseline before repair: no provider setup is retained, no
   Task-087 helper session exists before launch, and readiness does not claim
   candidate assets were imported before the candidate import step.
9. When asset qualification is in scope, stage only the candidate control ZIP,
   its checksum, the release-manifest-selected asset ZIP, and its checksum in a
   fresh validation directory. Run import with hash verification.
10. Capture only sanitized state transitions, image/project identities, exit
    classifications, and pass/fail results. Do not capture provider keys,
    helper credentials, certificate details, raw provider responses, uploads,
    or environment dumps.

## Post-Run Rule

Preserve the isolated project only while a restart/sleep persistence scenario
is active. After sanitized evidence is complete, stop the exact helper and
Compose project, verify their identities again, and remove only that run's
container, network, named volumes, temporary browser profile, package-local
helper state, staged assets, and unique local test image. Re-inventory Docker
and Podman afterward and confirm the unrelated `extracted-cpu` project remains
healthy.

Any removal requires the exact project/path targets to be reviewed before it
runs. Broad commands such as Docker/Podman system prune, unscoped volume
pruning, or recursive deletion of a general TowerScout directory are not part
of this plan.
