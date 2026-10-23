# Release and maintenance boundaries

TowerScout is a local single-user Windows application. Build from one accepted source revision and retain its exact identity.
CPU and CUDA 12.8 images must be separately identified and digest-pinned in their control packages.
Keep all nine required destination checks and review conversations satisfied before merge.

## Supported installation and qualification

The Windows control package is unsigned. See [the unsigned-package decision](adr/023-unsigned-windows-package-support-boundary.md).
Use an ordinary account and verify authoritative published hashes before extracting browser-downloaded packages.
Podman requires a short extraction path (package root at most 80 characters) and explicitly selected 64-bit Python 3.12.
The 80-character restriction still requires an actual installation at that limit
with the corrected candidate; a shorter-path test does not establish it.
CPU-only hardware, Podman without Docker Desktop installed, rootful Podman and signature-enforcing endpoints are unqualified.
For Podman testing, close Docker Desktop and verify the intended Podman machine and package-selected Compose provider.

The supported HTTP path uses `localhost` or `127.0.0.1` with the selected port,
on the package's IPv4 loopback binding. IPv6 literal hosts are rejected and are
not qualified. The exact Host allowlist, foreign-Origin, cross-site and same-site checks
reduce DNS-rebinding/browser request exposure; they are not authentication or
protection against same-origin script execution or other local software.

Official artifacts still require fresh qualification. Run core checks in all four engine/device profiles on both Windows NVIDIA hosts:
exact downloads, setup/import, both real models on the required device, Google and Azure workflows, review visibility and stop/relaunch.
Run full export/restore, cancellation/retry and recoverable-error workflows on first-host Docker CPU and Podman CUDA,
and independent-host Docker CUDA and Podman CPU. Reboot both hosts and verify all four installations with safe engine switching.
Compare final CPU/CUDA combined-model outputs and dependency-sensitive decode/preprocessing on the first host.
GPU fallback to CPU is a failure. Expand affected coverage after relevant changes or failures.

## Security and publication

Retain the unchanged 396-key security baseline. The October 22 owner-approved renewal retains only four existing exact residual identities in `.github/security/task103-accepted-residuals.v1.json`; the resolved Expat entry is removed.
The project owner owns the renewed acceptance and TASK-107 review, with a hard expiry of January 31, 2027 at 23:59:59 UTC.
Review weekly, immediately when a fix or relevant exposure/identity change appears, and again during the week of January 25. Remove resolved entries and requalify affected artifacts; do not automatically retain exceptions until expiry or extend them beyond it.
The project owner separately approved eight exact CVE-2026-53615 Debian 12 records through **November 5, 2026 at 23:59:59 UTC**, with TASK-107 weekly and immediate-change review. This earlier deadline is independent of the January renewal and blocks publication when it expires. See [the dependency disposition](security/dependency-security-disposition.md) for the exact records and controls. Neither approval authorizes publication or substitutes for final qualification.
Scan locally before registry login/push, then verify identity and rescan the exact published digest. New findings and unused/expired residuals fail closed.
Initial validation publication stays non-Latest. Recommendation and promotion require separate authorization after qualification.
Before stable/Latest promotion, prepare and review a path that promotes the exact
qualified digest. A new build with the same source is not the qualified artifact.
Configure the `official-release` environment with independent required reviewers, self-review prevention,
and a custom deployment branch policy allowing only `main`. The publishing preflight reads these settings
and fails before building if the environment or protections are missing. Verify administrator bypass policy
and assign workflow/security code ownership through the receiving owner's approved repository settings.
Supply the exact approved main SHA as `source_sha` at dispatch; the workflow rejects a different source.
Publication after expiry requires a valid new decision or remediation; expiry does not disable installed copies.
The torch 2.10.0/torchvision 0.25.0 bridge needs review by January 31, 2027 or earlier on its security/compatibility triggers.
The receiving maintainer owns advisory monitoring, qualification and future release decisions after handoff.

## Source and evidence

The adoption is a curated snapshot based on cdcai main, derived from reviewed fork commit
`724e619fcca6535d09f83dc1d897b41f2e230ae3`. Retained team and upstream credits and historical source access accompany the proposal.
Rights for project-controlled material outside the explicit application grant,
and the historical advisor-credit/privacy disposition, remain review items.
Do not push old fork branches/tags into cdcai. The incoming private planning archive is excluded.
Keep sanitized public evidence separate from restricted raw records. Source review does not qualify newly built artifacts.
Preserve corresponding-source references, licenses and model/data/provider notices. Public-distribution rights remain a release prerequisite.
Dataset export is not a full backup of configuration or named volumes. Use volume-preserving recovery instructions.
Dataset restore permits at most 1,000 ZIP members, 64 MiB per member and 512 MiB total expanded bytes.
Failed restores retain the current review and export inputs. CSV includes all rows with selection and threshold flags;
KML includes selected visible results using the UI primary/secondary threshold.
Training datasets include selected above-threshold annotations across each full
tile, including outside-boundary results. Review full images before training;
unlabeled tiles are not verified negative examples.
CSV text that could be interpreted as a formula is prefixed with an apostrophe. CSV uses a UTF-8 marker for Excel.

Custom-image uploads use server-generated names and are served only to the owning
session. A successful replacement removes only that session's previous generated
image; failed processing removes only its newly created file. Reload retains the
last image and map export inputs. Abandoned-session and legacy uploads are retained
for deliberate owner cleanup after backup/retention review; there is no blanket
startup deletion or volume cleanup. Browser cookies identify the session.
