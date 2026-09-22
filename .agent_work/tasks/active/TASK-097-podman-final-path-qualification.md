# TASK-097: Podman CPU/GPU Final Path Qualification

**Status**: SELECTED - W01 prerequisite inventory active
**Priority**: HIGH
**Type**: C (Runtime Qualification)

## Objective

Qualify the exact release package on Podman CPU and NVIDIA GPU without Docker
Desktop, using the approved Compose provider and intended Podman target.

## Requirements

- WHEN Podman is selected, THE PACKAGE SHALL use the intended machine,
  connection, and rootful/rootless mode or fail before mutation.
- WHEN Podman GPU is qualified, THE SYSTEM SHALL execute both models on CUDA
  through the intended WSL2/NVIDIA CDI path with no CPU fallback.
- WHEN the approved Compose provider is installed, THE USER SHALL need Python
  but not Git, Node, a source checkout, or a development environment.

## Acceptance Boundary

W01 records actual machine/provider/Python/CDI availability. W03 addresses only
reproduced targeting/process-boundary defects. W09/W10 qualify the exact ZIPs,
digests, asset bundle, providers, persistence, recovery, and independent host.
