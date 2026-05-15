# TASK-076: Provider API Key Exposure And Restriction Policy

**Status**: POLICY_DECISION_RECORDED - Task-071 docs integrated; Task-066 validation pending
**Priority**: HIGH
**Type**: C (Security / Release Policy)
**Estimated Effort**: 0.5-1.5 days (4-12 hours)
**Target Sprint**: Sprint 06 V1 RC1

## Objective

Record the V1 RC1 provider-key policy for TowerScout's Google Maps and Azure Maps integrations, including the known browser-visible map SDK key behavior, accepted pilot support boundary, required provider-side restrictions, and conditions that turn the issue into an engineering blocker.

This task is a release-policy decision, not a code redesign for V1 RC1. The current local pilot can proceed only if provider keys are site/user-owned and restricted. A shared unrestricted TowerScout project key is unsupported.

## Requirements (EARS Notation)

**R-076-001**: WHEN TowerScout uses Google Maps or Azure Maps browser SDKs, THE PROJECT SHALL document that browser map SDK keys are client-visible by provider design and can be inspected by someone with access to the running browser app.

**R-076-002**: WHEN V1 RC1 is distributed to pilot users, THE PROJECT SHALL require site/user-owned provider keys unless a separate owner-approved exception is recorded.

**R-076-003**: WHEN provider-key guidance is included in end-user docs, THE DOCUMENTATION SHALL state that unrestricted shared project keys are unsupported for V1 RC1.

**R-076-004**: WHEN pilot users configure provider keys, THE DOCUMENTATION SHALL instruct them to apply provider-side restrictions, quotas, billing alerts, usage monitoring, and key rotation according to their site policy.

**R-076-005**: WHEN Google Maps keys are used, THE DOCUMENTATION SHALL recommend separate restricted keys where practical and require Google-side application/API restrictions for the APIs TowerScout uses.

**R-076-006**: WHEN Azure Maps subscription keys are used, THE DOCUMENTATION SHALL state that shared-key authentication is acceptable for the local V1 RC1 pilot only with site/user-owned keys, rotation, monitoring, and quota controls.

**R-076-007**: IF a project-owned shared provider key is required for pilot or broader distribution, THEN THE TASK SHALL become an engineering blocker until stronger controls are implemented or explicitly risk-accepted by the owner.

**R-076-008**: WHEN broader or hosted distribution is planned, THE PROJECT SHALL revisit stronger provider-auth options, including separate browser/server keys, server-side proxying where compatible with provider terms, and Azure Entra ID or SAS-token authentication.

## Acceptance Criteria

- [x] V1 RC1 policy decision is recorded: browser-visible map SDK keys are accepted only for the local pilot with site/user-owned restricted keys.
- [x] Shared unrestricted TowerScout project keys are recorded as unsupported.
- [x] Required mitigations are recorded: provider restrictions, API scoping, quotas, billing alerts, monitoring, and rotation.
- [x] Future hardening options are recorded for broader or hosted distribution.
- [x] Task-071 end-user docs include the approved provider-key policy language.
- [ ] Task-066 release-candidate validation confirms the pilot key ownership/restriction assumption or records a blocker.

## Dependencies

- Current setup/settings behavior and provider-loading routes:
  - `/getgooglekey` returns the Google Maps browser key for dynamic Maps JavaScript SDK loading.
  - `/getazurekey` returns the Azure Maps subscription key for Azure Maps Web SDK initialization.
  - Settings/status responses mask key previews, but browser SDK keys remain inspectable in client traffic.
- `TASK-071`: end-user release package documentation must consume this policy.
- `TASK-066`: release-candidate validation must verify the key-ownership assumption.
- `TASK-069`: AGPL/source release policy does not change Google or Azure provider/API obligations.
- Provider references:
  - Google Maps Platform security guidance: https://developers.google.com/maps/api-security-best-practices
  - Azure Maps authentication best practices: https://learn.microsoft.com/en-us/azure/azure-maps/authentication-best-practices
  - Azure Maps authentication options: https://learn.microsoft.com/en-us/azure/azure-maps/azure-maps-authentication

## Policy Decision

For V1 RC1, TowerScout accepts the current browser-visible map SDK key behavior only under the following release boundary:

- The release is a local Windows pilot path, not a public hosted service.
- Provider keys are owned by the pilot site or user, not by a shared TowerScout project account.
- Users/sites restrict keys in the provider console, enable only the needed APIs/services, set quota and billing controls, monitor usage, and rotate keys if misuse is suspected.
- End-user docs state that anyone with access to the running browser app may be able to inspect browser map SDK keys.
- Support docs state that provider keys, `.env` files, screenshots, browser network traces, logs, cached provider responses, and exported investigation data are sensitive local material and must not be shared unless a site-specific support procedure approves it.

If the pilot requires TowerScout to provide a shared project-owned key, V1 RC1 should not broaden distribution under the current implementation. The project must first implement stronger controls, obtain explicit owner-approved risk acceptance, or narrow the pilot to a controlled internal environment where the exposure is accepted.

## Implementation Plan

1. Add the approved policy language to Task-071 quick start/package guide/user guide work.
2. Ensure provider setup docs cover:
   - site/user-owned key expectation
   - browser-visible SDK key caveat
   - no unrestricted shared project key support
   - Google application/API restrictions
   - Azure shared-key rotation/monitoring and future Entra/SAS option
   - quota, billing alert, and usage monitoring expectations
3. Update Task-066 validation checklist to confirm the key ownership/restriction assumption before external UAT.
4. Keep code changes out of V1 RC1 unless validation shows the accepted policy cannot be met.
5. Add future hardening work for broader/hosted distribution if the release model changes.

---

## Implementation Log

### 2026-05-14 - Provider-Key Policy Decision Recorded
**Objective**: Capture the approved Task-076 V1 RC1 policy for browser-visible Google/Azure map SDK keys.
**Context**: TowerScout masks stored keys in settings/status flows, but the current browser SDK integrations must provide usable Google and Azure map credentials to the client so the map SDKs can initialize. The accepted pilot assumption is that provider keys are site/user-owned.
**Decision**: Accept browser-visible map SDK keys for the V1 RC1 local pilot only with site/user-owned restricted keys, provider-side quota/billing/monitoring controls, and clear documentation. Treat shared unrestricted project-owned keys as unsupported and potentially release-blocking.
**Execution**: Created this Task-076 policy artifact and linked it to Task-071 documentation and Task-066 validation follow-through.
**Output**: Policy decision, requirements, acceptance criteria, dependencies, mitigations, and future hardening path are documented.
**Validation**: `.agent_work` validation and whitespace checks passed after related task-tracking updates. Sensitive-term scan completed with expected existing environment-variable and local `.env` matches; no new secret values were added by this task.
**Next**: Integrate this policy into Task-071 user docs and Task-066 release-candidate validation.

### 2026-05-15 - Task-071 Docs Integration Completed
**Objective**: Record that Task-071 consumed the approved Task-076 provider-key policy language.
**Context**: Task-071 now documents browser-visible map SDK keys, site/user-owned restricted key expectations, unsupported unrestricted shared TowerScout project keys, Google API/application restrictions, Azure shared-key monitoring/rotation, and provider-side quotas, billing alerts, monitoring, and rotation.
**Decision**: Mark Task-071 docs integration complete while keeping Task-066 validation open until the release-candidate path confirms the pilot key ownership/restriction assumption.
**Execution**: Updated Task-076 status and acceptance criteria after the Task-071 documentation commits.
**Output**: Policy decision remains recorded, docs integration is complete, and validation remains gated on Task-066.
**Validation**: Pending `.agent_work` validation after this status update.
**Next**: Confirm the site/user-owned restricted-key assumption during Task-066 or record a release blocker.

---

## Validation Results

### Test Summary
**Test Date**: 2026-05-14
**Test Environment**: Windows workspace, PowerShell
**Test Status**: PASS for task-tracking structure and whitespace; sensitive-term scan reviewed

### Acceptance Criteria Validation
- [x] V1 RC1 policy decision recorded - PASS: this task file.
- [x] Shared unrestricted project keys unsupported - PASS: policy decision section.
- [x] Required mitigations recorded - PASS: requirements and implementation plan.
- [x] Future hardening options recorded - PASS: R-076-008 and implementation plan.
- [x] Task-071 docs integration - PASS: quick start, package guide, user guide, Project Overview, and provider terms include the approved policy language.
- [ ] Task-066 validation integration - PENDING.

### Issues Identified

Sensitive-term scan reports existing environment-variable references and local `.env`/backup matches outside this documentation change. This update did not add real provider keys, raw logs, screenshots, browser traces, or support artifacts.

### Remediation Actions

None yet.

### Sign-off

Policy decision recorded. Final release sign-off remains pending Task-066 validation.
