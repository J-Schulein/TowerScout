(function () {
  'use strict';

  let currentStep = 1;
  let validatedKeys = {
    google: false,
    azure: false
  };
  let validationInFlight = false;
  let saveInFlight = false;
  const TLS_REPAIR_CATEGORIES = new Set([
    'tls_ca_untrusted',
    'tls_bundle_missing',
    'tls_bundle_unusable'
  ]);
  const PROVIDER_TLS_REPAIR_CONFIRMATION = 'repair_tls_and_restart';
  const PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED = false;
  const PROVIDER_TLS_REPAIR_OPERATION_ENDPOINT = '/operations/provider-tls-repair';
  const PROVIDER_TLS_REPAIR_STATUS_AUTHORIZATION_ENDPOINT = '/api/config/provider-tls-repair-status-authorization';
  const PROVIDER_TLS_REPAIR_ACTIVE_OPERATION_STORAGE_KEY = 'towerscout.providerTlsRepair.activeOperation';
  const PROVIDER_TLS_REPAIR_POLL_INTERVAL_MS = 1000;
  const PROVIDER_TLS_REPAIR_POLL_TIMEOUT_MS = 15 * 60 * 1000;
  const PROVIDER_TLS_REPAIR_ALLOWED_START_BODY_FIELDS = Object.freeze([
    'provider',
    'confirmation',
    'operation_authorization'
  ]);
  const PROVIDER_TLS_REPAIR_DISALLOWED_START_BODY_FIELDS = Object.freeze([
    'command',
    'repair_command',
    'script',
    'script_path',
    'engine',
    'gpu',
    'port',
    'app_port',
    'runtime',
    'restart_mode',
    'podman_provider',
    'provider_path',
    'install_dir',
    'python_path',
    'arguments',
    'helper_token',
    'durable_token'
  ]);
  const PROVIDER_TLS_REPAIR_STATUS_CLASSIFICATIONS = new Set([
    'pending',
    'active',
    'intermediate_success',
    'terminal_success',
    'terminal_timeout',
    'terminal_support_escalation',
    'retryable_failure_with_support_review',
    'rejected',
    'unknown'
  ]);
  const PROVIDER_TLS_REPAIR_NEXT_ACTIONS = new Set([
    'await_controlled_execution',
    'poll_existing_operation',
    'continue_to_runtime_stop',
    'continue_to_runtime_start',
    'retry_provider_validation',
    'review_runtime_state_before_retry',
    'use_startup_fallback_guidance',
    'clear_or_reauthorize_after_timeout',
    'use_manual_dry_run_support_selection',
    'use_manual_tls_repair_fallback',
    'use_manual_start_fallback',
    'use_status_and_log_guidance',
    'new_authorization_required',
    'support_review_required'
  ]);
  const providerNames = ['google', 'azure'];
  let providerValidationState = createEmptyProviderValidationState();
  let activeProviderTlsRepairProvider = null;
  let providerTlsRepairStartInFlight = false;
  let providerTlsRepairOperationStatus = null;
  let providerTlsRepairPollingPromise = null;
  const fetchJson = window.TowerScoutConfigApi.fetchJson;
  const providerFailureMessage = window.TowerScoutConfigApi.providerFailureMessage;
  const saveFailureMessage = window.TowerScoutConfigApi.saveFailureMessage;

  function createEmptyProviderValidationState() {
    return {
      google: {
        lastResult: null,
        lastFailure: null
      },
      azure: {
        lastResult: null,
        lastFailure: null
      }
    };
  }

  function getWizardElement() {
    return document.getElementById('setup_wizard_div');
  }

  function getSelectedDefaultProvider() {
    const selected = document.querySelector('input[name="default_provider"]:checked');
    return selected ? selected.value : 'azure';
  }

  function normalizeProviderTlsRepairBaseUrl(value) {
    const text = String(value || '').trim();
    const match = text.match(/^http:\/\/(?:127\.0\.0\.1|localhost):(\d{1,5})$/i);
    if (!match) {
      return '';
    }
    const port = Number(match[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? text.replace(/\/+$/, '') : '';
  }

  function normalizeProviderTlsRepairCredential(rawCredential, expectedScope) {
    if (!rawCredential || typeof rawCredential !== 'object') {
      return null;
    }
    const scope = String(rawCredential.scope || '').trim();
    const expiresAt = String(rawCredential.expires_at || rawCredential.expiresAt || '').trim();
    const authorization = String(
      rawCredential.authorization ||
      rawCredential.operation_token ||
      rawCredential.token ||
      ''
    ).trim();
    if (scope !== expectedScope || !expiresAt || !authorization) {
      return null;
    }
    return {
      scope,
      expires_at: expiresAt,
      authorization
    };
  }

  function normalizeProviderTlsRepairBridge(payload, details) {
    const rawBridge = payload.helper_bridge || details.helper_bridge || null;
    if (!rawBridge || typeof rawBridge !== 'object') {
      return null;
    }
    const baseUrl = normalizeProviderTlsRepairBaseUrl(rawBridge.base_url);
    const rawProbe = rawBridge.probe || {};
    const probe = normalizeProviderTlsRepairCredential(rawProbe, 'helper_probe');
    const operationAuthorization = normalizeProviderTlsRepairAuthorization(
      { operation_authorization: rawBridge.operation_authorization },
      {}
    );
    if (
      !baseUrl ||
      !probe ||
      rawProbe.path !== '/health'
    ) {
      return null;
    }
    return {
      base_url: baseUrl,
      probe: {
        ...probe,
        path: '/health'
      },
      operation_authorization: operationAuthorization,
      provider_tls_repair_capability: rawBridge.provider_tls_repair_capability === true
    };
  }

  function normalizeProviderValidationResult(provider, payload = {}) {
    const details = payload.details || {};
    const category = payload.category || details.category || null;
    const repairable = (
      payload.repairable === true ||
      details.repairable === true ||
      (category !== null && TLS_REPAIR_CATEGORIES.has(category))
    );
    const helperAvailable = payload.helper_available === true || details.helper_available === true;
    const helperBridge = repairable ? normalizeProviderTlsRepairBridge(payload, details) : null;
    const operationAuthorization = normalizeProviderTlsRepairAuthorization(payload, details);

    return {
      provider: payload.provider || details.provider || provider,
      valid: payload.valid === true,
      message: payload.message || payload.technical_message || payload.error || 'Validation failed.',
      category,
      repairable,
      support_action: payload.support_action || details.support_action || null,
      repair_command: payload.repair_command || details.repair_command || null,
      helper_available: repairable && helperAvailable,
      operation_authorization: repairable && helperAvailable ? operationAuthorization : null,
      helper_bridge: repairable ? helperBridge : null,
      status_code: payload.status_code || details.status_code || payload.status || null
    };
  }

  function normalizeProviderTlsRepairAuthorization(payload, details) {
    const rawAuthorization = payload.operation_authorization || details.operation_authorization || null;
    if (!rawAuthorization || typeof rawAuthorization !== 'object') {
      return null;
    }

    const operationType = rawAuthorization.operation_type || rawAuthorization.operationType || '';
    const expiresAt = rawAuthorization.expires_at || rawAuthorization.expiresAt || '';
    const token = rawAuthorization.operation_token || rawAuthorization.token || rawAuthorization.authorization || '';

    if (operationType !== 'provider_tls_repair' || !expiresAt || !token) {
      return null;
    }

    return {
      operation_type: 'provider_tls_repair',
      expires_at: String(expiresAt),
      operation_token: String(token)
    };
  }

  function cloneValidationRecord(record) {
    if (!record) {
      return null;
    }

    const cloned = { ...record };
    if (cloned.operation_authorization) {
      cloned.operation_authorization = {
        operation_type: cloned.operation_authorization.operation_type,
        expires_at: cloned.operation_authorization.expires_at
      };
    }
    if (cloned.helper_bridge) {
      cloned.helper_bridge = {
        base_url: cloned.helper_bridge.base_url,
        configured: true,
        provider_tls_repair_capability: (
          cloned.helper_bridge.provider_tls_repair_capability === true
        )
      };
    }
    return cloned;
  }

  function rememberProviderValidationResult(provider, payload) {
    if (!providerNames.includes(provider)) {
      return normalizeProviderValidationResult(provider, payload);
    }

    const normalized = normalizeProviderValidationResult(provider, payload);
    providerValidationState[provider] = {
      lastResult: normalized,
      lastFailure: normalized.valid ? null : normalized
    };
    renderProviderTlsRepairState();
    return normalized;
  }

  function rememberProviderValidationResults(validationResults = {}) {
    providerNames.forEach(provider => {
      if (validationResults[provider]) {
        rememberProviderValidationResult(provider, validationResults[provider]);
      }
    });
  }

  function clearProviderValidationState(provider) {
    if (providerNames.includes(provider)) {
      providerValidationState[provider] = {
        lastResult: null,
        lastFailure: null
      };
      if (providerTlsRepairOperationStatus && providerTlsRepairOperationStatus.provider === provider) {
        providerTlsRepairOperationStatus = null;
        providerTlsRepairStartInFlight = false;
      }
      renderProviderTlsRepairState();
    }
  }

  function resetProviderValidationState() {
    providerValidationState = createEmptyProviderValidationState();
    providerTlsRepairOperationStatus = null;
    providerTlsRepairStartInFlight = false;
    renderProviderTlsRepairState();
  }

  function getProviderValidationState(provider) {
    const state = providerValidationState[provider] || {
      lastResult: null,
      lastFailure: null
    };
    return {
      lastResult: cloneValidationRecord(state.lastResult),
      lastFailure: cloneValidationRecord(state.lastFailure)
    };
  }

  function getProviderValidationFailure(provider) {
    const state = providerValidationState[provider] || {};
    return state.lastFailure || null;
  }

  function shouldShowProviderTlsRepair(provider) {
    const failure = getProviderValidationFailure(provider);
    return Boolean(
      failure &&
      failure.repairable === true &&
      TLS_REPAIR_CATEGORIES.has(failure.category)
    );
  }

  function providerDisplayName(provider) {
    if (provider === 'google') {
      return 'Google Maps';
    }
    if (provider === 'azure') {
      return 'Azure Maps';
    }
    return provider || 'provider';
  }

  function hasCurrentProviderTlsRepairAuthorization(record, now = Date.now()) {
    const authorization = record && record.operation_authorization;
    if (!authorization || authorization.operation_type !== 'provider_tls_repair') {
      return false;
    }
    if (!authorization.operation_token) {
      return false;
    }

    const expiresAtMs = Date.parse(authorization.expires_at);
    if (!Number.isFinite(expiresAtMs)) {
      return false;
    }

    return expiresAtMs > now;
  }

  function hasCurrentProviderTlsRepairCredential(credential, now = Date.now()) {
    if (!credential || !credential.authorization) {
      return false;
    }
    const expiresAtMs = Date.parse(credential.expires_at);
    return Number.isFinite(expiresAtMs) && expiresAtMs > now;
  }

  function getPrivateProviderTlsRepairBridge(provider) {
    const failure = getProviderValidationFailure(provider);
    return failure && failure.helper_bridge ? failure.helper_bridge : null;
  }

  function getProviderTlsRepairHelperUrl(baseUrl, path) {
    const normalizedBaseUrl = normalizeProviderTlsRepairBaseUrl(baseUrl);
    const normalizedPath = String(path || '');
    if (!normalizedBaseUrl || !/^\/[a-z0-9/-]+$/i.test(normalizedPath)) {
      return '';
    }
    return `${normalizedBaseUrl}${normalizedPath}`;
  }

  async function refreshProviderTlsRepairHelperAvailability(provider) {
    const failure = getProviderValidationFailure(provider);
    const bridge = getPrivateProviderTlsRepairBridge(provider);
    if (
      !failure ||
      !bridge ||
      !hasCurrentProviderTlsRepairCredential(bridge.probe)
    ) {
      if (failure) {
        failure.helper_available = false;
        failure.operation_authorization = null;
      }
      renderProviderTlsRepairState();
      return false;
    }

    const healthUrl = getProviderTlsRepairHelperUrl(bridge.base_url, bridge.probe.path);
    if (!healthUrl) {
      failure.helper_available = false;
      failure.operation_authorization = null;
      renderProviderTlsRepairState();
      return false;
    }

    try {
      const health = await fetchJson(healthUrl, {
        method: 'GET',
        headers: {
          'X-TowerScout-Operation-Authorization': bridge.probe.authorization
        },
        cache: 'no-store'
      });
      const ready = Boolean(
        health &&
        health.state === 'ready' &&
        health.capabilities &&
        health.capabilities.max_active_operations === 1
      );
      failure.helper_available = ready;
      failure.operation_authorization = ready
        ? bridge.operation_authorization
        : null;
      renderProviderTlsRepairState();
      return ready;
    } catch (_error) {
      failure.helper_available = false;
      failure.operation_authorization = null;
      renderProviderTlsRepairState();
      return false;
    }
  }

  async function refreshProviderTlsRepairHelperAvailabilityForResults(validationResults = {}) {
    for (const provider of providerNames) {
      if (validationResults[provider]) {
        await refreshProviderTlsRepairHelperAvailability(provider);
      }
    }
  }

  function sanitizeProviderTlsRepairSymbol(value, allowedValues, fallback = '') {
    const text = String(value || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{1,80}$/.test(text)) {
      return fallback;
    }
    return allowedValues && !allowedValues.has(text) ? fallback : text;
  }

  function sanitizeProviderTlsRepairProvider(provider) {
    const normalized = String(provider || '').trim().toLowerCase();
    return providerNames.includes(normalized) ? normalized : '';
  }

  function sanitizeProviderTlsRepairOperationId(value) {
    const text = String(value || '').trim().toLowerCase();
    return /^[a-f0-9]{32}$/.test(text) ? text : '';
  }

  function cloneProviderTlsRepairOperationStatus(status) {
    if (!status) {
      return null;
    }
    return { ...status };
  }

  function normalizeProviderTlsRepairOperationStatus(payload = {}) {
    if (!payload || typeof payload !== 'object') {
      return null;
    }

    const provider = sanitizeProviderTlsRepairProvider(payload.provider);
    const operationType = payload.operation_type === 'provider_tls_repair' ? 'provider_tls_repair' : '';
    if (!provider || operationType !== 'provider_tls_repair') {
      return null;
    }

    const classification = sanitizeProviderTlsRepairSymbol(
      payload.classification,
      PROVIDER_TLS_REPAIR_STATUS_CLASSIFICATIONS,
      'unknown'
    );

    return {
      state: sanitizeProviderTlsRepairSymbol(payload.state, null, 'unknown'),
      operation_id: sanitizeProviderTlsRepairOperationId(payload.operation_id),
      operation_type: operationType,
      provider,
      accepted: payload.accepted === true,
      existing_operation: payload.existing_operation === true,
      execution_enabled: payload.execution_enabled === true,
      current_step: sanitizeProviderTlsRepairSymbol(payload.current_step, null, ''),
      classification,
      terminal: payload.terminal === true,
      next_action: sanitizeProviderTlsRepairSymbol(
        payload.next_action,
        PROVIDER_TLS_REPAIR_NEXT_ACTIONS,
        'support_review_required'
      )
    };
  }

  function isProviderTlsRepairOperationActive(status) {
    return Boolean(
      status &&
      status.terminal !== true &&
      ['pending', 'active', 'intermediate_success'].includes(status.classification)
    );
  }

  function rememberProviderTlsRepairOperationStatus(payload) {
    const status = normalizeProviderTlsRepairOperationStatus(payload);
    providerTlsRepairOperationStatus = status;
    if (!isProviderTlsRepairOperationActive(status)) {
      providerTlsRepairStartInFlight = false;
    }
    renderProviderTlsRepairState();
    return cloneProviderTlsRepairOperationStatus(status);
  }

  function getProviderTlsRepairActiveOperation() {
    if (!isProviderTlsRepairOperationActive(providerTlsRepairOperationStatus)) {
      return null;
    }
    return cloneProviderTlsRepairOperationStatus(providerTlsRepairOperationStatus);
  }

  function summarizeProviderTlsRepairAuthorization(record) {
    const authorization = record && record.operation_authorization;
    if (!hasCurrentProviderTlsRepairAuthorization(record)) {
      return null;
    }
    return {
      operation_type: 'provider_tls_repair',
      expires_at: authorization.expires_at,
      credential: 'short_lived_operation_authorization'
    };
  }

  function getProviderTlsRepairViewModel(provider) {
    const failure = getProviderValidationFailure(provider);
    if (!shouldShowProviderTlsRepair(provider)) {
      return {
        visible: false,
        enabled: false,
        provider,
        helper_available: false,
        blocked_reason: 'not_repairable'
      };
    }

    const helperAvailable = failure.helper_available === true;
    const authorizationReady = helperAvailable && hasCurrentProviderTlsRepairAuthorization(failure);
    const bridge = getPrivateProviderTlsRepairBridge(provider);
    const capabilityEnabled = Boolean(
      bridge && bridge.provider_tls_repair_capability === true
    );
    const enabled = (
      helperAvailable &&
      authorizationReady &&
      capabilityEnabled &&
      PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED
    );
    let blockedReason = null;
    if (!helperAvailable) {
      blockedReason = 'helper_unavailable';
    } else if (!authorizationReady) {
      blockedReason = 'operation_authorization_unavailable';
    } else if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED) {
      blockedReason = 'browser_mutation_disabled';
    } else if (!capabilityEnabled) {
      blockedReason = 'helper_capability_disabled';
    }

    return {
      visible: true,
      enabled,
      provider,
      display_name: providerDisplayName(provider),
      category: failure.category,
      message: failure.message,
      support_action: failure.support_action,
      repair_command: failure.repair_command,
      confirmation: PROVIDER_TLS_REPAIR_CONFIRMATION,
      helper_available: helperAvailable,
      capability_enabled: capabilityEnabled,
      authorization_ready: authorizationReady,
      blocked_reason: blockedReason
    };
  }

  function getProviderTlsRepairStartContract(provider) {
    const selectedProvider = sanitizeProviderTlsRepairProvider(provider) || activeProviderTlsRepairProvider;
    const baseContract = {
      endpoint: '',
      method: 'POST',
      content_type: 'application/json',
      provider: selectedProvider || '',
      confirmation: PROVIDER_TLS_REPAIR_CONFIRMATION,
      allowed_body_fields: [...PROVIDER_TLS_REPAIR_ALLOWED_START_BODY_FIELDS],
      disallowed_body_fields: [...PROVIDER_TLS_REPAIR_DISALLOWED_START_BODY_FIELDS],
      ready: false,
      enabled: false,
      blocked_reason: 'not_repairable'
    };

    const viewModel = getProviderTlsRepairViewModel(selectedProvider);
    if (!viewModel.visible) {
      return baseContract;
    }

    const activeOperation = getProviderTlsRepairActiveOperation();
    if (activeOperation && activeOperation.provider === viewModel.provider) {
      return {
        ...baseContract,
        provider: viewModel.provider,
        blocked_reason: 'operation_active',
        active_operation: activeOperation
      };
    }

    const failure = getProviderValidationFailure(viewModel.provider);
    const bridge = getPrivateProviderTlsRepairBridge(viewModel.provider);
    const endpoint = bridge
      ? getProviderTlsRepairHelperUrl(bridge.base_url, PROVIDER_TLS_REPAIR_OPERATION_ENDPOINT)
      : '';
    if (!viewModel.helper_available || !endpoint) {
      return {
        ...baseContract,
        provider: viewModel.provider,
        blocked_reason: 'helper_unavailable'
      };
    }
    const authorization = summarizeProviderTlsRepairAuthorization(failure);
    if (!authorization) {
      return {
        ...baseContract,
        endpoint,
        provider: viewModel.provider,
        blocked_reason: 'operation_authorization_unavailable'
      };
    }

    return {
      ...baseContract,
      endpoint,
      provider: viewModel.provider,
      operation_authorization: authorization,
      request_body_schema: {
        provider: viewModel.provider,
        confirmation: PROVIDER_TLS_REPAIR_CONFIRMATION,
        operation_authorization: 'short_lived_operation_authorization'
      },
      ready: true,
      enabled: viewModel.enabled,
      blocked_reason: viewModel.blocked_reason
    };
  }

  function buildProviderTlsRepairStartRequest(provider) {
    const contract = getProviderTlsRepairStartContract(provider);
    const failure = getProviderValidationFailure(contract.provider);
    const authorization = failure && failure.operation_authorization;
    if (!contract.ready || !authorization || !authorization.operation_token) {
      return null;
    }

    return {
      endpoint: contract.endpoint,
      options: {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: contract.provider,
          confirmation: PROVIDER_TLS_REPAIR_CONFIRMATION,
          operation_authorization: authorization.operation_token
        })
      }
    };
  }

  function clearStoredProviderTlsRepairOperation(operationId = '') {
    try {
      const stored = window.sessionStorage && window.sessionStorage.getItem(
        PROVIDER_TLS_REPAIR_ACTIVE_OPERATION_STORAGE_KEY
      );
      if (!stored) {
        return;
      }
      if (operationId) {
        const parsed = JSON.parse(stored);
        if (sanitizeProviderTlsRepairOperationId(parsed.operation_id) !== operationId) {
          return;
        }
      }
      window.sessionStorage.removeItem(PROVIDER_TLS_REPAIR_ACTIVE_OPERATION_STORAGE_KEY);
    } catch (_error) {
      // Storage is optional. Operation status remains available in memory.
    }
  }

  function persistProviderTlsRepairOperation(descriptor) {
    const operationId = sanitizeProviderTlsRepairOperationId(descriptor && descriptor.operation_id);
    const provider = sanitizeProviderTlsRepairProvider(descriptor && descriptor.provider);
    const helperBaseUrl = normalizeProviderTlsRepairBaseUrl(
      descriptor && descriptor.helper_base_url
    );
    if (!operationId || !provider || !helperBaseUrl) {
      return false;
    }
    try {
      window.sessionStorage.setItem(
        PROVIDER_TLS_REPAIR_ACTIVE_OPERATION_STORAGE_KEY,
        JSON.stringify({
          operation_id: operationId,
          provider,
          helper_base_url: helperBaseUrl
        })
      );
      return true;
    } catch (_error) {
      return false;
    }
  }

  function restoreProviderTlsRepairOperation() {
    try {
      const rawValue = window.sessionStorage && window.sessionStorage.getItem(
        PROVIDER_TLS_REPAIR_ACTIVE_OPERATION_STORAGE_KEY
      );
      if (!rawValue) {
        return null;
      }
      const parsed = JSON.parse(rawValue);
      const descriptor = {
        operation_id: sanitizeProviderTlsRepairOperationId(parsed.operation_id),
        provider: sanitizeProviderTlsRepairProvider(parsed.provider),
        helper_base_url: normalizeProviderTlsRepairBaseUrl(parsed.helper_base_url)
      };
      if (!descriptor.operation_id || !descriptor.provider || !descriptor.helper_base_url) {
        clearStoredProviderTlsRepairOperation();
        return null;
      }
      return descriptor;
    } catch (_error) {
      clearStoredProviderTlsRepairOperation();
      return null;
    }
  }

  function normalizeProviderTlsRepairStatusAuthorization(payload, descriptor) {
    const statusAuthorization = payload && payload.status_authorization;
    const baseUrl = normalizeProviderTlsRepairBaseUrl(payload && payload.base_url);
    const operationId = sanitizeProviderTlsRepairOperationId(payload && payload.operation_id);
    const credential = normalizeProviderTlsRepairCredential(
      statusAuthorization,
      'operation_status'
    );
    if (
      !credential ||
      !baseUrl ||
      operationId !== descriptor.operation_id ||
      baseUrl !== descriptor.helper_base_url ||
      !statusAuthorization ||
      statusAuthorization.operation_type !== 'provider_tls_repair'
    ) {
      return null;
    }
    return credential;
  }

  async function requestProviderTlsRepairStatusAuthorization(descriptor) {
    const payload = await fetchJson(PROVIDER_TLS_REPAIR_STATUS_AUTHORIZATION_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: descriptor.provider,
        operation_id: descriptor.operation_id
      })
    });
    return normalizeProviderTlsRepairStatusAuthorization(payload, descriptor);
  }

  function createProviderTlsRepairTerminalStatus(descriptor, state, classification, nextAction) {
    return {
      state,
      operation_id: descriptor.operation_id,
      operation_type: 'provider_tls_repair',
      provider: descriptor.provider,
      accepted: false,
      existing_operation: false,
      execution_enabled: false,
      current_step: '',
      classification,
      terminal: true,
      next_action: nextAction
    };
  }

  function waitForProviderTlsRepairPoll() {
    return new Promise(resolve => {
      window.setTimeout(resolve, PROVIDER_TLS_REPAIR_POLL_INTERVAL_MS);
    });
  }

  async function fetchProviderTlsRepairOperationStatus(descriptor, credential) {
    const statusUrl = getProviderTlsRepairHelperUrl(
      descriptor.helper_base_url,
      `/operations/${descriptor.operation_id}`
    );
    if (!statusUrl || !hasCurrentProviderTlsRepairCredential(credential)) {
      const error = new Error('Host repair status authorization is unavailable.');
      error.status = 401;
      throw error;
    }
    return fetchJson(statusUrl, {
      method: 'GET',
      headers: {
        'X-TowerScout-Operation-Authorization': credential.authorization
      },
      cache: 'no-store'
    });
  }

  async function runProviderTlsRepairPolling(descriptor) {
    const deadline = Date.now() + PROVIDER_TLS_REPAIR_POLL_TIMEOUT_MS;
    let statusAuthorization = null;

    while (Date.now() < deadline) {
      try {
        if (!hasCurrentProviderTlsRepairCredential(statusAuthorization)) {
          statusAuthorization = await requestProviderTlsRepairStatusAuthorization(descriptor);
          if (!statusAuthorization) {
            throw new Error('Host repair status authorization was rejected.');
          }
        }

        let payload;
        try {
          payload = await fetchProviderTlsRepairOperationStatus(descriptor, statusAuthorization);
        } catch (error) {
          if (error && error.status === 401) {
            statusAuthorization = await requestProviderTlsRepairStatusAuthorization(descriptor);
            if (!statusAuthorization) {
              throw error;
            }
            payload = await fetchProviderTlsRepairOperationStatus(descriptor, statusAuthorization);
          } else {
            throw error;
          }
        }

        const status = rememberProviderTlsRepairOperationStatus(payload);
        if (!status) {
          throw new Error('Host repair returned an invalid status.');
        }
        if (status.terminal) {
          clearStoredProviderTlsRepairOperation(descriptor.operation_id);
          return status;
        }
      } catch (error) {
        if (error && (error.status === 404 || error.status === 410)) {
          const expired = createProviderTlsRepairTerminalStatus(
            descriptor,
            'operation_expired',
            'terminal_timeout',
            'clear_or_reauthorize_after_timeout'
          );
          rememberProviderTlsRepairOperationStatus(expired);
          clearStoredProviderTlsRepairOperation(descriptor.operation_id);
          return expired;
        }

        const unavailable = createProviderTlsRepairTerminalStatus(
          descriptor,
          'helper_unavailable',
          'terminal_support_escalation',
          'use_manual_tls_repair_fallback'
        );
        rememberProviderTlsRepairOperationStatus(unavailable);
        clearStoredProviderTlsRepairOperation(descriptor.operation_id);
        TowerScoutErrorHandler.showUserNotification(
          'Host TLS repair status is unavailable. Use the suggested command fallback.',
          'info'
        );
        return unavailable;
      }

      await waitForProviderTlsRepairPoll();
    }

    const timedOut = createProviderTlsRepairTerminalStatus(
      descriptor,
      'operation_timeout',
      'terminal_timeout',
      'clear_or_reauthorize_after_timeout'
    );
    rememberProviderTlsRepairOperationStatus(timedOut);
    clearStoredProviderTlsRepairOperation(descriptor.operation_id);
    TowerScoutErrorHandler.showUserNotification(
      'Host TLS repair status timed out. Use the suggested command fallback.',
      'info'
    );
    return timedOut;
  }

  function pollProviderTlsRepairOperation(descriptor) {
    if (providerTlsRepairPollingPromise) {
      return providerTlsRepairPollingPromise;
    }
    providerTlsRepairPollingPromise = runProviderTlsRepairPolling(descriptor)
      .finally(() => {
        providerTlsRepairPollingPromise = null;
        providerTlsRepairStartInFlight = false;
        renderProviderTlsRepairState();
      });
    return providerTlsRepairPollingPromise;
  }

  function getVisibleProviderTlsRepairViewModels() {
    const visibleViewModels = [];
    for (const provider of providerNames) {
      const viewModel = getProviderTlsRepairViewModel(provider);
      if (viewModel.visible) {
        visibleViewModels.push(viewModel);
      }
    }
    return visibleViewModels;
  }

  function setText(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = text || '';
    }
  }

  function renderProviderTlsRepairState() {
    const panel = document.getElementById('wizard_provider_tls_repair_panel');
    if (!panel) {
      return null;
    }

    const visibleViewModels = getVisibleProviderTlsRepairViewModels();
    const viewModel = visibleViewModels[0] || null;
    const additionalVisibleCount = Math.max(visibleViewModels.length - 1, 0);
    const checkbox = document.getElementById('wizard_provider_tls_repair_confirm');
    const confirmation = document.getElementById('wizard_provider_tls_repair_confirmation');
    const button = document.getElementById('wizard_provider_tls_repair_button');

    if (!viewModel) {
      activeProviderTlsRepairProvider = null;
      panel.style.display = 'none';
      if (checkbox) {
        checkbox.checked = false;
      }
      if (confirmation) {
        confirmation.style.display = 'none';
      }
      if (button) {
        button.disabled = true;
        button.style.display = 'none';
      }
      setText('wizard_provider_tls_repair_title', '');
      setText('wizard_provider_tls_repair_message', '');
      setText('wizard_provider_tls_repair_support', '');
      setText('wizard_provider_tls_repair_command', '');
      setText('wizard_provider_tls_repair_status', '');
      return null;
    }

    activeProviderTlsRepairProvider = viewModel.provider;
    panel.style.display = 'block';
    setText('wizard_provider_tls_repair_title', `${viewModel.display_name} TLS repair`);
    const additionalRepairNotice = additionalVisibleCount === 1
      ? ' 1 additional provider also needs repair.'
      : additionalVisibleCount > 1
        ? ` ${additionalVisibleCount} additional providers also need repair.`
        : '';
    setText(
      'wizard_provider_tls_repair_message',
      `${viewModel.display_name} failed with a repairable TLS trust error.${additionalRepairNotice}`
    );
    setText('wizard_provider_tls_repair_support', viewModel.support_action || '');
    setText(
      'wizard_provider_tls_repair_command',
      viewModel.repair_command ? `Command fallback: ${viewModel.repair_command}` : ''
    );

    const confirmed = checkbox && checkbox.checked === true;
    const activeOperation = getProviderTlsRepairActiveOperation();
    const operationActive = activeOperation && activeOperation.provider === viewModel.provider;
    if (confirmation) {
      confirmation.style.display = viewModel.helper_available ? '' : 'none';
    }
    if (button) {
      button.style.display = viewModel.helper_available ? '' : 'none';
      button.disabled = Boolean(operationActive || providerTlsRepairStartInFlight || !(viewModel.enabled && confirmed));
      button.textContent = viewModel.enabled ? 'Repair and restart TowerScout' : 'Repair unavailable';
    }

    let statusMessage;
    if (operationActive) {
      statusMessage = 'A host repair operation is already active. Wait for it to finish before starting another repair.';
    } else if (!viewModel.helper_available) {
      statusMessage = 'The host helper is unavailable. Use the command fallback for this package.';
    } else if (!viewModel.authorization_ready) {
      statusMessage = 'Host repair authorization is not available yet. Use the command fallback for this package.';
    } else if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED) {
      statusMessage = 'Host repair is prepared for review but browser-triggered repair remains disabled in this gate.';
    } else if (!viewModel.capability_enabled) {
      statusMessage = 'The helper repair capability remains disabled pending review. Use the command fallback.';
    } else if (!confirmed) {
      statusMessage = 'Confirm the restart behavior before running repair.';
    } else {
      statusMessage = 'Ready to start the authorized repair operation.';
    }

    if (additionalVisibleCount > 0) {
      statusMessage += additionalVisibleCount === 1
        ? ' Another provider also needs repair.'
        : ` ${additionalVisibleCount} additional providers also need repair.`;
    }
    setText('wizard_provider_tls_repair_status', statusMessage);

    return viewModel;
  }

  function updateProviderTlsRepairControls() {
    return renderProviderTlsRepairState();
  }

  async function executeProviderTlsRepairStart(viewModel, request) {
    const bridge = getPrivateProviderTlsRepairBridge(viewModel.provider);
    const descriptorBase = {
      provider: viewModel.provider,
      helper_base_url: bridge && bridge.base_url
    };

    providerTlsRepairStartInFlight = true;
    renderProviderTlsRepairState();
    try {
      let payload;
      try {
        payload = await fetchJson(request.endpoint, request.options);
      } catch (error) {
        const conflictStatus = error && error.status === 409
          ? normalizeProviderTlsRepairOperationStatus(error.payload)
          : null;
        if (!conflictStatus || !conflictStatus.operation_id) {
          throw error;
        }
        payload = error.payload;
      }

      const status = rememberProviderTlsRepairOperationStatus(payload);
      if (!status || !status.operation_id) {
        throw new Error('Host repair did not return a valid operation.');
      }

      const descriptor = {
        ...descriptorBase,
        operation_id: status.operation_id
      };
      persistProviderTlsRepairOperation(descriptor);
      TowerScoutErrorHandler.showUserNotification(
        status.existing_operation
          ? 'The existing host TLS repair operation is being monitored.'
          : 'The authorized host TLS repair operation was accepted.',
        'info'
      );
      return pollProviderTlsRepairOperation(descriptor);
    } catch (_error) {
      providerTlsRepairStartInFlight = false;
      renderProviderTlsRepairState();
      TowerScoutErrorHandler.showUserNotification(
        'Host TLS repair could not be started. Use the suggested command fallback.',
        'info'
      );
      return false;
    }
  }

  function startProviderTlsRepair() {
    const viewModel = getProviderTlsRepairViewModel(activeProviderTlsRepairProvider);
    if (!viewModel.visible) {
      return false;
    }

    const startContract = getProviderTlsRepairStartContract(viewModel.provider);
    if (startContract.blocked_reason === 'operation_active') {
      TowerScoutErrorHandler.showUserNotification(
        'A host TLS repair operation is already active. Wait for it to finish before starting another repair.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED || !viewModel.enabled) {
      TowerScoutErrorHandler.showUserNotification(
        'Host TLS repair is not enabled for this package yet. Use the suggested command fallback.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    if (providerTlsRepairStartInFlight) {
      TowerScoutErrorHandler.showUserNotification(
        'Host TLS repair is already starting. Wait for the current operation status.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    const confirmation = document.getElementById('wizard_provider_tls_repair_confirm');
    if (!confirmation || confirmation.checked !== true) {
      TowerScoutErrorHandler.showUserNotification(
        'Confirm the restart behavior before running host TLS repair.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    const request = buildProviderTlsRepairStartRequest(viewModel.provider);
    if (!request) {
      TowerScoutErrorHandler.showUserNotification(
        'Host TLS repair authorization is no longer current. Use the command fallback or revalidate the key.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    return executeProviderTlsRepairStart(viewModel, request);
  }

  function resumeStoredProviderTlsRepairOperation() {
    if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED) {
      return false;
    }
    const descriptor = restoreProviderTlsRepairOperation();
    if (!descriptor) {
      return false;
    }
    rememberProviderTlsRepairOperationStatus({
      state: 'planned',
      operation_id: descriptor.operation_id,
      operation_type: 'provider_tls_repair',
      provider: descriptor.provider,
      accepted: true,
      existing_operation: true,
      execution_enabled: false,
      current_step: 'awaiting_status',
      classification: 'pending',
      terminal: false,
      next_action: 'poll_existing_operation'
    });
    return pollProviderTlsRepairOperation(descriptor);
  }

  function setSetupBlocked(isBlocked) {
    document.body.classList.toggle('setup-required-active', isBlocked);
  }

  function showStep(stepNumber) {
    const steps = document.querySelectorAll('#setup_wizard_div .wizard-step');
    const indicators = document.querySelectorAll('#setup_wizard_div .wizard-progress .step');

    steps.forEach(step => {
      step.style.display = Number(step.dataset.step) === stepNumber ? 'block' : 'none';
    });

    indicators.forEach(step => {
      const indicatorStep = Number(step.dataset.step);
      step.classList.toggle('active', indicatorStep === stepNumber);
      step.classList.toggle('complete', indicatorStep < stepNumber);
    });

    currentStep = stepNumber;
  }

  function show() {
    const wizard = getWizardElement();
    if (!wizard) {
      return;
    }

    wizard.style.display = 'flex';
    setSetupBlocked(true);
    showStep(currentStep);
    renderProviderTlsRepairState();
    loadPerformanceStats();
  }

  function hide() {
    const wizard = getWizardElement();
    if (!wizard) {
      return;
    }

    wizard.style.display = 'none';
    setSetupBlocked(false);
  }

  function updateIndicator(elementId, isValid) {
    const indicator = document.getElementById(elementId);
    if (!indicator) {
      return;
    }

    if (isValid === null) {
      indicator.textContent = '';
      indicator.classList.remove('valid', 'invalid');
      return;
    }

    indicator.textContent = isValid ? 'OK' : 'X';
    indicator.classList.toggle('valid', isValid);
    indicator.classList.toggle('invalid', !isValid);
  }

  function updateProviderOptions() {
    const googleOption = document.querySelector('#wizard_google_provider_option input');
    const azureOption = document.querySelector('#wizard_azure_provider_option input');

    if (googleOption) {
      googleOption.disabled = !validatedKeys.google;
    }
    if (azureOption) {
      azureOption.disabled = !validatedKeys.azure;
    }

    if (validatedKeys.google && googleOption) {
      googleOption.checked = true;
    } else if (validatedKeys.azure && azureOption) {
      azureOption.checked = true;
    }
  }

  async function validateKey(provider, key) {
    return fetchJson('/api/config/validate-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, key })
    });
  }

  async function validateProviderInput(provider, key, indicatorId, displayName, validationMessages) {
    if (!key) {
      clearProviderValidationState(provider);
      return false;
    }

    try {
      const result = await validateKey(provider, key);
      const validation = rememberProviderValidationResult(provider, result);
      await refreshProviderTlsRepairHelperAvailability(provider);
      const isValid = validation.valid === true;
      updateIndicator(indicatorId, isValid);
      if (!isValid && validation.message) {
        validationMessages.push(providerFailureMessage(displayName, validation));
      }
      return isValid;
    } catch (error) {
      const validation = rememberProviderValidationResult(provider, error.payload || error);
      await refreshProviderTlsRepairHelperAvailability(provider);
      updateIndicator(indicatorId, false);
      validationMessages.push(providerFailureMessage(displayName, validation));
      return false;
    }
  }

  function setButtonBusy(buttonId, isBusy, idleText, busyText) {
    const button = document.getElementById(buttonId);
    if (!button) {
      return;
    }

    button.disabled = isBusy;
    button.textContent = isBusy ? busyText : idleText;
  }

  async function validateAndNext() {
    if (validationInFlight) {
      return;
    }

    const googleKey = document.getElementById('wizard_google_key').value.trim();
    const azureKey = document.getElementById('wizard_azure_key').value.trim();
    const message = document.getElementById('wizard_validation_message');

    validatedKeys = { google: false, azure: false };
    resetProviderValidationState();
    updateIndicator('google_key_status', null);
    updateIndicator('azure_key_status', null);
    validationInFlight = true;
    setButtonBusy('wizard_validate_button', true, 'Validate Keys', 'Validating...');

    try {
      const validationMessages = [];

      validatedKeys.google = await validateProviderInput(
        'google',
        googleKey,
        'google_key_status',
        'Google Maps',
        validationMessages
      );
      validatedKeys.azure = await validateProviderInput(
        'azure',
        azureKey,
        'azure_key_status',
        'Azure Maps',
        validationMessages
      );

      if (!validatedKeys.google && !validatedKeys.azure) {
        throw new Error(validationMessages.join(' ') || 'Provide at least one valid API key before continuing.');
      }

      updateProviderOptions();
      if (message) {
        message.textContent = 'Validation succeeded.';
      }
      nextStep();
    } catch (error) {
      if (message) {
        message.textContent = error.message;
      }
      TowerScoutErrorHandler.showUserNotification(error.message, 'error');
    } finally {
      validationInFlight = false;
      setButtonBusy('wizard_validate_button', false, 'Validate Keys', 'Validating...');
    }
  }

  async function saveAndReview() {
    if (saveInFlight) {
      return;
    }

    const payload = {
      google_api_key: validatedKeys.google ? document.getElementById('wizard_google_key').value.trim() : '',
      azure_maps_subscription_key: validatedKeys.azure ? document.getElementById('wizard_azure_key').value.trim() : '',
      default_map_provider: getSelectedDefaultProvider()
    };

    saveInFlight = true;
    setButtonBusy('wizard_save_button', true, 'Save Configuration', 'Saving...');

    try {
      const result = await fetchJson('/api/config/save-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      rememberProviderValidationResults(result.validation_results);
      await refreshProviderTlsRepairHelperAvailabilityForResults(result.validation_results);

      window.needsSetup = false;
      nextStep();
      const failedGoogle = result.validation_results && result.validation_results.google && result.validation_results.google.valid !== true;
      const failedAzure = result.validation_results && result.validation_results.azure && result.validation_results.azure.valid !== true;
      if (failedGoogle || failedAzure) {
        const messages = [];
        if (failedGoogle) {
          messages.push(providerFailureMessage('Google Maps', result.validation_results.google));
        }
        if (failedAzure) {
          messages.push(providerFailureMessage('Azure Maps', result.validation_results.azure));
        }
        TowerScoutErrorHandler.showUserNotification(`Configuration saved. ${messages.join(' ')}`, 'info');
      } else {
        TowerScoutErrorHandler.showUserNotification('Configuration saved successfully.', 'success');
      }
    } catch (error) {
      const validationResults = (error.payload && error.payload.validation_results) || {};
      rememberProviderValidationResults(validationResults);
      await refreshProviderTlsRepairHelperAvailabilityForResults(validationResults);
      TowerScoutErrorHandler.showUserNotification(saveFailureMessage(error), 'error');
    } finally {
      saveInFlight = false;
      setButtonBusy('wizard_save_button', false, 'Save Configuration', 'Saving...');
    }
  }

  async function loadPerformanceStats() {
    const container = document.getElementById('wizard_performance_stats');
    if (!container) {
      return;
    }

    try {
      const stats = await fetchJson('/api/config/performance');
      if (!stats.session_count) {
        container.innerHTML = '<p>No recent detection runs found yet.</p>';
        return;
      }

      container.innerHTML = `
        <p>Recent sessions: ${stats.session_count}</p>
        <p>Average throughput: ${stats.avg_tiles_per_second.toFixed(2)} tiles/second</p>
        <p>Last detection: ${stats.last_detection_timestamp || 'Unavailable'}</p>
      `;
    } catch (_error) {
      container.innerHTML = '<p>Performance metrics are not available yet.</p>';
    }
  }

  function nextStep() {
    if (currentStep < 5) {
      showStep(currentStep + 1);
    }
  }

  function prevStep() {
    if (currentStep > 1) {
      showStep(currentStep - 1);
    }
  }

  function complete() {
    hide();
    window.location.reload();
  }

  async function init() {
    try {
      const status = await fetchJson('/api/config/status');
      window.needsSetup = Boolean(status.needs_setup);
      if (window.needsSetup) {
        show();
      }
      resumeStoredProviderTlsRepairOperation();
    } catch (error) {
      console.error('SetupWizard init failed:', error);
    }
  }

  window.SetupWizard = {
    init,
    show,
    hide,
    showStep,
    nextStep,
    prevStep,
    validateAndNext,
    saveAndReview,
    complete,
    getProviderValidationState,
    refreshProviderTlsRepairHelperAvailability,
    shouldShowProviderTlsRepair,
    getProviderTlsRepairViewModel,
    getProviderTlsRepairStartContract,
    rememberProviderTlsRepairOperationStatus,
    getProviderTlsRepairActiveOperation,
    renderProviderTlsRepairState,
    updateProviderTlsRepairControls,
    startProviderTlsRepair
  };

  document.addEventListener('DOMContentLoaded', init);
})();
