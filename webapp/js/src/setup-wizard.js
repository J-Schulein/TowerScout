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
  const providerNames = ['google', 'azure'];
  let providerValidationState = createEmptyProviderValidationState();
  let activeProviderTlsRepairProvider = null;

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

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const error = new Error(data.message || data.error || `Request failed with status ${response.status}`);
      error.status = response.status;
      error.payload = data;
      error.details = data.details || {};
      error.category = data.category || (data.details && data.details.category);
      throw error;
    }

    return data;
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
      renderProviderTlsRepairState();
    }
  }

  function resetProviderValidationState() {
    providerValidationState = createEmptyProviderValidationState();
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
      TLS_REPAIR_CATEGORIES.has(failure.category) &&
      failure.helper_available === true
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

  function getProviderTlsRepairViewModel(provider) {
    const failure = getProviderValidationFailure(provider);
    if (!shouldShowProviderTlsRepair(provider)) {
      return {
        visible: false,
        enabled: false,
        provider,
        blocked_reason: 'not_repairable_or_helper_unavailable'
      };
    }

    const authorizationReady = hasCurrentProviderTlsRepairAuthorization(failure);
    const enabled = authorizationReady && PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED;
    let blockedReason = null;
    if (!authorizationReady) {
      blockedReason = 'operation_authorization_unavailable';
    } else if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED) {
      blockedReason = 'browser_mutation_disabled';
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
      authorization_ready: authorizationReady,
      blocked_reason: blockedReason
    };
  }

  function firstVisibleProviderTlsRepairViewModel() {
    for (const provider of providerNames) {
      const viewModel = getProviderTlsRepairViewModel(provider);
      if (viewModel.visible) {
        return viewModel;
      }
    }
    return null;
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

    const viewModel = firstVisibleProviderTlsRepairViewModel();
    const checkbox = document.getElementById('wizard_provider_tls_repair_confirm');
    const button = document.getElementById('wizard_provider_tls_repair_button');

    if (!viewModel) {
      activeProviderTlsRepairProvider = null;
      panel.style.display = 'none';
      if (checkbox) {
        checkbox.checked = false;
      }
      if (button) {
        button.disabled = true;
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
    setText(
      'wizard_provider_tls_repair_message',
      `${viewModel.display_name} failed with a repairable TLS trust error.`
    );
    setText('wizard_provider_tls_repair_support', viewModel.support_action || '');
    setText(
      'wizard_provider_tls_repair_command',
      viewModel.repair_command ? `Command fallback: ${viewModel.repair_command}` : ''
    );

    const confirmed = checkbox && checkbox.checked === true;
    if (button) {
      button.disabled = !(viewModel.enabled && confirmed);
      button.textContent = viewModel.enabled ? 'Repair and restart TowerScout' : 'Repair unavailable';
    }

    if (!viewModel.authorization_ready) {
      setText(
        'wizard_provider_tls_repair_status',
        'Host repair authorization is not available yet. Use the command fallback for this package.'
      );
    } else if (!PROVIDER_TLS_REPAIR_BROWSER_MUTATION_ENABLED) {
      setText(
        'wizard_provider_tls_repair_status',
        'Host repair is prepared for review but browser-triggered repair remains disabled in this gate.'
      );
    } else if (!confirmed) {
      setText('wizard_provider_tls_repair_status', 'Confirm the restart behavior before running repair.');
    } else {
      setText('wizard_provider_tls_repair_status', 'Ready to start the authorized repair operation.');
    }

    return viewModel;
  }

  function updateProviderTlsRepairControls() {
    return renderProviderTlsRepairState();
  }

  function startProviderTlsRepair() {
    const viewModel = getProviderTlsRepairViewModel(activeProviderTlsRepairProvider);
    if (!viewModel.visible) {
      return false;
    }

    if (!viewModel.enabled) {
      TowerScoutErrorHandler.showUserNotification(
        'Host TLS repair is not enabled for this package yet. Use the suggested command fallback.',
        'info'
      );
      renderProviderTlsRepairState();
      return false;
    }

    TowerScoutErrorHandler.showUserNotification(
      'Host TLS repair authorization is ready, but execution is still gated pending review.',
      'info'
    );
    renderProviderTlsRepairState();
    return false;
  }

  function providerFailureMessage(displayName, payload) {
    if (!payload) {
      return '';
    }

    const normalized = normalizeProviderValidationResult('', payload);
    const parts = [`${displayName}: ${normalized.message}`];
    if (normalized.category) {
      parts.push(`Category: ${normalized.category}.`);
    }
    if (normalized.support_action) {
      parts.push(normalized.support_action);
    }
    if (
      normalized.repair_command &&
      (!normalized.support_action || !normalized.support_action.includes(normalized.repair_command))
    ) {
      parts.push(`Suggested command: ${normalized.repair_command}`);
    }
    return parts.join(' ');
  }

  function saveFailureMessage(error) {
    const payload = error.payload || {};
    const validationResults = payload.validation_results || {};
    const messages = [];

    if (validationResults.google && validationResults.google.valid !== true) {
      messages.push(providerFailureMessage('Google Maps', validationResults.google));
    }
    if (validationResults.azure && validationResults.azure.valid !== true) {
      messages.push(providerFailureMessage('Azure Maps', validationResults.azure));
    }

    return [payload.message || error.message, ...messages].filter(Boolean).join(' ');
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
      const isValid = validation.valid === true;
      updateIndicator(indicatorId, isValid);
      if (!isValid && validation.message) {
        validationMessages.push(providerFailureMessage(displayName, validation));
      }
      return isValid;
    } catch (error) {
      const validation = rememberProviderValidationResult(provider, error.payload || error);
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
      rememberProviderValidationResults((error.payload && error.payload.validation_results) || {});
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
    shouldShowProviderTlsRepair,
    getProviderTlsRepairViewModel,
    renderProviderTlsRepairState,
    updateProviderTlsRepairControls,
    startProviderTlsRepair
  };

  document.addEventListener('DOMContentLoaded', init);
})();
