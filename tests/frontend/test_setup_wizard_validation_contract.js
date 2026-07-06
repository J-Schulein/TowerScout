#!/usr/bin/env node
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '../..');
const SETUP_WIZARD_PATH = path.join(ROOT, 'webapp/js/src/setup-wizard.js');

function createClassList() {
  const values = new Set();
  return {
    toggle(name, enabled) {
      if (enabled) {
        values.add(name);
      } else {
        values.delete(name);
      }
    },
    remove(...names) {
      names.forEach(name => values.delete(name));
    },
    contains(name) {
      return values.has(name);
    }
  };
}

function createElement(id, value = '') {
  return {
    id,
    value,
    textContent: '',
    disabled: false,
    checked: false,
    style: { display: 'none' },
    classList: createClassList(),
    dataset: {}
  };
}

function createJsonResponse(ok, status, payload) {
  return {
    ok,
    status,
    async json() {
      return payload;
    }
  };
}

function createContext(options = {}) {
  const elements = {
    setup_wizard_div: createElement('setup_wizard_div'),
    wizard_google_key: createElement('wizard_google_key', 'bad-google-key'),
    wizard_azure_key: createElement('wizard_azure_key', 'valid-azure-key'),
    wizard_validation_message: createElement('wizard_validation_message'),
    google_key_status: createElement('google_key_status'),
    azure_key_status: createElement('azure_key_status'),
    wizard_validate_button: createElement('wizard_validate_button'),
    wizard_save_button: createElement('wizard_save_button'),
    wizard_performance_stats: createElement('wizard_performance_stats')
  };
  const steps = [1, 2, 3, 4, 5].map(stepNumber => ({
    dataset: { step: String(stepNumber) },
    style: { display: 'none' },
    classList: createClassList()
  }));
  const indicators = [1, 2, 3, 4, 5].map(stepNumber => ({
    dataset: { step: String(stepNumber) },
    classList: createClassList()
  }));
  const providerOptions = {
    google: createElement('default_provider_google'),
    azure: createElement('default_provider_azure')
  };
  providerOptions.google.value = 'google';
  providerOptions.azure.value = 'azure';

  const document = {
    body: { classList: createClassList() },
    getElementById(id) {
      return elements[id] || null;
    },
    querySelector(selector) {
      if (selector === '#wizard_google_provider_option input') {
        return providerOptions.google;
      }
      if (selector === '#wizard_azure_provider_option input') {
        return providerOptions.azure;
      }
      if (selector === 'input[name="default_provider"]:checked') {
        return Object.values(providerOptions).find(option => option.checked) || null;
      }
      return null;
    },
    querySelectorAll(selector) {
      if (selector === '#setup_wizard_div .wizard-step') {
        return steps;
      }
      if (selector === '#setup_wizard_div .wizard-progress .step') {
        return indicators;
      }
      return [];
    },
    addEventListener() {}
  };

  const fetchCalls = [];
  let savePayload = null;
  const notifications = [];
  const googleValidationPayload = options.googleValidationPayload || {
    error: true,
    message: 'TowerScout could not verify the Google Maps TLS certificate.',
    details: {
      provider: 'google',
      category: 'tls_ca_untrusted',
      repairable: true,
      support_action: 'Import the trusted organization/root TLS CA into the container trust store, then retry Google Maps.',
      repair_command: '.\\scripts\\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off',
      helper_available: false
    }
  };
  const googleValidationOk = options.googleValidationOk === true;
  const googleValidationStatus = options.googleValidationStatus || (googleValidationOk ? 200 : 502);
  const azureValidationPayload = options.azureValidationPayload || {
    valid: true,
    provider: 'azure',
    category: 'tls_ok',
    repairable: false,
    helper_available: false,
    message: 'Azure Maps subscription key validated successfully.'
  };
  const context = {
    console,
    document,
    fetchCalls,
    get savePayload() {
      return savePayload;
    },
    window: {},
    TowerScoutErrorHandler: {
      showUserNotification(message, type) {
        notifications.push({ message, type });
      }
    },
    async fetch(url, options = {}) {
      if (url === '/api/config/validate-key') {
        const body = JSON.parse(options.body);
        fetchCalls.push(body.provider);
        if (body.provider === 'google') {
          return createJsonResponse(googleValidationOk, googleValidationStatus, googleValidationPayload);
        }
        return createJsonResponse(true, 200, azureValidationPayload);
      }

      if (url === '/api/config/save-keys') {
        savePayload = JSON.parse(options.body);
        return {
          ok: true,
          status: 200,
          async json() {
            return { success: true };
          }
        };
      }

      if (url === '/api/config/performance') {
        return {
          ok: true,
          status: 200,
          async json() {
            return { session_count: 0 };
          }
        };
      }

      throw new Error(`Unexpected fetch URL: ${url}`);
    }
  };
  context.window = {
    window: null,
    needsSetup: true,
    SetupWizard: null,
    TowerScoutErrorHandler: context.TowerScoutErrorHandler
  };
  context.window.window = context.window;

  return { context, elements, steps, providerOptions, notifications };
}

async function testSecondProviderStillValidatesAfterFirstProviderNetworkFailure() {
  const { context, elements, steps, providerOptions } = createContext();
  vm.createContext(context);
  const source = fs.readFileSync(SETUP_WIZARD_PATH, 'utf8');
  vm.runInContext(source, context, { filename: SETUP_WIZARD_PATH });

  context.window.SetupWizard.showStep(2);
  await context.window.SetupWizard.validateAndNext();

  assert.deepStrictEqual(context.fetchCalls, ['google', 'azure']);
  assert.strictEqual(elements.google_key_status.textContent, 'X');
  assert.strictEqual(elements.azure_key_status.textContent, 'OK');
  assert.strictEqual(providerOptions.google.disabled, true);
  assert.strictEqual(providerOptions.azure.disabled, false);
  assert.strictEqual(providerOptions.azure.checked, true);
  assert.strictEqual(elements.wizard_validation_message.textContent, 'Validation succeeded.');
  assert.strictEqual(steps[2].style.display, 'block');
  const googleValidation = context.window.SetupWizard.getProviderValidationState('google');
  assert.strictEqual(googleValidation.lastFailure.provider, 'google');
  assert.strictEqual(googleValidation.lastFailure.category, 'tls_ca_untrusted');
  assert.strictEqual(googleValidation.lastFailure.repairable, true);
  assert.strictEqual(googleValidation.lastFailure.helper_available, false);
  assert.strictEqual(
    googleValidation.lastFailure.repair_command,
    '.\\scripts\\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off'
  );
  assert.strictEqual(context.window.SetupWizard.shouldShowProviderTlsRepair('google'), false);

  await context.window.SetupWizard.saveAndReview();
  assert.deepStrictEqual(context.savePayload, {
    google_api_key: '',
    azure_maps_subscription_key: 'valid-azure-key',
    default_map_provider: 'azure'
  });
}

async function testInvalidProviderKeyDoesNotExposeRepairPredicate() {
  const { context } = createContext({
    googleValidationOk: true,
    googleValidationPayload: {
      valid: false,
      provider: 'google',
      category: 'invalid_provider_key',
      repairable: false,
      helper_available: false,
      repair_command: null,
      message: 'Google Maps key reached Google but was rejected.'
    }
  });
  vm.createContext(context);
  const source = fs.readFileSync(SETUP_WIZARD_PATH, 'utf8');
  vm.runInContext(source, context, { filename: SETUP_WIZARD_PATH });

  context.window.SetupWizard.showStep(2);
  await context.window.SetupWizard.validateAndNext();

  const googleValidation = context.window.SetupWizard.getProviderValidationState('google');
  assert.strictEqual(googleValidation.lastFailure.category, 'invalid_provider_key');
  assert.strictEqual(googleValidation.lastFailure.repairable, false);
  assert.strictEqual(googleValidation.lastFailure.helper_available, false);
  assert.strictEqual(context.window.SetupWizard.shouldShowProviderTlsRepair('google'), false);
}

async function testRepairPredicateRequiresRepairableTlsAndHelperAvailability() {
  const { context } = createContext({
    googleValidationPayload: {
      error: true,
      message: 'TowerScout could not verify the Google Maps TLS certificate.',
      details: {
        provider: 'google',
        category: 'tls_ca_untrusted',
        repairable: true,
        support_action: 'Import the trusted organization/root TLS CA into the container trust store, then retry Google Maps.',
        repair_command: '.\\scripts\\repair-provider-tls.cmd -Provider google -Engine docker -Gpu off',
        helper_available: true
      }
    }
  });
  vm.createContext(context);
  const source = fs.readFileSync(SETUP_WIZARD_PATH, 'utf8');
  vm.runInContext(source, context, { filename: SETUP_WIZARD_PATH });

  context.window.SetupWizard.showStep(2);
  await context.window.SetupWizard.validateAndNext();

  assert.strictEqual(context.window.SetupWizard.shouldShowProviderTlsRepair('google'), true);
  assert.strictEqual(context.window.SetupWizard.shouldShowProviderTlsRepair('azure'), false);
}

testSecondProviderStillValidatesAfterFirstProviderNetworkFailure()
  .then(testInvalidProviderKeyDoesNotExposeRepairPredicate)
  .then(testRepairPredicateRequiresRepairableTlsAndHelperAvailability)
  .then(() => {
    console.log('Setup wizard validation contract PASSED');
  })
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
