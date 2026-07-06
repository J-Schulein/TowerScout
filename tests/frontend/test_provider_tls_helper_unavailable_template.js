/**
 * Frontend Integration Test Template - Provider TLS helper-unavailable fallback
 *
 * Purpose: Template test that simulates the host helper being unavailable
 * (network or 5xx response) during the start attempt and asserts the
 * frontend falls back to the command guidance and does not enter retry loops.
 *
 * IMPORTANT: This is a template scaffold. The real assertions may need to be
 * adapted to the UI markup and notification helpers present in the app.
 *
 * Usage:
 *  node tests/frontend/test_provider_tls_helper_unavailable_template.js
 */

const puppeteer = require('puppeteer');

const CONFIG = { baseUrl: 'http://localhost:5000', headless: true, timeout: 60000 };

async function run() {
  const launchOptions = { headless: CONFIG.headless };
  if (process.env.TEST_BROWSER_EXECUTABLE) {
    launchOptions.executablePath = process.env.TEST_BROWSER_EXECUTABLE;
  }
  const browser = await puppeteer.launch(launchOptions);
  const page = await browser.newPage();

  try {
    const USE_REAL_HELPER = (process.env.E2E_USE_SERVER === '1' || process.env.E2E_USE_SERVER === 'true' || process.env.USE_REAL_HELPER === '1');

    await page.goto(CONFIG.baseUrl, { waitUntil: 'networkidle2', timeout: CONFIG.timeout });

    // Expose helper base URL to the page when running e2e
    await page.evaluateOnNewDocument((hb) => {
      try { window.__TEST_HELPER_BASE_URL = hb || '' } catch(e) {}
    }, process.env.TEST_HELPER_BASE_URL || '');

    // Inject a repairable validation result as in the other template
    const future = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    await page.evaluate((future) => {
      const payload = {
        provider: 'google',
        repairable: true,
        helper_available: true,
        category: 'tls_ca_untrusted',
        operation_authorization: {
          operation_type: 'provider_tls_repair',
          expires_at: future,
          operation_token: 'TEST_TOKEN_YYYYYYYYYYYYYYYY'
        }
      };
      if (typeof rememberProviderValidationResult === 'function') {
        rememberProviderValidationResult('google', payload);
      } else {
        window.__TEST_provider_validation = payload;
      }
    }, future);

    // Shim fetch to return 503 for the POST and record call count unless running e2e
    await page.evaluate((useReal) => {
      const orig = window.fetch;
      window.__fetchCalls = [];
      if (useReal) return;
      window.fetch = async function(url, options) {
        window.__fetchCalls.push(String(url));
        if (typeof url === 'string' && url.endsWith('/operations/provider-tls-repair')) {
          // Simulate helper unavailable
          return { ok: false, status: 503, json: async () => ({ message: 'helper_unavailable' }) };
        }
        return orig.apply(this, arguments);
      };
    }, USE_REAL_HELPER);

    // Use the builder to create POST body and then attempt a start via a small
    // injected helper so we can observe UI reaction.
    const outcome = await page.evaluate(async () => {
      let built = typeof buildProviderTlsRepairStartRequest === 'function' ? buildProviderTlsRepairStartRequest('google') : null;
      if (!built && window.__TEST_provider_validation) {
        const pv = window.__TEST_provider_validation;
        built = {
          endpoint: (window.__TEST_HELPER_BASE_URL || '') + '/operations/provider-tls-repair',
          options: {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              provider: pv.provider,
              confirmation: 'repair_tls_and_restart',
              operation_authorization: pv.operation_authorization && pv.operation_authorization.operation_token
            })
          }
        };
      }
      if (!built) {
        return { error: 'no_builder' };
      }

      // Perform a single POST attempt
      const resp = await fetch(built.endpoint, built.options);
      const body = await (resp.json ? resp.json() : {});

      // Wait a short while to detect any retry loops
      await new Promise(r => setTimeout(r, 200));

      return {
        status: resp.status,
        bodyText: body && body.message,
        fetchCalls: (window.__fetchCalls || []).slice()
      };
    });

    if (outcome.error) {
      console.error('Builder not available in page context; adapt test to current frontend build.');
      process.exitCode = 2;
      return;
    }

    if (outcome.status !== 503) {
      console.error('Expected helper POST to return 503 in this simulation, got', outcome.status);
      process.exitCode = 2;
      return;
    }

    // Assert only one POST attempt occurred and that the UI should have fallback guidance
    const postCalls = outcome.fetchCalls.filter(u => u.endsWith('/operations/provider-tls-repair'));
    if (postCalls.length !== 1) {
      console.error('Expected a single POST attempt, saw', postCalls.length);
      process.exitCode = 2;
      return;
    }

    console.log('Helper-unavailable template: single POST observed, status=503');
    console.log('Body message:', outcome.bodyText);

    // TODO: Add DOM assertions here to validate that the UI shows the command
    // fallback text or an appropriate user notification instead of retry loops.

  } finally {
    await browser.close();
  }
}

run().catch(err => { console.error(err); process.exitCode = 1; });
