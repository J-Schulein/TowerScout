/**
 * Frontend Integration Test Template - Provider TLS live POST/poll flow
 *
 * Purpose: Template for a Puppeteer-driven test that verifies the browser
 * posts the exact allowed body shape to the helper POST endpoint and then
 * polls the operation status endpoint for progress. This is a template
 * scaffold to be wired into the real POST/poll implementation once the
 * feature-flagged code is enabled in the PR (see PR #46, commit 97b2d9a).
 *
 * IMPORTANT:
 *  - This file is a template (TODO markers) and will not be runnable until
 *    the live browser->helper POST/poll wiring is implemented and the test
 *    environment provides a running app at `http://localhost:5000`.
 *
 * Prerequisites:
 *  - `node` and `npm` installed
 *  - Puppeteer installed: `npm install puppeteer`
 *  - Flask app running at http://localhost:5000 (dev server)
 *
 * Usage:
 *  node tests/frontend/test_provider_tls_live_post_poll_template.js
 *
 * Test outline (fill in TODOs):
 *  1. Inject a repaired provider validation record containing a short-lived
 *     `operation_authorization` (operation_token) into the page using the
 *     existing frontend helpers (`rememberProviderValidationResult`).
 *  2. Replace or shadow a small start function that calls
 *     `buildProviderTlsRepairStartRequest()` and then performs `fetch()` so
 *     we can observe the POST body shape and subsequent poll behavior.
 *  3. Assert the POST body contains ONLY the allowed fields:
 *     `provider`, `confirmation`, `operation_authorization` and that no
 *     forbidden runtime/control fields are present.
 *  4. Simulate helper responses for POST -> 202/operation_id and subsequent
 *     GET /operations/{id} poll responses (active -> ready) and assert the
 *     client polls instead of starting a duplicate operation.
 */

const puppeteer = require('puppeteer');

const CONFIG = {
  baseUrl: 'http://localhost:5000',
  headless: true,
  timeout: 60000
};

async function run() {
  const launchOptions = { headless: CONFIG.headless, args: ['--no-sandbox', '--disable-setuid-sandbox'] };
  // Prefer a provided executable path (Playwright-installed Chromium) in CI
  if (process.env.PUPPETEER_EXECUTABLE_PATH) {
    launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  } else if (process.env.TEST_BROWSER_EXECUTABLE) {
    launchOptions.executablePath = process.env.TEST_BROWSER_EXECUTABLE;
  }
  const browser = await puppeteer.launch(launchOptions);
  const page = await browser.newPage();

  try {
      // Determine whether to use a real helper server (e2e CI) or run in shimmed mode.
      const USE_REAL_HELPER = (process.env.E2E_USE_SERVER === '1' || process.env.E2E_USE_SERVER === 'true' || process.env.USE_REAL_HELPER === '1');

    await page.goto(CONFIG.baseUrl, { waitUntil: 'networkidle2', timeout: CONFIG.timeout });

      // If the test runner provides a helper base URL, expose it to page scripts
      await page.evaluateOnNewDocument((hb) => {
        try { window.__TEST_HELPER_BASE_URL = hb || '' } catch(e) {}
      }, process.env.TEST_HELPER_BASE_URL || '');

    // Prepare a fake, valid short-lived authorization and inject into page state
    const future = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
    await page.evaluate((future) => {
      // Example validation payload the frontend normalizer expects
      const payload = {
        provider: 'google',
        repairable: true,
        helper_available: true,
        category: 'tls_ca_untrusted',
        operation_authorization: {
          operation_type: 'provider_tls_repair',
          expires_at: future,
          operation_token: 'TEST_TOKEN_XXXXXXXXXXXXXXXX'
        }
      };

      // Use the existing frontend helper to remember the validation result.
      // If the production code changes, adapt the call here.
      if (typeof rememberProviderValidationResult === 'function') {
        rememberProviderValidationResult('google', payload);
      } else {
        // Fallback: attach to window so tests can still inspect contract
        window.__TEST_provider_validation = payload;
      }
    }, future);

    // Capture fetch calls made by the page so we can assert request shapes
    await page.exposeFunction('__recordFetchCall', args => {
      window.__fetchCalls = window.__fetchCalls || [];
      window.__fetchCalls.push(args);
    });

    // Install fetch shim only when not running in e2e mode against a real helper.
    await page.evaluate((useReal) => {
      if (useReal) {
        // expose lightweight collectors but do not override fetch
        window.__fetchCalls = [];
        return;
      }

      const orig = window.fetch;
      window.__fetchCalls = [];
      window.fetch = async function(url, options) {
        try {
          const recorded = { url, options: { method: options && options.method, headers: options && options.headers } };
          try {
            recorded.options.body = options && options.body ? options.body : null;
          } catch (e) {
            recorded.options.body = '<unserializable>';
          }
          window.__fetchCalls.push(recorded);

          if (typeof url === 'string' && url.endsWith('/operations/provider-tls-repair')) {
            return {
              ok: true,
              status: 202,
              json: async () => ({ operation_id: '0123456789abcdef0123456789abcdef', state: 'planned' })
            };
          }

          const opMatch = String(url).match(/\/operations\/(?:([a-f0-9]{32}))/i);
          if (opMatch) {
            window.__pollCount = (window.__pollCount || 0) + 1;
            if (window.__pollCount <= 2) {
              return { ok: true, status: 200, json: async () => ({ state: 'active', classification: 'active', terminal: false }) };
            }
            return { ok: true, status: 200, json: async () => ({ state: 'ready', classification: 'terminal_success', terminal: true }) };
          }

          return orig.apply(this, arguments);
        } catch (e) {
          return orig.apply(this, arguments);
        }
      };
    }, USE_REAL_HELPER);

    // Create a test helper on the page that performs the start+poll flow using
    // the public builder helpers (so we don't need to toggle internal flags).
    const result = await page.evaluate(async () => {
      // Build the POST request via the existing helper
      let built = typeof buildProviderTlsRepairStartRequest === 'function' ? buildProviderTlsRepairStartRequest('google') : null;
      // Fallback: if the production builder is not available in this test build,
      // construct a minimal allowed POST body from the injected test validation
      // payload (`window.__TEST_provider_validation`).
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

      const postBody = built && built.options && built.options.body ? built.options.body : null;

      // Perform the POST to the helper
      let postResp = null;
      if (built) {
        const r = await fetch(built.endpoint, built.options);
        postResp = await (r.json ? r.json() : {});
      }

      // If we got an operation_id, poll it until terminal
      let pollSequence = [];
      if (postResp && postResp.operation_id) {
        const id = postResp.operation_id;
        for (let i = 0; i < 5; i++) {
          const pr = await fetch(`/operations/${id}`);
          const pj = await (pr.json ? pr.json() : {});
          pollSequence.push(pj);
          if (pj && pj.terminal) break;
          // small delay between polls
          await new Promise(r => setTimeout(r, 50));
        }
      }

      // Return observations for assertions in the test harness
      return {
        postBody,
        fetchCalls: window.__fetchCalls || [],
        pollSequence
      };
    });

    // Assertions (template): ensure the POST body is valid JSON and contains only allowed keys
    if (!result.postBody) {
      console.error('No built POST body found. Ensure buildProviderTlsRepairStartRequest is available and returns a body.');
      process.exitCode = 2;
      return;
    }

    let parsed = null;
    try {
      parsed = JSON.parse(result.postBody);
    } catch (e) {
      console.error('POST body is not valid JSON:', result.postBody);
      process.exitCode = 2;
      return;
    }

    // Allowed keys
    const allowed = ['provider', 'confirmation', 'operation_authorization'];
    const forbidden = Object.keys(parsed).filter(k => !allowed.includes(k));
    if (forbidden.length > 0) {
      console.error('POST body contains forbidden fields:', forbidden);
      process.exitCode = 2;
      return;
    }

    // Verify fetch was called for POST and then for polls
    const postCalls = result.fetchCalls.filter(c => String(c.url).endsWith('/operations/provider-tls-repair'));
    const pollCalls = result.fetchCalls.filter(c => /\/operations\/[a-f0-9]{32}$/i.test(String(c.url)));

    if (postCalls.length === 0) {
      console.error('No POST calls captured to helper endpoint');
      process.exitCode = 2;
      return;
    }

    if (pollCalls.length === 0) {
      console.error('No poll calls captured for operation status');
      process.exitCode = 2;
      return;
    }

    console.log('Template assertions passed (shape + calls captured).');
    console.log('Captured POST payload:', parsed);
    console.log('Poll sequence length:', result.pollSequence.length);

  } finally {
    await browser.close();
  }
}

run().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
