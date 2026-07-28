#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const puppeteer = require('puppeteer');

const BASE_URL = (process.env.TOWERSCOUT_BASE_URL || '').replace(/\/+$/, '');
const ALT_BASE_URL = (process.env.TOWERSCOUT_ALT_BASE_URL || '').replace(/\/+$/, '');
const EXECUTABLE_PATH = process.env.TOWERSCOUT_EXECUTABLE_PATH || '';
const READY_SIGNAL_PATH = process.env.TOWERSCOUT_BROWSER_READY_SIGNAL || '';
const TRANSITION_TIMEOUT_MS = Number(
  process.env.TOWERSCOUT_RESTART_TRANSITION_TIMEOUT_MS || 120000
);

function requireConfiguration() {
  for (const [name, value] of [
    ['TOWERSCOUT_BASE_URL', BASE_URL],
    ['TOWERSCOUT_ALT_BASE_URL', ALT_BASE_URL],
    ['TOWERSCOUT_EXECUTABLE_PATH', EXECUTABLE_PATH],
    ['TOWERSCOUT_BROWSER_READY_SIGNAL', READY_SIGNAL_PATH]
  ]) {
    if (!value) {
      throw new Error(`${name} is required.`);
    }
  }
  if (!Number.isFinite(TRANSITION_TIMEOUT_MS) || TRANSITION_TIMEOUT_MS < 10000) {
    throw new Error('TOWERSCOUT_RESTART_TRANSITION_TIMEOUT_MS must be at least 10000.');
  }
}

async function waitFor(check, description) {
  const deadline = Date.now() + TRANSITION_TIMEOUT_MS;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      if (await check()) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  const suffix = lastError ? ` Last error: ${lastError.message}` : '';
  throw new Error(`Timed out waiting for ${description}.${suffix}`);
}

async function readinessFromPage(page) {
  return page.evaluate(async () => {
    try {
      const response = await fetch('/api/readiness', { cache: 'no-store' });
      const payload = await response.json();
      return {
        reachable: true,
        state: String(payload.state || '')
      };
    } catch (_error) {
      return {
        reachable: false,
        state: ''
      };
    }
  });
}

async function assertTowerScoutShell(page, url) {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  assert.strictEqual(await page.title(), 'TowerScout');
  assert.strictEqual(
    await page.$eval('#setup_wizard_div', element => element.id),
    'setup_wizard_div'
  );
  const readiness = await readinessFromPage(page);
  assert.strictEqual(readiness.reachable, true);
  assert.ok(
    ['setup_required', 'degraded', 'ready'].includes(readiness.state),
    `Unexpected readiness state: ${readiness.state}`
  );
  return readiness.state;
}

async function run() {
  requireConfiguration();
  const browser = await puppeteer.launch({
    executablePath: EXECUTABLE_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  try {
    const initialState = await assertTowerScoutShell(page, BASE_URL);
    fs.writeFileSync(READY_SIGNAL_PATH, 'browser_ready', {
      encoding: 'utf8',
      flag: 'wx'
    });

    await waitFor(
      async () => !(await readinessFromPage(page)).reachable,
      'the dedicated TowerScout app to stop'
    );
    await waitFor(
      async () => (await readinessFromPage(page)).reachable,
      'the dedicated TowerScout app to restart'
    );

    const recoveredState = await assertTowerScoutShell(page, BASE_URL);
    const alternatePage = await browser.newPage();
    let alternateState;
    try {
      alternateState = await assertTowerScoutShell(alternatePage, ALT_BASE_URL);
    } finally {
      await alternatePage.close();
    }

    console.log(
      JSON.stringify({
        result: 'passed',
        browser: 'edge',
        initial_state: initialState,
        recovered_state: recoveredState,
        alternate_origin_state: alternateState,
        observed_stop: true,
        observed_restart: true
      })
    );
  } finally {
    await browser.close();
  }
}

run().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
