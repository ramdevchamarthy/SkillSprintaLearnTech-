'use strict';
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');

const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const DB = path.join(__dirname, 'e2e.sqlite');
const FILES = path.join(__dirname, 'e2e-files');
const A = '9876543210', B_UNUSED = '9123456780', F = '9000011111';

let srv, browser;
const devices = [];

function waitFor(fn, ms = 10000) {
  return (async () => {
    const t = Date.now();
    while (Date.now() - t < ms) {
      const v = await fn();
      if (v) return v;
      await new Promise((r) => setTimeout(r, 150));
    }
    throw new Error('timed out waiting');
  })();
}

async function device() {
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    try { localStorage.setItem('ss-splashed', '1'); localStorage.setItem('ss-onboarded', '1'); } catch (e) {}
  });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const d = { ctx, page, errors };
  devices.push(d);
  return d;
}

async function saveProfile(page, name) {
  // The profile page only opens once a profile exists. Create a placeholder first, as onboarding would.
  await page.goto(BASE + '/');
  await page.evaluate(() => {
    if (!localStorage.getItem('ss-profile')) {
      localStorage.setItem('ss-profile', JSON.stringify({ name: 'x', avatar: 0, college: '', degree: '', branch: '', year: '1', sem: '1', subjects: '', exam: '', hours: '2', level: 'Beginner', lang: 'English', style: 'Text', goals: '' }));
    }
  });
  await page.goto(BASE + '/#profile');
  await page.fill('#pf-name', name);
  await page.fill('#pf-college', 'Test College');
  await page.fill('#pf-degree', 'B.Tech');
  await page.fill('#pf-branch', 'CSE');
  await page.fill('#pf-subjects', 'DSA');
  await page.fill('#pf-exam', '2030-03-01');
  await page.fill('#pf-hours', '2');
  await page.fill('#pf-goals', 'Pass DSA');
  await page.click('#pform button[type="submit"]');
  await page.waitForTimeout(200);
}

async function signIn(page, phone) {
  await page.goto(BASE + '/#sync');
  await page.fill('#sy-phone', phone);
  await page.click('#sy-send');
  await page.waitForSelector('#sy-codebox:not([hidden])');
  const status = await page.textContent('#sync-status');
  const code = status.match(/code is (\d{6})/)[1];
  await page.fill('#sy-code', code);
  await page.click('#sy-verify');
}

async function serverState(page) {
  const r = await page.request.get(BASE + '/api/state');
  return (await r.json()).state;
}
async function serverUploads(page) {
  const r = await page.request.get(BASE + '/api/uploads');
  return r.json();
}

before(async () => {
  fs.rmSync(DB, { force: true });
  srv = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, SESSION_SECRET: 'e2e-secret-0123456789', DEMO_OTP: '1', DB_PATH: DB, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    srv.stdout.on('data', (c) => { if (String(c).includes('SkillSprinta API')) resolve(); });
    srv.stderr.on('data', () => {});
    srv.on('exit', (code) => reject(new Error('server exited ' + code)));
  });
  browser = await chromium.launch();
});

after(async () => {
  for (const d of devices) await d.ctx.close().catch(() => {});
  if (browser) await browser.close();
  if (srv) srv.kill();
  fs.rmSync(DB, { force: true });
});

describe('the app is served from the API origin', () => {
  test('app pages load and unknown paths are not served', async () => {
    assert.equal((await fetch(BASE + '/')).status, 200);
    assert.match(await (await fetch(BASE + '/')).text(), /SkillSprinta/);
    assert.equal((await fetch(BASE + '/sprintmap.html')).status, 200);
    assert.equal((await fetch(BASE + '/secret.txt')).status, 404);
  });
});

describe('sync across two devices', () => {
  let deviceA, deviceB;

  test('device A: sign in and the profile is saved to the account', async () => {
    deviceA = await device();
    await saveProfile(deviceA.page, 'Asha');
    await signIn(deviceA.page, A);
    await deviceA.page.waitForSelector('#sy-signout', { state: 'visible' });
    const state = await waitFor(async () => {
      const s = await serverState(deviceA.page);
      return s['ss-profile'] ? s : null;
    });
    assert.match(state['ss-profile'], /Asha/);
    assert.equal(deviceA.errors.length, 0, deviceA.errors.join('; '));
  });

  test('device B: a new browser signs in and gets the saved profile', async () => {
    deviceB = await device();
    await signIn(deviceB.page, A);
    await deviceB.page.waitForSelector('#sy-signout', { state: 'visible', timeout: 15000 });
    await deviceB.page.goto(BASE + '/#profile');
    await waitFor(async () => (await deviceB.page.inputValue('#pf-name')) === 'Asha');
    assert.equal(deviceB.errors.length, 0, deviceB.errors.join('; '));
  });

  test('changes on device B are saved to the account', async () => {
    await saveProfile(deviceB.page, 'Asha K');
    await waitFor(async () => (await serverState(deviceB.page))['ss-profile']?.includes('Asha K'));
  });

  test('the server enforces the 5-file limit even if the browser says there is room', async () => {
    const page = deviceA.page;
    await page.goto(BASE + '/#upload');
    await page.setInputFiles('#fup', [1, 2, 3, 4, 5].map((i) => path.join(FILES, `f${i}.pdf`)));
    await waitFor(async () => (await serverUploads(page)).uploadUsed === 5);
    // Simulate a second device or a changed browser: local counter says there is room.
    await page.evaluate(() => localStorage.setItem('ss-upload-used', '0'));
    await page.setInputFiles('#fup', [path.join(FILES, 'f6.pdf')]);
    await waitFor(async () => /free plan allows 5/.test(await page.textContent('#up-msg')));
    assert.equal((await serverUploads(page)).uploadUsed, 5);
    const names = await page.$$eval('[data-id], .file-row, li', (els) => els.map((e) => e.textContent).join(' '));
    assert.doesNotMatch(names, /f6\.pdf/);
  });

  test('a conflict asks which copy to keep, and Cancel keeps this browser copy', async () => {
    const d = await device();
    await saveProfile(d.page, 'Local G');
    await d.page.goto(BASE + '/#sync');
    await d.page.fill('#sy-phone', A);
    await d.page.click('#sy-send');
    await d.page.waitForSelector('#sy-codebox:not([hidden])');
    const code = (await d.page.textContent('#sync-status')).match(/code is (\d{6})/)[1];
    await d.page.fill('#sy-code', code);
    await d.page.click('#sy-verify');
    await d.page.waitForSelector('#ask:not([hidden])');
    assert.match(await d.page.textContent('#ask-msg'), /different progress/);
    await d.page.click('#ask-no');
    await waitFor(async () => (await serverState(d.page))['ss-profile']?.includes('Local G'));
    assert.equal(d.errors.length, 0, d.errors.join('; '));
  });
});

describe('uploads made before signing in are counted on the account', () => {
  test('two local uploads become two counted uploads when the device signs in', async () => {
    const d = await device();
    await saveProfile(d.page, 'Fia');
    await d.page.goto(BASE + '/#upload');
    await d.page.setInputFiles('#fup', [path.join(FILES, 'f1.pdf'), path.join(FILES, 'f2.pdf')]);
    await waitFor(async () => (await d.page.evaluate(() => localStorage.getItem('ss-upload-used'))) === '2');
    await signIn(d.page, F);
    await d.page.waitForSelector('#sy-signout', { state: 'visible', timeout: 15000 });
    const count = await waitFor(async () => {
      const u = await serverUploads(d.page);
      return u.uploadUsed === 2 ? u : null;
    });
    assert.equal(count.uploadUsed, 2);
    assert.equal(count.freeLimit, 5);
  });
});

describe('signed-out use still works', () => {
  test('without an account the app saves only in the browser and shows the sign-in prompt', async () => {
    const d = await device();
    await saveProfile(d.page, 'Solo');
    await d.page.goto(BASE + '/#profile');
    await d.page.goto(BASE + '/#sync');
    await d.page.waitForSelector('#sy-phone', { state: 'visible' });
    assert.match(await d.page.textContent('#sync-status'), /Not signed in/);
    assert.equal(d.errors.length, 0, d.errors.join('; '));
  });
});

describe('OCR, AI tutor and contact form in the browser', () => {
  test('a scanned PDF with no text layer is read with OCR after signing in', { skip: !hasOcrTools() }, async () => {
    const d = await device();
    await saveProfile(d.page, 'Scan');
    await signIn(d.page, '9000022222');
    await d.page.waitForSelector('#sy-signout', { state: 'visible', timeout: 15000 });
    await d.page.goto(BASE + '/#upload');
    await d.page.setInputFiles('#fup', [path.join(FILES, 'scanned.pdf')]);
    const text = await waitFor(async () => {
      const files = JSON.parse((await d.page.evaluate(() => localStorage.getItem('ss-files'))) || '[]');
      const f = files.find((x) => x.name === 'scanned.pdf' && x.status === 'done');
      return f && f.ocr ? f.text : null;
    }, 60000);
    assert.match(text, /binary search/i);
    assert.equal(d.errors.length, 0, d.errors.join('; '));
  });

  test('the AI tutor page explains that it is not connected when there is no key', async () => {
    const d = await device();
    await saveProfile(d.page, 'Tutor');
    await signIn(d.page, '9000033333');
    await d.page.waitForSelector('#sy-signout', { state: 'visible', timeout: 15000 });
    await d.page.goto(BASE + '/#upload');
    await d.page.setInputFiles('#fup', [path.join(FILES, 'f1.pdf')]);
    await waitFor(async () => (JSON.parse((await d.page.evaluate(() => localStorage.getItem('ss-files'))) || '[]')).some((x) => x.status === 'done'), 30000);
    await d.page.goto(BASE + '/#tutor');
    await d.page.waitForSelector('#tu-ask', { state: 'visible' });
    await d.page.fill('#tu-q', 'What is a linked list?');
    await d.page.click('#tu-ask');
    await waitFor(async () => /not connected/.test(await d.page.textContent('#tu-msg')));
    assert.equal(d.errors.length, 0, d.errors.join('; '));
  });

  test('the contact form says email is not connected on this server', async () => {
    const d = await device();
    await d.page.goto(BASE + '/#contact');
    await d.page.waitForSelector('#cform', { state: 'visible' });
    await d.page.fill('#cf-name', 'Ravi');
    await d.page.fill('#cf-email', 'ravi@example.com');
    await d.page.fill('#cf-msg', 'Is there a pricing page?');
    await d.page.click('#cform button[type="submit"]');
    await waitFor(async () => /not connected/.test(await d.page.textContent('#cf-out')));
    assert.equal(d.errors.length, 0, d.errors.join('; '));
  });
});

function hasOcrTools() {
  const { spawnSync } = require('node:child_process');
  return !spawnSync('tesseract', ['--version']).error && !spawnSync('pdftoppm', ['-v']).error;
}
