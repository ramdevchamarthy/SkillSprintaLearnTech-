'use strict';
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('./server.js');

const SECRET = 'test-secret-0123456789abcdef';

async function start(extraEnv = {}) {
  const app = createApp({
    dbPath: ':memory:',
    env: { SESSION_SECRET: SECRET, DEMO_OTP: '1', ...extraEnv },
  });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const stop = async () => { app.server.closeAllConnections(); await app.close(); };
  return { app, base, stop };
}

async function api(base, method, path, { body, cookie, rawBody, contentType } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  let payload;
  if (body !== undefined) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  if (rawBody !== undefined) { headers['content-type'] = contentType; payload = rawBody; }
  const r = await fetch(base + path, { method, headers, body: payload });
  const text = await r.text();
  let data = null; try { data = JSON.parse(text); } catch (_) {}
  return { status: r.status, data, text, setCookie: r.headers.get('set-cookie') };
}

async function login(base, phone = '9876543210') {
  const req = await api(base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone } });
  assert.equal(req.status, 200, JSON.stringify(req.data));
  const v = await api(base, 'POST', '/api/auth/otp/verify', { body: { country: '+91', phone, code: req.data.code } });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  return { cookie: v.setCookie.split(';')[0], user: v.data.user };
}

const pdf = (name, extra = {}) => ({ name, ext: 'pdf', size: 1000, text: 'some extracted text', ...extra });

describe('configuration', () => {
  test('refuses to start without a strong SESSION_SECRET', () => {
    assert.throws(() => createApp({ dbPath: ':memory:', env: { SESSION_SECRET: 'short', DEMO_OTP: '' } }), /SESSION_SECRET/);
  });
});

describe('sign-in with one-time codes', () => {
  test('rejects an invalid phone number', async () => {
    const t = await start();
    try {
      const r = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '12345' } });
      assert.equal(r.status, 400);
    } finally { await t.stop(); }
  });

  test('a correct code signs in and sets an HttpOnly session cookie', async () => {
    const t = await start();
    try {
      const req = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      assert.match(String(req.data.code), /^\d{6}$/);
      const v = await api(t.base, 'POST', '/api/auth/otp/verify', { body: { country: '+91', phone: '9876543210', code: req.data.code } });
      assert.equal(v.status, 200);
      assert.match(v.setCookie, /ss_session=/);
      assert.match(v.setCookie, /HttpOnly/);
      assert.match(v.setCookie, /SameSite=Lax/);
      assert.equal(v.data.user.phone, '+919876543210');
    } finally { await t.stop(); }
  });

  test('a code cannot be used twice', async () => {
    const t = await start();
    try {
      const req = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      const body = { country: '+91', phone: '9876543210', code: req.data.code };
      assert.equal((await api(t.base, 'POST', '/api/auth/otp/verify', { body })).status, 200);
      assert.equal((await api(t.base, 'POST', '/api/auth/otp/verify', { body })).status, 401);
    } finally { await t.stop(); }
  });

  test('a wrong code is refused', async () => {
    const t = await start();
    try {
      const req = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      const wrong = req.data.code === '000000' ? '111111' : '000000';
      const v = await api(t.base, 'POST', '/api/auth/otp/verify', { body: { country: '+91', phone: '9876543210', code: wrong } });
      assert.equal(v.status, 401);
      assert.equal(v.setCookie, null);
    } finally { await t.stop(); }
  });

  test('after 5 wrong attempts the correct code is also locked out', async () => {
    const t = await start();
    try {
      const req = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      const wrong = req.data.code === '000000' ? '111111' : '000000';
      const body = (code) => ({ country: '+91', phone: '9876543210', code });
      for (let i = 0; i < 5; i++) {
        assert.equal((await api(t.base, 'POST', '/api/auth/otp/verify', { body: body(wrong) })).status, 401);
      }
      assert.equal((await api(t.base, 'POST', '/api/auth/otp/verify', { body: body(req.data.code) })).status, 429);
    } finally { await t.stop(); }
  });

  test('an expired code is refused', async () => {
    const t = await start();
    try {
      const req = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      t.app.db.prepare('UPDATE otps SET expires_at = ?').run(new Date(Date.now() - 1000).toISOString());
      const v = await api(t.base, 'POST', '/api/auth/otp/verify', { body: { country: '+91', phone: '9876543210', code: req.data.code } });
      assert.equal(v.status, 401);
      assert.match(v.data.error, /expired/);
    } finally { await t.stop(); }
  });

  test('more than 3 code requests in 10 minutes is refused', async () => {
    const t = await start();
    try {
      for (let i = 0; i < 3; i++) {
        assert.equal((await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } })).status, 200);
      }
      assert.equal((await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } })).status, 429);
    } finally { await t.stop(); }
  });

  test('in production the code is never returned, and with no SMS provider sending fails safely', async () => {
    const t = await start({ DEMO_OTP: '', SMS_PROVIDER: '', NODE_ENV: 'production' });
    try {
      const r = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      assert.equal(r.status, 503);
      assert.equal(r.data.code, undefined);
      assert.doesNotMatch(r.text, /\b\d{6}\b/);
    } finally { await t.stop(); }
  });
});

describe('demo SMS provider', () => {
  test('the demo provider is refused in production', () => {
    assert.throws(() => createApp({ dbPath: ':memory:', env: { SESSION_SECRET: SECRET, NODE_ENV: 'production', SMS_PROVIDER: 'demo' } }), /demo SMS provider cannot run in production/);
    assert.throws(() => createApp({ dbPath: ':memory:', env: { SESSION_SECRET: SECRET, NODE_ENV: 'production', DEMO_OTP: '1' } }), /cannot run in production/);
  });

  test('live demo sign-in works in production only with the explicit opt-in', async () => {
    const t = await start({ DEMO_OTP: '', SMS_PROVIDER: 'demo', NODE_ENV: 'production', ALLOW_DEMO_SMS_IN_PRODUCTION: '1' });
    try {
      const r = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      assert.equal(r.status, 200);
      assert.equal(r.data.demo, true);
    } finally { await t.stop(); }
  });

  test('outside production the demo SMS is on by default and returns the code as a demo SMS', async () => {
    const t = await start({ DEMO_OTP: '', SMS_PROVIDER: '' });
    try {
      const r = await api(t.base, 'POST', '/api/auth/otp/request', { body: { country: '+91', phone: '9876543210' } });
      assert.equal(r.status, 200);
      assert.equal(r.data.demo, true);
      assert.match(String(r.data.code), /^\d{6}$/);
    } finally { await t.stop(); }
  });
});

describe('sessions', () => {
  test('protected routes refuse requests with no session', async () => {
    const t = await start();
    try {
      assert.equal((await api(t.base, 'GET', '/api/me')).status, 401);
      assert.equal((await api(t.base, 'GET', '/api/uploads')).status, 401);
      assert.equal((await api(t.base, 'PUT', '/api/state', { body: {} })).status, 401);
    } finally { await t.stop(); }
  });

  test('a forged or random cookie is refused', async () => {
    const t = await start();
    try {
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie: 'ss_session=not-a-real-token' })).status, 401);
    } finally { await t.stop(); }
  });

  test('a session works until logout, then stops working', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie })).status, 200);
      await api(t.base, 'POST', '/api/auth/logout', { cookie });
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie })).status, 401);
    } finally { await t.stop(); }
  });

  test('the session token is stored hashed, not in plain text', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const token = decodeURIComponent(cookie.split('=')[1]);
      const rows = t.app.db.prepare('SELECT token_hash FROM sessions').all();
      assert.equal(rows.length, 1);
      assert.notEqual(rows[0].token_hash, token);
      assert.equal(JSON.stringify(t.app.db.prepare('SELECT * FROM sessions').all()).includes(token), false);
    } finally { await t.stop(); }
  });

  test('one user cannot read or change another user\'s data', async () => {
    const t = await start();
    try {
      const a = await login(t.base, '9876543210');
      const b = await login(t.base, '9123456780');
      await api(t.base, 'PUT', '/api/state', { cookie: a.cookie, body: { secret: 'A' } });
      assert.deepEqual((await api(t.base, 'GET', '/api/state', { cookie: b.cookie })).data, { state: {} });
      const up = await api(t.base, 'POST', '/api/uploads', { cookie: a.cookie, body: pdf('a.pdf') });
      assert.equal((await api(t.base, 'GET', `/api/uploads/${up.data.id}`, { cookie: b.cookie })).status, 404);
      assert.equal((await api(t.base, 'DELETE', `/api/uploads/${up.data.id}`, { cookie: b.cookie })).status, 404);
    } finally { await t.stop(); }
  });
});

describe('saved state and profile', () => {
  test('state and profile are saved and read back for the signed-in user', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'PUT', '/api/state', { cookie, body: { map: { x: 1 } } })).status, 200);
      assert.deepEqual((await api(t.base, 'GET', '/api/state', { cookie })).data, { state: { map: { x: 1 } } });
      assert.equal((await api(t.base, 'PUT', '/api/profile', { cookie, body: { name: 'Asha', exam: '2027-03-01' } })).status, 200);
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie })).data.user.profile.name, 'Asha');
    } finally { await t.stop(); }
  });

  test('a non-object body is refused', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'PUT', '/api/state', { cookie, body: [1, 2] })).status, 400);
    } finally { await t.stop(); }
  });

  test('requests that are not JSON are refused', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const r = await api(t.base, 'PUT', '/api/state', { cookie, rawBody: 'x=1', contentType: 'text/plain' });
      assert.equal(r.status, 415);
    } finally { await t.stop(); }
  });
});

describe('free upload limit (server-side)', () => {
  test('the 6th PDF or PPT is refused, and the 5 allowed ones count', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      for (let i = 1; i <= 5; i++) {
        const r = await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf(`f${i}.pdf`) });
        assert.equal(r.status, 201);
        assert.equal(r.data.uploadUsed, i);
      }
      const sixth = await api(t.base, 'POST', '/api/uploads', { cookie, body: { name: 'deck.pptx', ext: 'pptx', size: 500, text: 'slide' } });
      assert.equal(sixth.status, 403);
      assert.match(sixth.data.error, /5 PDF or PPT/);
    } finally { await t.stop(); }
  });

  test('parallel requests cannot get past the limit', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const results = await Promise.all(
        Array.from({ length: 8 }, (_, i) => api(t.base, 'POST', '/api/uploads', { cookie, body: pdf(`p${i}.pdf`) })),
      );
      const codes = results.map((r) => r.status);
      assert.equal(codes.filter((c) => c === 201).length, 5);
      assert.equal(codes.filter((c) => c === 403).length, 3);
      assert.equal(t.app.db.prepare('SELECT used FROM quota').get().used, 5);
    } finally { await t.stop(); }
  });

  test('deleting an upload does not give the slot back', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const ids = [];
      for (let i = 1; i <= 5; i++) ids.push((await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf(`f${i}.pdf`) })).data.id);
      const del = await api(t.base, 'DELETE', `/api/uploads/${ids[0]}`, { cookie });
      assert.equal(del.status, 200);
      assert.equal(del.data.uploadUsed, 5);
      const again = await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf('new.pdf') });
      assert.equal(again.status, 403);
    } finally { await t.stop(); }
  });

  test('a deleted upload is gone and its text is cleared', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const up = await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf('notes.pdf') });
      assert.equal((await api(t.base, 'GET', `/api/uploads/${up.data.id}`, { cookie })).data.text, 'some extracted text');
      await api(t.base, 'DELETE', `/api/uploads/${up.data.id}`, { cookie });
      assert.equal((await api(t.base, 'GET', `/api/uploads/${up.data.id}`, { cookie })).status, 404);
      assert.equal(t.app.db.prepare('SELECT text FROM uploads WHERE id = ?').get(up.data.id).text, '');
      assert.equal((await api(t.base, 'GET', '/api/uploads', { cookie })).data.uploads.length, 0);
    } finally { await t.stop(); }
  });

  test('TXT and DOCX files are not counted against the limit', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      for (let i = 0; i < 7; i++) {
        assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie, body: { name: `n${i}.txt`, ext: 'txt', size: 100, text: 'notes' } })).status, 201);
      }
      assert.equal((await api(t.base, 'GET', '/api/uploads', { cookie })).data.uploadUsed, 0);
    } finally { await t.stop(); }
  });

  test('unsupported types, bad sizes and oversized text are refused', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie, body: { name: 'x.exe', ext: 'exe', size: 10, text: 'a' } })).status, 400);
      assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie, body: { name: 'x.pdf', ext: 'pdf', size: 21 * 1024 * 1024, text: 'a' } })).status, 400);
      assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie, body: { name: 'x.txt', ext: 'txt', size: 10, text: 'a'.repeat(150001) } })).status, 400);
      assert.equal((await api(t.base, 'GET', '/api/uploads', { cookie })).data.uploadUsed, 0);
    } finally { await t.stop(); }
  });

  test('a file name with path separators is cleaned', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      const r = await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf('../../etc/passwd') });
      assert.equal(r.status, 201);
      const list = await api(t.base, 'GET', '/api/uploads', { cookie });
      assert.equal(list.data.uploads[0].name.includes('/'), false);
    } finally { await t.stop(); }
  });
});

describe('account', () => {
  test('signing out and deleting the account both end access', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'POST', '/api/account/delete', { cookie, body: {} })).status, 200);
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie })).status, 401);
      assert.equal(t.app.db.prepare('SELECT COUNT(*) AS c FROM users').get().c, 0);
    } finally { await t.stop(); }
  });

  test('unknown routes return 404 and never leak details', async () => {
    const t = await start();
    try {
      const r = await api(t.base, 'GET', '/api/nope');
      assert.equal(r.status, 404);
    } finally { await t.stop(); }
  });
});

describe('upload allowance survives account deletion', () => {
  test('deleting the account and signing in again does not reset the 5 free files', async () => {
    const t = await start();
    try {
      const a = await login(t.base, '9876543210');
      for (let i = 1; i <= 5; i++) assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie: a.cookie, body: pdf(`f${i}.pdf`) })).status, 201);
      assert.equal((await api(t.base, 'POST', '/api/account/delete', { cookie: a.cookie, body: {} })).status, 200);
      const b = await login(t.base, '9876543210');
      const r = await api(t.base, 'POST', '/api/uploads', { cookie: b.cookie, body: pdf('again.pdf') });
      assert.equal(r.status, 403);
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie: b.cookie })).data.user.uploadUsed, 5);
    } finally { await t.stop(); }
  });
});

describe('clearing data', () => {
  test('clear removes profile, progress and uploads, but keeps the upload count', async () => {
    const t = await start();
    try {
      const { cookie } = await login(t.base);
      await api(t.base, 'PUT', '/api/profile', { cookie, body: { name: 'Asha' } });
      await api(t.base, 'PUT', '/api/state', { cookie, body: { 'ss-profile': '{}' } });
      await api(t.base, 'POST', '/api/uploads', { cookie, body: pdf('a.pdf') });
      const r = await api(t.base, 'POST', '/api/data/clear', { cookie, body: {} });
      assert.equal(r.status, 200);
      assert.equal(r.data.uploadUsed, 1);
      assert.deepEqual((await api(t.base, 'GET', '/api/state', { cookie })).data, { state: {} });
      assert.equal((await api(t.base, 'GET', '/api/me', { cookie })).data.user.profile.name, undefined);
      assert.equal((await api(t.base, 'GET', '/api/uploads', { cookie })).data.uploads.length, 0);
    } finally { await t.stop(); }
  });
});

describe('admin', () => {
  const ADMIN = '+919876543210';

  test('non-admins are refused and signed-out visitors are asked to sign in', async () => {
    const t = await start({ ADMIN_PHONES: ADMIN });
    try {
      assert.equal((await api(t.base, 'GET', '/api/admin/summary')).status, 401);
      const u = await login(t.base, '9123456780');
      assert.equal((await api(t.base, 'GET', '/api/admin/summary', { cookie: u.cookie })).status, 403);
      assert.equal((await api(t.base, 'GET', '/api/admin/users', { cookie: u.cookie })).status, 403);
    } finally { await t.stop(); }
  });

  test('an admin sees counts and masked phone numbers, never profiles or uploaded text', async () => {
    const t = await start({ ADMIN_PHONES: ADMIN });
    try {
      const other = await login(t.base, '9123456780');
      await api(t.base, 'PUT', '/api/profile', { cookie: other.cookie, body: { name: 'Secret Name' } });
      await api(t.base, 'PUT', '/api/state', { cookie: other.cookie, body: { 'ss-files': '[{"text":"private notes"}]' } });
      await api(t.base, 'POST', '/api/uploads', { cookie: other.cookie, body: { name: 'notes.pdf', ext: 'pdf', size: 10, text: 'private notes' } });
      const admin = await login(t.base, '9876543210');
      const summary = await api(t.base, 'GET', '/api/admin/summary', { cookie: admin.cookie });
      assert.equal(summary.status, 200);
      assert.equal(summary.data.users, 2);
      assert.equal(summary.data.countedUploads, 1);
      const users = await api(t.base, 'GET', '/api/admin/users', { cookie: admin.cookie });
      const text = users.text;
      assert.doesNotMatch(text, /9123456780/);
      assert.doesNotMatch(text, /Secret Name/);
      assert.doesNotMatch(text, /private notes/);
      assert.match(text, /•••/);
      assert.equal(users.data.users.length, 2);
    } finally { await t.stop(); }
  });

  test('an admin can change a plan, the change is audited, and a paid plan is not limited', async () => {
    const t = await start({ ADMIN_PHONES: ADMIN });
    try {
      const u = await login(t.base, '9123456780');
      for (let i = 1; i <= 5; i++) await api(t.base, 'POST', '/api/uploads', { cookie: u.cookie, body: pdf(`f${i}.pdf`) });
      assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie: u.cookie, body: pdf('six.pdf') })).status, 403);
      const admin = await login(t.base, '9876543210');
      const list = (await api(t.base, 'GET', '/api/admin/users', { cookie: admin.cookie })).data.users;
      const target = list.find((x) => x.phone.endsWith('6780'));
      const r = await api(t.base, 'POST', `/api/admin/users/${target.id}/plan`, { cookie: admin.cookie, body: { plan: 'paid' } });
      assert.equal(r.status, 200);
      assert.equal((await api(t.base, 'POST', '/api/uploads', { cookie: u.cookie, body: pdf('six.pdf') })).status, 201);
      const log = await api(t.base, 'GET', '/api/admin/audit', { cookie: admin.cookie });
      assert.equal(log.data.entries[0].action, 'set-plan');
      assert.equal(log.data.entries[0].detail, 'paid');
      const bad = await api(t.base, 'POST', `/api/admin/users/${target.id}/plan`, { cookie: admin.cookie, body: { plan: 'vip' } });
      assert.equal(bad.status, 400);
      assert.equal((await api(t.base, 'POST', '/api/admin/users/nope/plan', { cookie: admin.cookie, body: { plan: 'paid' } })).status, 404);
    } finally { await t.stop(); }
  });

  test('the admin page is served', async () => {
    const t = await start({ ADMIN_PHONES: ADMIN });
    try {
      const r = await fetch(t.base + '/admin');
      assert.equal(r.status, 200);
      assert.match(await r.text(), /SkillSprinta admin/);
    } finally { await t.stop(); }
  });
});

// ---------- OCR, AI tutor and contact form ----------
const { spawnSync } = require('node:child_process');
const fsMod = require('node:fs');
const pathMod = require('node:path');
const hasTool = (name) => !spawnSync(name, ['--version']).error;

async function startWith(env = {}, { fetch: fakeFetch } = {}) {
  const app = createApp({ dbPath: ':memory:', env: { SESSION_SECRET: SECRET, DEMO_OTP: '1', ...env }, fetch: fakeFetch });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  return { app, base, stop: async () => { app.server.closeAllConnections(); await app.close(); } };
}

describe('OCR for scanned PDFs', () => {
  test('a non-PDF or a file that is not a PDF is refused', async () => {
    const t = await startWith();
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'POST', '/api/ocr', { cookie, body: { ext: 'txt', data: 'aGk=' } })).status, 400);
      const fake = await api(t.base, 'POST', '/api/ocr', { cookie, body: { ext: 'pdf', data: Buffer.from('hello').toString('base64') } });
      assert.equal(fake.status, 400);
      assert.match(fake.data.error, /not a PDF/);
    } finally { await t.stop(); }
  });

  test('OCR needs a signed-in user', async () => {
    const t = await startWith();
    try {
      assert.equal((await api(t.base, 'POST', '/api/ocr', { body: { ext: 'pdf', data: 'JVBERi0=' } })).status, 401);
    } finally { await t.stop(); }
  });

  test('OCR is limited to 10 PDFs a day per user', async () => {
    const t = await startWith();
    try {
      const { cookie } = await login(t.base);
      const bad = { ext: 'pdf', data: Buffer.from('%PDF-1.4 not really a pdf').toString('base64') };
      for (let i = 0; i < 10; i++) assert.equal((await api(t.base, 'POST', '/api/ocr', { cookie, body: bad })).status, 422);
      assert.equal((await api(t.base, 'POST', '/api/ocr', { cookie, body: bad })).status, 429);
    } finally { await t.stop(); }
  });

  test('reads text from a PDF page image with tesseract', { skip: !hasTool('tesseract') || !hasTool('pdftoppm') }, async () => {
    const t = await startWith();
    try {
      const { cookie } = await login(t.base);
      const pdfBytes = fsMod.readFileSync(pathMod.join(__dirname, 'e2e-files', 'f1.pdf'));
      const r = await api(t.base, 'POST', '/api/ocr', { cookie, body: { ext: 'pdf', data: pdfBytes.toString('base64') } });
      assert.equal(r.status, 200, JSON.stringify(r.data));
      assert.match(r.data.text, /Linked/i);
      assert.ok(r.data.pages >= 1);
    } finally { await t.stop(); }
  });
});

describe('AI tutor', () => {
  const okFetch = (answer = 'A linked list stores nodes.') => async (url, opts) => ({
    ok: true,
    json: async () => ({ content: [{ type: 'text', text: answer }] }),
    _url: url, _opts: opts,
  });

  test('without an API key the tutor says it is not connected and makes no request', async () => {
    let called = false;
    const t = await startWith({ ANTHROPIC_API_KEY: '' }, { fetch: async () => { called = true; } });
    try {
      const { cookie } = await login(t.base);
      const r = await api(t.base, 'POST', '/api/tutor/ask', { cookie, body: { question: 'What is a node?', context: 'Nodes hold data.', fileName: 'n.txt' } });
      assert.equal(r.status, 503);
      assert.match(r.data.error, /not connected/);
      assert.equal(called, false);
    } finally { await t.stop(); }
  });

  test('with a key, it calls the model with the notes and the key only in a header, and returns the answer', async () => {
    const seen = [];
    const fake = async (url, opts) => { seen.push({ url, opts }); return okFetch()(url, opts); };
    const t = await startWith({ ANTHROPIC_API_KEY: 'sk-test-123456789' }, { fetch: fake });
    try {
      const { cookie } = await login(t.base);
      const r = await api(t.base, 'POST', '/api/tutor/ask', { cookie, body: { question: 'What is a node?', context: 'Nodes hold data.', fileName: 'notes.txt' } });
      assert.equal(r.status, 200);
      assert.equal(r.data.answer, 'A linked list stores nodes.');
      assert.equal(r.data.model, 'claude-haiku-5-5');
      assert.doesNotMatch(r.text, /sk-test/);
      assert.equal(seen[0].url, 'https://api.anthropic.com/v1/messages');
      assert.equal(seen[0].opts.headers['x-api-key'], 'sk-test-123456789');
      const sent = JSON.parse(seen[0].opts.body);
      assert.equal(sent.model, 'claude-haiku-5-5');
      assert.match(sent.system, /Answer using only the notes/);
      assert.match(sent.messages[0].content, /<notes file="notes\.txt">[\s\S]*Nodes hold data\.[\s\S]*What is a node\?/);
    } finally { await t.stop(); }
  });

  test('empty questions, empty notes and provider failures are handled without leaking details', async () => {
    const t = await startWith({ ANTHROPIC_API_KEY: 'sk-test-123456789' }, { fetch: async () => ({ ok: false, status: 500 }) });
    try {
      const { cookie } = await login(t.base);
      assert.equal((await api(t.base, 'POST', '/api/tutor/ask', { cookie, body: { question: '', context: 'x' } })).status, 400);
      assert.equal((await api(t.base, 'POST', '/api/tutor/ask', { cookie, body: { question: 'Why?', context: '   ' } })).status, 400);
      const r = await api(t.base, 'POST', '/api/tutor/ask', { cookie, body: { question: 'Why?', context: 'Some notes.' } });
      assert.equal(r.status, 502);
      assert.doesNotMatch(r.text, /sk-test|500/);
    } finally { await t.stop(); }
  });

  test('the tutor answers 20 questions a day per user', async () => {
    const t = await startWith({ ANTHROPIC_API_KEY: 'sk-test-123456789' }, { fetch: okFetch() });
    try {
      const { cookie } = await login(t.base);
      const body = { question: 'Q?', context: 'Notes.' };
      for (let i = 0; i < 20; i++) assert.equal((await api(t.base, 'POST', '/api/tutor/ask', { cookie, body })).status, 200);
      assert.equal((await api(t.base, 'POST', '/api/tutor/ask', { cookie, body })).status, 429);
    } finally { await t.stop(); }
  });
});

describe('contact form', () => {
  const sent = [];
  const fakeMail = async (url, opts) => { sent.push({ url, body: JSON.parse(opts.body), auth: opts.headers.Authorization }); return { ok: true }; };
  const cfg = { RESEND_API_KEY: 're_test_key_123', MAIL_FROM: 'app@example.org', CONTACT_TO: 'team@example.org' };
  const good = { name: 'Asha', email: 'asha@example.com', message: 'Please call me about pricing.' };

  test('without email configured the form says so and sends nothing', async () => {
    const t = await startWith({ RESEND_API_KEY: '', CONTACT_TO: '', MAIL_FROM: '' }, { fetch: fakeMail });
    try {
      const r = await api(t.base, 'POST', '/api/contact', { body: good });
      assert.equal(r.status, 503);
    } finally { await t.stop(); }
  });

  test('a valid message is sent with the reply address set to the sender', async () => {
    sent.length = 0;
    const t = await startWith(cfg, { fetch: fakeMail });
    try {
      const r = await api(t.base, 'POST', '/api/contact', { body: good });
      assert.equal(r.status, 200);
      assert.equal(sent.length, 1);
      assert.equal(sent[0].url, 'https://api.resend.com/emails');
      assert.equal(sent[0].auth, 'Bearer re_test_key_123');
      assert.equal(sent[0].body.reply_to, 'asha@example.com');
      assert.deepEqual(sent[0].body.to, ['team@example.org']);
      assert.doesNotMatch(sent[0].body.subject, /[\r\n]/);
    } finally { await t.stop(); }
  });

  test('bad input is refused', async () => {
    const t = await startWith(cfg, { fetch: fakeMail });
    try {
      assert.equal((await api(t.base, 'POST', '/api/contact', { body: { ...good, email: 'not-an-email' } })).status, 400);
      assert.equal((await api(t.base, 'POST', '/api/contact', { body: { ...good, name: '' } })).status, 400);
      assert.equal((await api(t.base, 'POST', '/api/contact', { body: { ...good, message: 'hi' } })).status, 400);
    } finally { await t.stop(); }
  });

  test('5 messages a day per network address', async () => {
    const t = await startWith(cfg, { fetch: fakeMail });
    try {
      for (let i = 0; i < 5; i++) assert.equal((await api(t.base, 'POST', '/api/contact', { body: good })).status, 200);
      assert.equal((await api(t.base, 'POST', '/api/contact', { body: good })).status, 429);
    } finally { await t.stop(); }
  });

  test('a provider failure returns a plain error', async () => {
    const t = await startWith(cfg, { fetch: async () => ({ ok: false, status: 500 }) });
    try {
      const r = await api(t.base, 'POST', '/api/contact', { body: good });
      assert.equal(r.status, 502);
      assert.match(r.data.error, /could not be sent/);
    } finally { await t.stop(); }
  });
});

describe('behind a proxy', () => {
  test('the visitor address comes from X-Forwarded-For only when TRUST_PROXY=1', async () => {
    const mail = async () => ({ ok: true });
    const cfg = { RESEND_API_KEY: 'k', MAIL_FROM: 'f@example.org', CONTACT_TO: 't@example.org' };
    // Without TRUST_PROXY, every request is from the socket: 5 allowed, then 429 even with different headers.
    const t1 = await startWith(cfg, { fetch: mail });
    try {
      for (let i = 0; i < 5; i++) await fetch(t1.base + '/api/contact', { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '10.0.0.' + i }, body: JSON.stringify({ name: 'A', email: 'a@example.com', message: 'Hello there friend' }) });
      const r1 = await fetch(t1.base + '/api/contact', { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '10.9.9.9' }, body: JSON.stringify({ name: 'A', email: 'a@example.com', message: 'Hello there friend' }) });
      assert.equal(r1.status, 429);
    } finally { await t1.stop(); }
    // With TRUST_PROXY=1, each forwarded address has its own 5.
    const t2 = await startWith({ ...cfg, TRUST_PROXY: '1' }, { fetch: mail });
    try {
      for (let i = 0; i < 6; i++) {
        const r = await fetch(t2.base + '/api/contact', { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '10.0.0.' + i }, body: JSON.stringify({ name: 'A', email: 'a@example.com', message: 'Hello there friend' }) });
        assert.equal(r.status, 200);
      }
    } finally { await t2.stop(); }
  });
});
