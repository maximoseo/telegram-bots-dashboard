const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const PORT = 43117;
const BASE = `http://127.0.0.1:${PORT}`;
let server;
let serverOutput = '';

async function waitForHealth() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return;
    } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`server did not become healthy. Output:\n${serverOutput}`);
}

test.before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      SUPABASE_URL: 'http://127.0.0.1:9',
      SUPABASE_SERVICE_ROLE_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
  server.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });
  await waitForHealth();
});

test.after(async () => {
  if (!server) return;
  server.kill('SIGTERM');
  await new Promise((resolve) => server.once('exit', resolve));
});

test('frontend does not prompt for a dashboard password', () => {
  const source = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  assert.equal(source.includes('window.prompt'), false);
  assert.equal(source.includes('Enter Telegram Bots Dashboard password'), false);
  assert.equal(source.includes('tgbDashboardSession'), false);
  assert.match(source, /async function authFetch\(url, options = \{\}\) \{\s*return fetch\(url, options\);\s*\}/);
});

test('auth-check reports the dashboard is open without password', async () => {
  const res = await fetch(`${BASE}/api/auth-check`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, needsAuth: false });
});

test('dashboard APIs are reachable without X-Session-Id', async () => {
  const setup = await fetch(`${BASE}/api/setup/status`);
  assert.equal(setup.status, 200);
  const setupBody = await setup.json();
  assert.equal(setupBody.total, 4);

  const health = await fetch(`${BASE}/api/bots/health`);
  assert.equal(health.status, 200);
  const healthBody = await health.json();
  assert.equal(Object.keys(healthBody).length, 4);
  assert.equal(healthBody.nous.error, 'Token not configured');
});

test('same-origin CSRF protection remains on mutation endpoints', async () => {
  const missingOrigin = await fetch(`${BASE}/api/setup/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ botId: 'nous', token: 'invalid' }),
  });
  assert.equal(missingOrigin.status, 403);

  const crossOrigin = await fetch(`${BASE}/api/setup/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
    body: JSON.stringify({ botId: 'nous', token: 'invalid' }),
  });
  assert.equal(crossOrigin.status, 403);
});
