const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const PORT = 43117;
const BASE = `http://127.0.0.1:${PORT}`;
const PASSWORD = 'contract-test-password';
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
  const sessionFile = path.join('/tmp', `tgb-contract-sessions-${Date.now()}.json`);
  server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      DASHBOARD_PASSWORD: PASSWORD,
      SESSION_FILE: sessionFile,
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

test('server registers JSON parser exactly once and before /api/login', () => {
  const source = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  const parserMatches = [...source.matchAll(/app\.use\(express\.json\(\{ limit: '1mb' \}\)\)/g)];
  assert.equal(parserMatches.length, 1);
  assert.ok(parserMatches[0].index < source.indexOf("app.post('/api/login'"));
});

test('POST /api/login parses JSON and accepts same-origin Origin including port', async () => {
  const res = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: BASE,
    },
    body: JSON.stringify({ password: PASSWORD }),
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.ok, true);
  assert.match(body.token, /^[a-f0-9]{48}$/);

  const authCheck = await fetch(`${BASE}/api/auth-check`, {
    headers: { 'x-session-id': body.token },
  });
  assert.equal(authCheck.status, 200);
  assert.equal((await authCheck.json()).ok, true);
});

test('POST /api/login accepts same-origin Referer fallback including path and port', async () => {
  const res = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Referer: `${BASE}/login`,
    },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).ok, true);
});

test('POST /api/login rejects cross-origin and missing CSRF headers', async () => {
  const crossOrigin = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'http://evil.example',
    },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(crossOrigin.status, 403);

  const missingOrigin = await fetch(`${BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: PASSWORD }),
  });
  assert.equal(missingOrigin.status, 403);
});
