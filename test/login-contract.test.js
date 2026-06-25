const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
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
      CUSTOM_BOTS_FILE: path.join(os.tmpdir(), `tgb-custom-bots-${Date.now()}.json`),
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

test('frontend does not prompt for a dashboard password and loads bots dynamically', () => {
  const source = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  assert.equal(source.includes('window.prompt'), false);
  assert.equal(source.includes('Enter Telegram Bots Dashboard password'), false);
  assert.equal(source.includes('tgbDashboardSession'), false);
  assert.match(source, /let BOTS = \[\];/);
  assert.match(source, /async function loadBots\(\)/);
  assert.match(source, /async function addBotFromToken\(\)/);
  assert.match(source, /async function deleteBot\(botId\)/);
  assert.match(source, /async function enableTelegramReplies\(botId\)/);
});

test('auth-check reports the dashboard is open without password', async () => {
  const res = await fetch(`${BASE}/api/auth-check`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, needsAuth: false });
});

test('dashboard APIs and bot management metadata are reachable without X-Session-Id', async () => {
  const bots = await fetch(`${BASE}/api/bots`);
  assert.equal(bots.status, 200);
  const botsBody = await bots.json();
  assert.equal(botsBody.bots.length, 4);
  assert.equal(botsBody.botfather.automaticPullSupported, false);

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

test('bot delete and restore default bots work with same-origin CSRF', async () => {
  const del = await fetch(`${BASE}/api/bots/nous`, {
    method: 'DELETE',
    headers: { Origin: BASE },
  });
  assert.equal(del.status, 200);
  const afterDelete = await del.json();
  assert.equal(afterDelete.ok, true);
  assert.equal(afterDelete.bots.some((b) => b.id === 'nous'), false);

  const restore = await fetch(`${BASE}/api/bots/restore-defaults`, {
    method: 'POST',
    headers: { Origin: BASE },
  });
  assert.equal(restore.status, 200);
  const afterRestore = await restore.json();
  assert.equal(afterRestore.ok, true);
  assert.equal(afterRestore.bots.some((b) => b.id === 'nous'), true);
});

test('same-origin CSRF protection remains on mutation endpoints', async () => {
  const missingOrigin = await fetch(`${BASE}/api/setup/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ botId: 'nous', token: 'invalid' }),
  });
  assert.equal(missingOrigin.status, 403);

  const crossOrigin = await fetch(`${BASE}/api/bots`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
    body: JSON.stringify({ token: 'invalid' }),
  });
  assert.equal(crossOrigin.status, 403);
});

test('telegram reply webhook routes exist and are protected', async () => {
  const serverSource = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  assert.match(serverSource, /setWebhook/);
  assert.match(serverSource, /x-telegram-bot-api-secret-token/);
  assert.match(serverSource, /app\.post\('\/api\/telegram\/:botId\/webhook'/);

  const registerMissingOrigin = await fetch(`${BASE}/api/telegram/nous/webhook/register`, {
    method: 'POST',
  });
  assert.equal(registerMissingOrigin.status, 403);

  const webhookWithoutToken = await fetch(`${BASE}/api/telegram/nous/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: { chat: { id: 1 }, text: 'hi' } }),
  });
  assert.equal(webhookWithoutToken.status, 404);
});
