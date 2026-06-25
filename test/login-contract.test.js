const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const PORT = 43117;
const HERMES_PORT = 43118;
const BASE = `http://127.0.0.1:${PORT}`;
let server;
let fakeHermes;
let lastHermesRequest = null;
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
  fakeHermes = http.createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'ok', platform: 'api_server' }));
    }
    if (req.url === '/v1/chat/completions' && req.method === 'POST') {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk.toString(); });
      req.on('end', () => {
        lastHermesRequest = {
          auth: req.headers.authorization || '',
          sessionKey: req.headers['x-hermes-session-key'] || '',
          body: JSON.parse(raw || '{}'),
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          choices: [{ message: { content: 'אני Hermes Agent אמיתי: בדקתי את הבקשה, אני יכול להשתמש בכלים כשמחברים אותי לשרת Hermes, ואענה כמו צ׳אט עוזר.' } }],
        }));
      });
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });
  await new Promise((resolve) => fakeHermes.listen(HERMES_PORT, '127.0.0.1', resolve));

  server = spawn(process.execPath, ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      CUSTOM_BOTS_FILE: path.join(os.tmpdir(), `tgb-custom-bots-${Date.now()}.json`),
      SUPABASE_URL: 'http://127.0.0.1:9',
      SUPABASE_SERVICE_ROLE_KEY: '',
      OPENAI_API_KEY: '',
      OPENROUTER_API_KEY: '',
      CHAT_MODEL: '',
      HERMES_API_BASE_URL: `http://127.0.0.1:${HERMES_PORT}`,
      HERMES_API_KEY: 'test-hermes-key',
      HERMES_MODEL: 'hermes-agent',
      DISABLE_PUBLIC_AI: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (chunk) => { serverOutput += chunk.toString(); });
  server.stderr.on('data', (chunk) => { serverOutput += chunk.toString(); });
  await waitForHealth();
});

test.after(async () => {
  if (server) {
    server.kill('SIGTERM');
    await new Promise((resolve) => server.once('exit', resolve));
  }
  if (fakeHermes) {
    await new Promise((resolve) => fakeHermes.close(resolve));
  }
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

  const agent = await fetch(`${BASE}/api/agent/status`);
  assert.equal(agent.status, 200);
  const agentBody = await agent.json();
  assert.equal(agentBody.agentConfigured, true);
  assert.equal(agentBody.provider, 'hermes-agent');
  assert.equal(agentBody.healthStatus, 'ok');

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

test('dashboard embeds MaximoSEO dashboards panel exactly once without duplicate tabs or frames', () => {
  const source = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  const dashboardUrlMatches = source.match(/https:\/\/dashboards-panel\.maximo-seo\.ai\//g) || [];
  const dashboardsTabMatches = source.match(/id="dashboardsTab"/g) || [];
  const dashboardsFrameMatches = source.match(/id="dashboardsFrame"/g) || [];

  assert.equal(dashboardsTabMatches.length, 1);
  assert.equal(dashboardsFrameMatches.length, 1);
  assert.equal(dashboardUrlMatches.length, 2); // iframe src + explicit "Open" link only
  assert.match(source, /data-tab="dashboards"/);
  assert.match(source, /function reloadDashboardsPanel\(\)/);
});

test('dashboard chatbot uses Hermes Agent backend instead of receipt-only fallback copy', async () => {
  const source = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  assert.match(source, /async function generateAgentReply\(/);
  assert.match(source, /function hermesAgentConfig\(/);
  assert.match(source, /X-Hermes-Session-Key/);
  assert.match(source, /chat\/completions/);
  assert.match(source, /function cleanModelReply\(/);
  assert.doesNotMatch(source, /קיבלתי את ההודעה שלך/);
  assert.doesNotMatch(source, /safe built-in dashboard chatbot fallback/);

  const missingOrigin = await fetch(`${BASE}/api/chat/nous`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'status' }),
  });
  assert.equal(missingOrigin.status, 403);

  const reply = await fetch(`${BASE}/api/chat/nous`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: BASE },
    body: JSON.stringify({ text: 'תענה לי כמו צאט אמיתי ותבדוק משהו עם כלי אם צריך' }),
  });
  assert.equal(reply.status, 200);
  const body = await reply.json();
  assert.equal(body.ok, true);
  assert.equal(body.mode, 'agent-chat');
  assert.equal(body.provider, 'hermes-agent');
  assert.equal(body.model, 'hermes-agent');
  assert.match(body.reply, /Hermes Agent|כלים|צ׳אט/);
  assert.doesNotMatch(body.reply, /קיבלתי|received|fallback|dashboard chat mode/i);
  assert.equal(lastHermesRequest.auth, 'Bearer test-hermes-key');
  assert.match(lastHermesRequest.sessionKey, /^dashboard:nous:/);
  assert.equal(lastHermesRequest.body.model, 'hermes-agent');
  assert.equal(lastHermesRequest.body.stream, false);
});

test('telegram reply webhook routes exist and persist chats for dashboard send targets', async () => {
  const serverSource = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  assert.match(serverSource, /setWebhook/);
  assert.match(serverSource, /x-telegram-bot-api-secret-token/);
  assert.match(serverSource, /app\.post\('\/api\/telegram\/:botId\/webhook'/);
  assert.match(serverSource, /upsertTelegramConversation\(bot, chat, inboundText\)/);
  assert.match(serverSource, /conversation_id: conversationId/);
  assert.match(serverSource, /listStoredTelegramChats\(bot\)/);
  assert.match(serverSource, /source: 'supabase'/);

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
