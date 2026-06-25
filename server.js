const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// Security headers.
// This dashboard is a single-file app with inline CSS/JS in public/index.html,
// so Helmet's default CSP blocks the app runtime. Keep Helmet's other
// hardening headers, but disable CSP until the frontend is split into
// external hashed assets.
app.use(helmet({ contentSecurityPolicy: false }));

// CORS — allow frontend (same-origin) and external dashboard consumers
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id');
  res.set('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── CSRF Protection ─────────────────────────────────────
// Validates Origin/Referer headers on mutation endpoints.
// Compare against the full Host header (including port) so same-origin
// localhost/Render requests are not rejected as false positives.
function isSameRequestHost(req, candidateUrl) {
  const expectedHost = (req.get('host') || '').toLowerCase();
  if (!expectedHost) return false;
  try {
    const parsed = new URL(candidateUrl);
    return parsed.host.toLowerCase() === expectedHost;
  } catch {
    return false;
  }
}

function validateCSRF(req) {
  // Check Origin first (most reliable)
  const origin = req.headers.origin;
  if (origin) {
    if (!isSameRequestHost(req, origin)) {
      return { valid: false, error: 'Origin mismatch — possible CSRF attack' };
    }
    return { valid: true };
  }
  // Fallback to Referer
  const referer = req.headers.referer;
  if (referer) {
    if (!isSameRequestHost(req, referer)) {
      return { valid: false, error: 'Referer mismatch — possible CSRF attack' };
    }
    return { valid: true };
  }
  // Neither present — reject cross-origin mutations
  return { valid: false, error: 'Missing Origin and Referer headers — possible CSRF attack' };
}

// Rate limiting: global 100 req/min per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Body parser — MUST be registered before any route that reads req.body.
// Keep this as a single registration; duplicate JSON parsers add noise and
// can hide route-order regressions during audits.
app.use(express.json({ limit: '1mb' }));

// Stricter rate limit for setup endpoints: 5 req/min
const setupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many setup requests. Try again in a minute.' }
});

app.get('/api/auth-check', (req, res) => {
  res.json({ ok: true, needsAuth: false });
});

// Supabase
const SB_URL = process.env.SUPABASE_URL || 'https://sunrupuwvpalipiuebcv.supabase.co';
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// AbortController wrapper — prevents hung fetch calls from exhausting the connection pool
function fetchWithTimeout(url, opts = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...opts, signal: controller.signal }).finally(() => clearTimeout(timer));
}

// Bot tokens — loaded from Supabase on startup, updated via /api/setup
let BOT_TOKENS = Object.create(null);
let tokenLoadCompleted = false;
function configuredTokenCount() {
  return Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length;
}
function tokenStatus() {
  return { tokenLoadCompleted, configured: configuredTokenCount(), total: BOTS.length, tokensLoaded: configuredTokenCount() > 0 };
}

// Bot definitions
const DEFAULT_BOTS = [
  { id: 'nous', name: 'HermesL64 Bot', username: '@HermesL64Bot', icon: '🧠', color: '#10b981', model: 'Nous', role: 'General Purpose', supabaseId: '7e3c5278-f01f-4c62-9d8a-aba2599982e0', botApiId: 8609253721, envVar: 'BOT_TOKEN_NOUS' },
  { id: 'claude', name: 'HermesClaude64 Bot', username: '@HermesClaude64Bot', icon: '🎯', color: '#3b82f6', model: 'Claude', role: 'Advanced Reasoning', supabaseId: 'c186e227-6ff6-4f9e-8906-5867e1f14224', botApiId: 8885902648, envVar: 'BOT_TOKEN_CLAUDE' },
  { id: 'nous2', name: 'HermesNous64 Bot', username: '@HermesNous64Bot', icon: '⚡', color: '#ec4899', model: 'Nous', role: 'Fast & Efficient', supabaseId: '594619d9-e765-4d82-b289-953390aa6d0a', botApiId: 8707123248, envVar: 'BOT_TOKEN_NOUS2' },
  { id: 'codex', name: 'HermesCodexNew64 Bot', username: '@HermesCodexNew64Bot', icon: '💻', color: '#f59e0b', model: 'Codex', role: 'Code Generation', supabaseId: '630b8adc-0756-41e3-91a8-88bd0ff1443d', botApiId: 8907343970, envVar: 'BOT_TOKEN_CODEX' }
];

const CUSTOM_BOTS_FILE = process.env.CUSTOM_BOTS_FILE || path.join('/tmp', 'tgb-custom-bots.json');
const BOT_CONFIG_ROW_ID = '__dashboard_bot_config__';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/$/, '');
let botConfig = { customBots: [], hiddenDefaultIds: [] };
let BOTS = [];

function sanitizeBotId(input) {
  return String(input || '').toLowerCase().replace(/[^a-z0-9_-]/g, '_').replace(/^_+|_+$/g, '').slice(0, 48);
}
function normalizeUsername(username) {
  if (!username) return '';
  return username.startsWith('@') ? username : '@' + username;
}
function rebuildBots() {
  const hidden = new Set(botConfig.hiddenDefaultIds || []);
  BOTS = [
    ...DEFAULT_BOTS.filter(b => !hidden.has(b.id)).map(b => ({ ...b, locked: true })),
    ...(botConfig.customBots || []).map(b => ({ ...b, locked: false }))
  ];
  for (const bot of BOTS) if (!(bot.id in BOT_TOKENS)) BOT_TOKENS[bot.id] = '';
}
function loadBotConfig() {
  try {
    if (fsExists(CUSTOM_BOTS_FILE)) {
      const parsed = JSON.parse(require('fs').readFileSync(CUSTOM_BOTS_FILE, 'utf8'));
      botConfig = { customBots: Array.isArray(parsed.customBots) ? parsed.customBots : [], hiddenDefaultIds: Array.isArray(parsed.hiddenDefaultIds) ? parsed.hiddenDefaultIds : [] };
    }
  } catch (e) { console.error('[BOTS] Failed to load custom bot config:', e.message); }
  rebuildBots();
}
function saveBotConfig() {
  const fs = require('fs');
  fs.mkdirSync(path.dirname(CUSTOM_BOTS_FILE), { recursive: true });
  fs.writeFileSync(CUSTOM_BOTS_FILE, JSON.stringify(botConfig, null, 2));
  rebuildBots();
  saveBotConfigToDB().catch(e => console.error('[BOTS] Failed to persist bot config:', e.message));
}
function fsExists(file) { try { return require('fs').existsSync(file); } catch { return false; } }
function publicBot(bot) {
  return { id: bot.id, name: bot.name, username: bot.username, model: bot.model, role: bot.role, supabaseId: bot.supabaseId, botApiId: bot.botApiId, icon: bot.icon || '🤖', color: bot.color || '#10b981', locked: !!bot.locked, hasToken: !!BOT_TOKENS[bot.id] };
}

loadBotConfig();

// ─── Load tokens from environment variables (backup) ──────────
function loadTokensFromEnv() {
  let loaded = 0;
  for (const bot of BOTS) {
    const val = (process.env[bot.envVar] || '').trim();
    if (val && val.length > 20) {  // skip redacted/placeholder values
      BOT_TOKENS[bot.id] = val;
      loaded++;
    }
  }
  if (loaded > 0) console.log(`✅ Bot tokens from env vars: ${loaded}/${BOTS.length}`);
  return loaded;
}

// ─── Load tokens from Supabase (primary source) ───────────────
async function loadTokensFromDB() {
  try {
    const resp = await fetchWithTimeout(`${SB_URL}/rest/v1/bot_tokens?select=*`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    if (!resp.ok) return;
    const rows = await resp.json();
    if (!Array.isArray(rows)) return;

    let filled = 0;
    for (const row of rows) {
      if (row.bot_id === BOT_CONFIG_ROW_ID && row.token) {
        try {
          const parsed = JSON.parse(row.token);
          botConfig = {
            customBots: Array.isArray(parsed.customBots) ? parsed.customBots : [],
            hiddenDefaultIds: Array.isArray(parsed.hiddenDefaultIds) ? parsed.hiddenDefaultIds : []
          };
          rebuildBots();
          console.log(`✅ Bot config from Supabase: ${botConfig.customBots.length} custom, ${botConfig.hiddenDefaultIds.length} hidden default(s)`);
        } catch (e) {
          console.error('[BOTS] Failed to parse Supabase bot config:', e.message);
        }
        continue;
      }
      if (row.bot_id && row.token && row.token.length > 20) {
        BOT_TOKENS[row.bot_id] = row.token;
        filled++;
      }
    }
    // tokenLoadCompleted is set after both DB and env fallback loaders run.
    console.log(`✅ Bot tokens from Supabase (backup): filled ${filled} empty slot(s). Total configured: ${Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length}`);
  } catch (e) {
    console.log('⚠️ Could not load tokens from DB:', e.message);
  }
}

async function saveBotConfigToDB() {
  if (!SB_KEY) return { skipped: true, reason: 'Supabase key not configured' };
  const resp = await fetchWithTimeout(`${SB_URL}/rest/v1/bot_tokens`, {
    method: 'POST',
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'resolution=merge-duplicates'
    },
    body: JSON.stringify({ bot_id: BOT_CONFIG_ROW_ID, token: JSON.stringify(botConfig), updated_at: new Date().toISOString() })
  });
  if (!resp.ok) throw new Error(`Supabase bot config save failed: ${resp.status}`);
  return { ok: true };
}

// ─── Save token to Supabase ───────────────────────────────────
async function saveTokenToDB(botId, token) {
  try {
    if (!SB_KEY) return { ok: false, durable: false, error: 'Supabase key not configured' };
    const resp = await fetchWithTimeout(`${SB_URL}/rest/v1/bot_tokens`, {
      method: 'POST',
      headers: {
        'apikey': SB_KEY,
        'Authorization': `Bearer ${SB_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify({ bot_id: botId, token, updated_at: new Date().toISOString() })
    });
    if (!resp.ok) throw new Error(`Supabase token save failed: ${resp.status}`);
    return { ok: true, durable: true };
  } catch (e) {
    console.error('Failed to save token:', e.message);
    return { ok: false, durable: false, error: 'Token is active in memory but was not saved durably' };
  }
}
async function deleteTokenFromDB(botId) {
  try {
    await fetchWithTimeout(`${SB_URL}/rest/v1/bot_tokens?bot_id=eq.${encodeURIComponent(botId)}`, {
      method: 'DELETE',
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
  } catch (e) {
    console.error('Failed to delete token:', e.message);
  }
}

app.use(express.static(path.join(__dirname, 'public')));

// ─── Supabase Proxy ──────────────────────────────────────────
// Table whitelist — only these tables are accessible through the proxy
const ALLOWED_TABLES = ['messages', 'conversations', 'bot_tokens', 'dashboard_suggestions'];

app.all('/api/sb/*', async (req, res) => {
  const restPath = req.params[0];
  const table = restPath.split('?')[0].split('/')[0];
  if (!ALLOWED_TABLES.includes(table)) {
    return res.status(403).json({ error: `Forbidden: table '${table}' not in proxy whitelist` });
  }
  // Additional check: POST/PATCH/PUT require body validation
  if (['POST','PATCH','PUT'].includes(req.method) && !req.body) {
    return res.status(400).json({ error: 'Request body required for write operations' });
  }
  const target = `${SB_URL}/rest/v1/${restPath}`;
  const headers = {
    'apikey': SB_KEY,
    'Authorization': `Bearer ${SB_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };
  const qs = new URLSearchParams(req.query).toString();
  const url = target + (qs ? `?${qs}` : '');
  try {
    const opts = { method: req.method, headers };
    if (['POST','PATCH','PUT'].includes(req.method) && req.body) opts.body = JSON.stringify(req.body);
    const resp = await fetchWithTimeout(url, opts);
    const data = await resp.text();
    res.status(resp.status);
    const cr = resp.headers.get('content-range');
    if (cr) res.set('Content-Range', cr);
    try { res.json(JSON.parse(data)); } catch { res.send(data); }
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(502).json({ error: 'Proxy error' });
  }
});

// ─── Telegram Bot API Proxy ──────────────────────────────────
async function tgApi(botId, method, body = null) {
  const token = BOT_TOKENS[botId];
  if (!token) throw new Error(`No token configured for bot: ${botId}. Go to Setup to configure.`);
  const url = `https://api.telegram.org/bot${token}/${method}`;
  const opts = { method: 'POST', headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const data = await resp.json();
  if (!data.ok) throw new Error(data.description || 'Telegram API error');
  return data.result;
}

function publicBaseUrl(req) {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;
  const proto = req.get('x-forwarded-proto') || req.protocol || 'https';
  return `${proto}://${req.get('host')}`.replace(/\/$/, '');
}

function webhookSecretFor(botId) {
  const token = BOT_TOKENS[botId] || '';
  return crypto.createHmac('sha256', token).update(`telegram-webhook:${botId}`).digest('hex');
}

async function registerWebhookForBot(botId, baseUrl) {
  const bot = BOTS.find(b => b.id === botId);
  if (!bot) throw new Error('Bot not found');
  if (!BOT_TOKENS[botId]) throw new Error('No token configured for bot');
  const url = `${baseUrl.replace(/\/$/, '')}/api/telegram/${encodeURIComponent(botId)}/webhook`;
  const result = await tgApi(botId, 'setWebhook', {
    url,
    allowed_updates: ['message'],
    drop_pending_updates: false,
    secret_token: webhookSecretFor(botId)
  });
  return { ok: true, bot: publicBot(bot), webhookUrl: url, result };
}

async function saveMessageRow(row) {
  if (!SB_KEY) return { skipped: true, reason: 'Supabase key not configured' };
  try {
    const resp = await fetchWithTimeout(`${SB_URL}/rest/v1/messages`, {
      method: 'POST',
      headers: {
        'apikey': SB_KEY,
        'Authorization': `Bearer ${SB_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify(row)
    });
    if (!resp.ok) throw new Error(`Supabase messages insert failed: ${resp.status}`);
    return { ok: true };
  } catch (e) {
    console.error('Failed to store Telegram message:', e.message);
    return { ok: false, error: e.message };
  }
}

function chatLabel(chat = {}) {
  return chat.username ? `@${chat.username}` : [chat.first_name, chat.last_name].filter(Boolean).join(' ') || String(chat.id || 'Telegram user');
}

async function registerConfiguredWebhooks(baseUrl) {
  if (!baseUrl) return;
  const configured = BOTS.filter(bot => BOT_TOKENS[bot.id]);
  for (const bot of configured) {
    try {
      await registerWebhookForBot(bot.id, baseUrl);
      console.log(`✅ Telegram webhook registered for ${bot.id}`);
    } catch (e) {
      console.error(`Webhook auto-register failed for ${bot.id}:`, e.message);
    }
  }
}

// ─── Bot Management ───────────────────────────────────────────
app.get('/api/bots', (req, res) => {
  res.json({ bots: BOTS.map(publicBot), botfather: { automaticPullSupported: false, reason: 'Telegram Bot API does not expose a BotFather endpoint to list a user\'s bots or retrieve tokens. Use /token in @BotFather manually, then paste a token here; the dashboard auto-imports name/username via getMe.' } });
});

app.post('/api/bots', setupLimiter, async (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  try {
    const { token, name, role, model, icon, color } = req.body || {};
    if (!token || String(token).trim().length < 20) return res.status(400).json({ error: 'Valid bot token required' });
    const testResp = await fetch(`https://api.telegram.org/bot${String(token).trim()}/getMe`);
    const testData = await testResp.json();
    if (!testData.ok) return res.status(400).json({ error: 'Invalid token: ' + (testData.description || 'unknown') });
    const info = testData.result;
    const id = sanitizeBotId(`bot_${info.id || info.username || crypto.randomUUID()}`);
    if (BOTS.some(b => b.id === id)) return res.status(409).json({ error: 'Bot already exists', bot: BOTS.find(b => b.id === id) });
    const bot = {
      id,
      name: String(name || info.first_name || info.username || 'Telegram Bot').slice(0, 80),
      username: normalizeUsername(info.username || ''),
      model: String(model || 'Custom').slice(0, 40),
      role: String(role || 'Custom Bot').slice(0, 80),
      supabaseId: crypto.randomUUID(),
      botApiId: info.id,
      icon: String(icon || '🤖').slice(0, 4),
      color: /^#[0-9a-fA-F]{6}$/.test(color || '') ? color : '#10b981',
      envVar: ''
    };
    botConfig.customBots.push(bot);
    BOT_TOKENS[id] = String(token).trim();
    saveBotConfig();
    const persistence = await saveTokenToDB(id, BOT_TOKENS[id]);
    let webhook = null;
    try {
      webhook = await registerWebhookForBot(id, publicBaseUrl(req));
    } catch (e) {
      console.error('Add bot webhook setup failed:', e.message);
    }
    res.json({ ok: true, bot: publicBot(bot), telegram: info, webhook, persistence });
  } catch (err) {
    console.error('Add bot error:', err.message);
    res.status(500).json({ error: 'Failed to add bot' });
  }
});

app.delete('/api/bots/:botId', setupLimiter, async (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  const botId = req.params.botId;
  const bot = BOTS.find(b => b.id === botId);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  if (DEFAULT_BOTS.some(b => b.id === botId)) {
    botConfig.hiddenDefaultIds = Array.from(new Set([...(botConfig.hiddenDefaultIds || []), botId]));
  } else {
    botConfig.customBots = (botConfig.customBots || []).filter(b => b.id !== botId);
  }
  delete BOT_TOKENS[botId];
  saveBotConfig();
  await deleteTokenFromDB(botId);
  res.json({ ok: true, bots: BOTS.map(publicBot) });
});

app.post('/api/bots/restore-defaults', setupLimiter, (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  botConfig.hiddenDefaultIds = [];
  saveBotConfig();
  res.json({ ok: true, bots: BOTS.map(publicBot) });
});

app.get('/api/botfather/status', (req, res) => {
  res.json({ automaticPullSupported: false, officialApiAvailable: false, message: 'BotFather does not provide an official Bot API endpoint for listing your bots or extracting tokens. Manual /token in @BotFather is required; this dashboard can auto-import metadata after you paste a token.' });
});

// ─── Setup Endpoint ──────────────────────────────────────────
app.get('/api/setup/status', (req, res) => {
  const status = tokenStatus();
  res.json({ ...status, bots: BOTS.map(publicBot) });
});

app.post('/api/setup/token', setupLimiter, async (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  try {
    const { botId, token } = req.body;
    if (!botId || !token) return res.status(400).json({ error: 'botId and token required' });
    
    // Validate token by calling getMe
    const testResp = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const testData = await testResp.json();
    if (!testData.ok) return res.status(400).json({ error: 'Invalid token: ' + (testData.description || 'unknown') });
    
    // Save
    BOT_TOKENS[botId] = token;
    const persistence = await saveTokenToDB(botId, token);
    let webhook = null;
    try {
      webhook = await registerWebhookForBot(botId, publicBaseUrl(req));
    } catch (e) {
      console.error('Token setup webhook setup failed:', e.message);
    }
    
    res.json({ ok: true, bot: testData.result, webhook, persistence });
  } catch (err) {
    console.error('Token setup error:', err.message);
    res.status(500).json({ error: 'Token setup failed' });
  }
});

// ─── Telegram Endpoints ──────────────────────────────────────
app.get('/api/telegram/:botId/me', async (req, res) => {
  try {
    const info = await tgApi(req.params.botId, 'getMe');
    res.json({ ok: true, result: info });
  } catch (err) {
    console.error('getMe error:', err.message);
    res.json({ ok: false, error: 'Telegram API request failed' });
  }
});

app.post('/api/telegram/:botId/webhook/register', setupLimiter, async (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  try {
    const result = await registerWebhookForBot(req.params.botId, publicBaseUrl(req));
    res.json(result);
  } catch (err) {
    console.error('Webhook register error:', err.message);
    res.status(400).json({ ok: false, error: 'Webhook registration failed' });
  }
});

app.get('/api/telegram/:botId/webhook/info', async (req, res) => {
  try {
    const result = await tgApi(req.params.botId, 'getWebhookInfo');
    const sanitized = { ...result };
    if (sanitized.url) sanitized.url = sanitized.url.replace(/\/api\/telegram\/[^/]+\/webhook$/, '/api/telegram/[bot]/webhook');
    res.json({ ok: true, result: sanitized });
  } catch (err) {
    console.error('Webhook info error:', err.message);
    res.json({ ok: false, error: 'Telegram API request failed' });
  }
});

app.post('/api/telegram/:botId/webhook', async (req, res) => {
  const botId = req.params.botId;
  const bot = BOTS.find(b => b.id === botId);
  if (!bot || !BOT_TOKENS[botId]) return res.status(404).json({ ok: false });

  const expectedSecret = webhookSecretFor(botId);
  const actualSecret = req.get('x-telegram-bot-api-secret-token') || '';
  if (actualSecret !== expectedSecret) return res.status(403).json({ ok: false });

  // Telegram retries non-2xx responses. Acknowledge quickly and process async.
  res.json({ ok: true });

  const update = req.body || {};
  const msg = update.message;
  if (!msg || !msg.chat) return;

  const inboundText = msg.text || msg.caption || '[non-text message]';
  const chat = msg.chat;
  const from = msg.from || {};
  const receivedAt = msg.date ? new Date(msg.date * 1000).toISOString() : new Date().toISOString();

  await saveMessageRow({
    bot_id: bot.supabaseId,
    direction: 'inbound',
    sender_type: 'user',
    content_type: msg.text ? 'text' : 'message',
    content: `${chatLabel(chat)}: ${inboundText}`,
    created_at: receivedAt
  });

  const reply = `✅ ${bot.name} מחובר וקיבל את ההודעה שלך.\n\nכרגע זה חיבור בסיסי לדשבורד: ההודעה נשמרת ומופיעה שם. השלב הבא הוא לחבר את הבוט למנוע AI/Agent כדי שיענה תשובות חכמות.`;
  try {
    await tgApi(botId, 'sendMessage', { chat_id: chat.id, text: reply });
    await saveMessageRow({
      bot_id: bot.supabaseId,
      direction: 'outbound',
      sender_type: 'bot',
      content_type: 'text',
      content: reply,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('Webhook auto-reply failed:', err.message);
  }
});

app.get('/api/telegram/:botId/updates', async (req, res) => {
  try {
    const offset = req.query.offset || 0;
    const limit = parseInt(req.query.limit) || 50;
    const updates = await tgApi(req.params.botId, 'getUpdates', {
      offset, limit, allowed_updates: ['message']
    });
    res.json({ ok: true, result: updates });
  } catch (err) {
    console.error('getUpdates error:', err.message);
    res.json({ ok: false, error: 'Telegram API request failed' });
  }
});

app.post('/api/telegram/:botId/send', async (req, res) => {
  const csrf = validateCSRF(req);
  if (!csrf.valid) return res.status(403).json({ error: csrf.error });
  try {
    const { chatId, text, parseMode } = req.body;
    if (!chatId || !text) return res.status(400).json({ error: 'chatId and text required' });
    const result = await tgApi(req.params.botId, 'sendMessage', {
      chat_id: chatId, text, parse_mode: parseMode || 'HTML'
    });
    res.json({ ok: true, result });
  } catch (err) {
    console.error('sendMessage error:', err.message);
    res.json({ ok: false, error: 'Telegram API request failed' });
  }
});

app.get('/api/telegram/:botId/chats', async (req, res) => {
  try {
    const updates = await tgApi(req.params.botId, 'getUpdates', { limit: 100 });
    const chats = {};
    for (const u of updates) {
      if (u.message) {
        const chat = u.message.chat;
        const key = chat.id.toString();
        if (!chats[key]) {
          chats[key] = {
            id: chat.id, type: chat.type,
            firstName: chat.first_name || '', lastName: chat.last_name || '',
            username: chat.username || '',
            lastMessage: u.message.text || '',
            lastDate: new Date(u.message.date * 1000).toISOString()
          };
        }
      }
    }
    res.json({ ok: true, chats: Object.values(chats) });
  } catch (err) {
    console.error('getChats error:', err.message);
    res.json({ ok: false, error: 'Telegram API request failed' });
  }
});

// Batch health
app.get('/api/bots/health', async (req, res) => {
  const results = {};
  await Promise.allSettled(
    BOTS.map(async (bot) => {
      if (!BOT_TOKENS[bot.id]) {
        results[bot.id] = { online: false, error: 'Token not configured' };
        return;
      }
      try {
        const start = Date.now();
        const info = await tgApi(bot.id, 'getMe');
        results[bot.id] = { online: true, latency: Date.now() - start, username: info.username, firstName: info.first_name };
      } catch (err) {
        console.error('Health check error for', bot.id, ':', err.message);
        results[bot.id] = { online: false, error: 'Health check failed' };
      }
    })
  );
  res.json(results);
});

// ─── Stats ───────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const [convosResp, msgsResp] = await Promise.all([
      fetchWithTimeout(`${SB_URL}/rest/v1/conversations?select=id,bot_id,message_count,total_tokens,total_cost,created_at`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetchWithTimeout(`${SB_URL}/rest/v1/messages?select=id,bot_id,tokens_used,cost,created_at`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      })
    ]);
    const convos = await convosResp.json();
    const msgs = await msgsResp.json();

    const stats = {
      totalConversations: Array.isArray(convos) ? convos.length : 0,
      totalMessages: Array.isArray(msgs) ? msgs.length : 0,
      totalTokens: 0, totalCost: 0, perBot: {}
    };

    for (const bot of BOTS) stats.perBot[bot.id] = { conversations: 0, messages: 0, tokens: 0, cost: 0 };

    // Per-bot: conversations from convos table
    if (Array.isArray(convos)) {
      for (const c of convos) {
        const bid = BOTS.find(b => b.supabaseId === c.bot_id);
        if (bid) { stats.perBot[bid.id].conversations++; stats.perBot[bid.id].tokens += c.total_tokens || 0; stats.perBot[bid.id].cost += parseFloat(c.total_cost || 0); }
      }
    }
    // Per-bot: messages from msgs table (NOT added to global total to avoid double-count)
    if (Array.isArray(msgs)) {
      for (const m of msgs) {
        const bid = BOTS.find(b => b.supabaseId === m.bot_id);
        if (bid) stats.perBot[bid.id].messages++;
        stats.totalTokens += m.tokens_used || 0;
        stats.totalCost += parseFloat(m.cost || 0);
      }
    }
    res.json(stats);
  } catch (err) {
    console.error('Stats error:', err.message);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ─── Search ──────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json({ messages: [], conversations: [] });
    const [msgsResp, convosResp] = await Promise.all([
      fetchWithTimeout(`${SB_URL}/rest/v1/messages?content=ilike.%25${encodeURIComponent(q)}%25&order=created_at.desc&limit=50`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetchWithTimeout(`${SB_URL}/rest/v1/conversations?or=(username.ilike.%25${encodeURIComponent(q)}%25,telegram_user_id.ilike.%25${encodeURIComponent(q)}%25)&order=updated_at.desc&limit=50`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      })
    ]);
    const msgs = await msgsResp.json();
    const convos = await convosResp.json();
    res.json({
      messages: Array.isArray(msgs) ? msgs : [],
      conversations: Array.isArray(convos) ? convos : []
    });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── Export ──────────────────────────────────────────────────
app.get('/api/export/:botId', async (req, res) => {
  try {
    const bot = BOTS.find(b => b.id === req.params.botId);
    if (!bot) return res.status(400).json({ error: 'Invalid bot' });
    const [msgsResp, convosResp] = await Promise.all([
      fetchWithTimeout(`${SB_URL}/rest/v1/messages?bot_id=eq.${bot.supabaseId}&order=created_at.asc&limit=1000`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetchWithTimeout(`${SB_URL}/rest/v1/conversations?bot_id=eq.${bot.supabaseId}&order=updated_at.desc&limit=100`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      })
    ]);
    const convos = await convosResp.json();
    const msgs = await msgsResp.json();
    res.json({
      bot, exportedAt: new Date().toISOString(),
      conversations: Array.isArray(convos) ? convos : [],
      messages: Array.isArray(msgs) ? msgs : []
    });
  } catch (err) {
    console.error('Export error:', err.message);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Health
app.get('/api/health', (_, res) => res.json({ ok: true, uptime: process.uptime(), ...tokenStatus() }));

// API fallback: unknown API routes should return JSON, not the SPA HTML.
app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found', path: req.originalUrl }));

// SPA fallback
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Startup ─────────────────────────────────────────────────
// Start server immediately — Render health checks need a fast listen().
// Token loading happens in background so a slow/hung Supabase never blocks startup.
app.listen(PORT, '0.0.0.0', () => {
  const configured = configuredTokenCount();
  console.log(`🤖 Telegram Bots Dashboard on :${PORT} (${configured}/${BOTS.length} tokens pre-configured)`);
});

// Background: load tokens from Supabase, then fill gaps from env vars
loadTokensFromDB()
  .catch(err => console.error('❌ loadTokensFromDB failed:', err.message))
  .finally(() => {
    loadTokensFromEnv();
    tokenLoadCompleted = true;
    const configured = configuredTokenCount();
    console.log(`🔑 Tokens after background load: ${configured}/${BOTS.length}`);
    if (PUBLIC_BASE_URL && configured > 0) {
      registerConfiguredWebhooks(PUBLIC_BASE_URL).catch(err => console.error('❌ webhook auto-register failed:', err.message));
    }
  });
