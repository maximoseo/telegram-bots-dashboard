const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Supabase
const SB_URL = process.env.SUPABASE_URL || 'https://jzfamdshbfbwolupywrw.supabase.co';
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Bot tokens — loaded from Supabase on startup, updated via /api/setup
let BOT_TOKENS = Object.create(null);
BOT_TOKENS.nous = '';
BOT_TOKENS.claude = '';
BOT_TOKENS.nous2 = '';
BOT_TOKENS.codex = '';
let tokensLoaded = false;

// Bot definitions
const BOTS = [
  { id: 'nous', name: 'HemesL64 Bot', username: '@HemesL64Bot', model: 'Nous', role: 'General Purpose', supabaseId: '7e3c5278-f01f-4c62-9d8a-aba2599982e0', botApiId: 8609253721, envVar: 'BOT_TOKEN_NOUS' },
  { id: 'claude', name: 'HermesClaude64 Bot', username: '@HermesClaude64Bot', model: 'Claude', role: 'Advanced Reasoning', supabaseId: 'c186e227-6ff6-4f9e-8906-5867e1f14224', botApiId: 8885902648, envVar: 'BOT_TOKEN_CLAUDE' },
  { id: 'nous2', name: 'HermesNous64 Bot', username: '@HermesNous64Bot', model: 'Nous', role: 'Fast & Efficient', supabaseId: '594619d9-e765-4d82-b289-953390aa6d0a', botApiId: 8707123248, envVar: 'BOT_TOKEN_NOUS2' },
  { id: 'codex', name: 'HermesCodexNew64 Bot', username: '@HermesCodexNew64Bot', model: 'Codex', role: 'Code Generation', supabaseId: '630b8adc-0756-41e3-91a8-88bd0ff1443d', botApiId: 8907343970, envVar: 'BOT_TOKEN_CODEX' }
];

// ─── Load tokens from environment variables (primary source) ──
function loadTokensFromEnv() {
  let loaded = 0;
  for (const bot of BOTS) {
    const val = (process.env[bot.envVar] || '').trim();
    if (val) {
      BOT_TOKENS[bot.id] = val;
      loaded++;
    }
  }
  if (loaded > 0) tokensLoaded = true;
  console.log(`✅ Bot tokens loaded from env: ${loaded}/${BOTS.length}`);
  return loaded;
}

// ─── Load tokens from Supabase (backup — fills empty slots only) ─
async function loadTokensFromDB() {
  try {
    const resp = await fetch(`${SB_URL}/rest/v1/bot_tokens?select=*`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    if (!resp.ok) return;
    const rows = await resp.json();
    if (!Array.isArray(rows)) return;

    let filled = 0;
    for (const row of rows) {
      // Env vars take priority — only use the DB value when no env token is set.
      if (row.bot_id && row.token && !BOT_TOKENS[row.bot_id]) {
        BOT_TOKENS[row.bot_id] = row.token;
        filled++;
      }
    }
    if (Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length > 0) tokensLoaded = true;
    console.log(`✅ Bot tokens from Supabase (backup): filled ${filled} empty slot(s). Total configured: ${Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length}`);
  } catch (e) {
    console.log('⚠️ Could not load tokens from DB:', e.message);
  }
}

// ─── Save token to Supabase ───────────────────────────────────
async function saveTokenToDB(botId, token) {
  try {
    await fetch(`${SB_URL}/rest/v1/bot_tokens`, {
      method: 'POST',
      headers: {
        'apikey': SB_KEY,
        'Authorization': `Bearer ${SB_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify({ bot_id: botId, token, updated_at: new Date().toISOString() })
    });
  } catch (e) {
    console.error('Failed to save token:', e.message);
  }
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Supabase Proxy ──────────────────────────────────────────
app.all('/api/sb/*', async (req, res) => {
  const restPath = req.params[0];
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
    const resp = await fetch(url, opts);
    const data = await resp.text();
    res.status(resp.status);
    const cr = resp.headers.get('content-range');
    if (cr) res.set('Content-Range', cr);
    try { res.json(JSON.parse(data)); } catch { res.send(data); }
  } catch (err) {
    res.status(502).json({ error: err.message });
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

// ─── Setup Endpoint ──────────────────────────────────────────
app.get('/api/setup/status', (req, res) => {
  const configured = Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length;
  res.json({ configured, total: 4, tokensLoaded, bots: BOTS.map(b => ({
    id: b.id, name: b.name, hasToken: !!BOT_TOKENS[b.id]
  }))});
});

app.post('/api/setup/token', async (req, res) => {
  try {
    const { botId, token } = req.body;
    if (!botId || !token) return res.status(400).json({ error: 'botId and token required' });
    
    // Validate token by calling getMe
    const testResp = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const testData = await testResp.json();
    if (!testData.ok) return res.status(400).json({ error: 'Invalid token: ' + (testData.description || 'unknown') });
    
    // Save
    BOT_TOKENS[botId] = token;
    await saveTokenToDB(botId, token);
    
    res.json({ ok: true, bot: testData.result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Telegram Endpoints ──────────────────────────────────────
app.get('/api/telegram/:botId/me', async (req, res) => {
  try {
    const info = await tgApi(req.params.botId, 'getMe');
    res.json({ ok: true, result: info });
  } catch (err) {
    res.json({ ok: false, error: err.message });
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
    res.json({ ok: false, error: err.message });
  }
});

app.post('/api/telegram/:botId/send', async (req, res) => {
  try {
    const { chatId, text, parseMode } = req.body;
    if (!chatId || !text) return res.status(400).json({ error: 'chatId and text required' });
    const result = await tgApi(req.params.botId, 'sendMessage', {
      chat_id: chatId, text, parse_mode: parseMode || 'HTML'
    });
    res.json({ ok: true, result });
  } catch (err) {
    res.json({ ok: false, error: err.message });
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
    res.json({ ok: false, error: err.message });
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
        results[bot.id] = { online: false, error: err.message };
      }
    })
  );
  res.json(results);
});

// ─── Stats ───────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const [convosResp, msgsResp] = await Promise.all([
      fetch(`${SB_URL}/rest/v1/conversations?select=id,bot_id,message_count,total_tokens,total_cost,created_at`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetch(`${SB_URL}/rest/v1/messages?select=id,bot_id,tokens_used,cost,created_at`, {
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

    if (Array.isArray(convos)) {
      for (const c of convos) {
        const bid = BOTS.find(b => b.supabaseId === c.bot_id);
        if (bid) { stats.perBot[bid.id].conversations++; stats.perBot[bid.id].tokens += c.total_tokens || 0; stats.perBot[bid.id].cost += parseFloat(c.total_cost || 0); }
        stats.totalTokens += c.total_tokens || 0;
        stats.totalCost += parseFloat(c.total_cost || 0);
      }
    }
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
    res.status(500).json({ error: err.message });
  }
});

// ─── Search ──────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json({ messages: [], conversations: [] });
    const [msgsResp, convosResp] = await Promise.all([
      fetch(`${SB_URL}/rest/v1/messages?content=ilike.%25${encodeURIComponent(q)}%25&order=created_at.desc&limit=50`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetch(`${SB_URL}/rest/v1/conversations?or=(username.ilike.%25${encodeURIComponent(q)}%25,telegram_user_id.ilike.%25${encodeURIComponent(q)}%25)&order=updated_at.desc&limit=50`, {
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
    res.status(500).json({ error: err.message });
  }
});

// ─── Export ──────────────────────────────────────────────────
app.get('/api/export/:botId', async (req, res) => {
  try {
    const bot = BOTS.find(b => b.id === req.params.botId);
    if (!bot) return res.status(400).json({ error: 'Invalid bot' });
    const [msgsResp, convosResp] = await Promise.all([
      fetch(`${SB_URL}/rest/v1/messages?bot_id=eq.${bot.supabaseId}&order=created_at.asc&limit=1000`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      }),
      fetch(`${SB_URL}/rest/v1/conversations?bot_id=eq.${bot.supabaseId}&order=updated_at.desc&limit=100`, {
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
    res.status(500).json({ error: err.message });
  }
});

// Health
app.get('/api/health', (_, res) => res.json({ ok: true, uptime: process.uptime(), tokensLoaded }));

// SPA fallback
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Startup ─────────────────────────────────────────────────
// Primary source: environment variables. Backup: Supabase bot_tokens table.
loadTokensFromEnv();
loadTokensFromDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    const configured = Object.keys(BOT_TOKENS).filter(k => BOT_TOKENS[k]).length;
    console.log(`🤖 Telegram Bots Dashboard on :${PORT} (${configured}/4 tokens configured)`);
  });
});
