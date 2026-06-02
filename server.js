const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Supabase
const SB_URL = process.env.SUPABASE_URL || 'https://jzfamdshbfbwolupywrw.supabase.co';
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// Telegram Bot Tokens (from env vars)
const BOT_TOKENS = {
  nous:    process.env.BOT_TOKEN_NOUS    || '8609253721:AAHt82-RSXd-Q7VZFNpJhXD05o2t_im8P_Q',
  claude:  process.env.BOT_TOKEN_CLAUDE  || '8885902648:AAGAV4hysmObP_uK_s7dJ2k8alc-xc36tgc',
  nous2:   process.env.BOT_TOKEN_NOUS2   || '8707123248:AAG5M_MyiN08M_Ll1GKiJM5OV1_nKJQwpA0',
  codex:   process.env.BOT_TOKEN_CODEX   || '8907343970:AAHK5WXsv6yG8v1JDL7CaVcS6ulBooQR5M0'
};

// Bot definitions
const BOTS = [
  { id: 'nous', name: 'HemesL64 Bot', username: '@HemesL64Bot', model: 'Nous', role: 'General Purpose' },
  { id: 'claude', name: 'HermesClaude64 Bot', username: '@HermesClaude64Bot', model: 'Claude', role: 'Advanced Reasoning' },
  { id: 'nous2', name: 'HermesNous64 Bot', username: '@HermesNous64Bot', model: 'Nous', role: 'Fast & Efficient' },
  { id: 'codex', name: 'HermesCodexNew64 Bot', username: '@HermesCodexNew64Bot', model: 'Codex', role: 'Code Generation' }
];

// Supabase UUIDs for each bot
const BOT_IDS = {
  nous:   '7e3c5278-f01f-4c62-9d8a-aba2599982e0',
  claude: 'c186e227-6ff6-4f9e-8906-5867e1f14224',
  nous2:  '594619d9-e765-4d82-b289-953390aa6d0a',
  codex:  '630b8adc-0756-41e3-91a8-88bd0ff1443d'
};

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
  if (!token) throw new Error(`No token for bot: ${botId}`);
  const url = `https://api.telegram.org/bot${token}/${method}`;
  const opts = { method: 'POST', headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const data = await resp.json();
  if (!data.ok) throw new Error(data.description || 'Telegram API error');
  return data.result;
}

// Get bot info (health check)
app.get('/api/telegram/:botId/me', async (req, res) => {
  try {
    const info = await tgApi(req.params.botId, 'getMe');
    res.json({ ok: true, result: info });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Get bot updates (recent messages)
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

// Send message via Telegram Bot API
app.post('/api/telegram/:botId/send', async (req, res) => {
  try {
    const { chatId, text, parseMode } = req.body;
    if (!chatId || !text) return res.status(400).json({ error: 'chatId and text required' });
    const result = await tgApi(req.params.botId, 'sendMessage', {
      chat_id: chatId,
      text,
      parse_mode: parseMode || 'HTML'
    });
    res.json({ ok: true, result });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Get bot webhook info
app.get('/api/telegram/:botId/webhook', async (req, res) => {
  try {
    const info = await tgApi(req.params.botId, 'getWebhookInfo');
    res.json({ ok: true, result: info });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Health check for all bots (batch)
app.get('/api/bots/health', async (req, res) => {
  const results = {};
  await Promise.allSettled(
    BOTS.map(async (bot) => {
      try {
        const start = Date.now();
        const info = await tgApi(bot.id, 'getMe');
        const latency = Date.now() - start;
        results[bot.id] = { online: true, latency, username: info.username, firstName: info.first_name };
      } catch (err) {
        results[bot.id] = { online: false, error: err.message };
      }
    })
  );
  res.json(results);
});

// Get recent chat IDs from a bot's updates
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
            id: chat.id,
            type: chat.type,
            firstName: chat.first_name || '',
            lastName: chat.last_name || '',
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

// ─── Dashboard Stats Endpoint ────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    // Get conversation counts
    const convosResp = await fetch(`${SB_URL}/rest/v1/conversations?select=id,bot_id,message_count,total_tokens,total_cost,created_at`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    const convos = await convosResp.json();

    // Get message counts
    const msgsResp = await fetch(`${SB_URL}/rest/v1/messages?select=id,bot_id,tokens_used,cost,created_at`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    const msgs = await msgsResp.json();

    const stats = {
      totalConversations: Array.isArray(convos) ? convos.length : 0,
      totalMessages: Array.isArray(msgs) ? msgs.length : 0,
      totalTokens: 0,
      totalCost: 0,
      perBot: {}
    };

    // Init per-bot stats
    for (const bot of BOTS) {
      stats.perBot[bot.id] = { conversations: 0, messages: 0, tokens: 0, cost: 0 };
    }

    // Aggregate conversations
    if (Array.isArray(convos)) {
      for (const c of convos) {
        const bid = Object.keys(BOT_IDS).find(k => BOT_IDS[k] === c.bot_id);
        if (bid && stats.perBot[bid]) {
          stats.perBot[bid].conversations++;
          stats.perBot[bid].tokens += c.total_tokens || 0;
          stats.perBot[bid].cost += parseFloat(c.total_cost || 0);
        }
        stats.totalTokens += c.total_tokens || 0;
        stats.totalCost += parseFloat(c.total_cost || 0);
      }
    }

    // Aggregate messages
    if (Array.isArray(msgs)) {
      for (const m of msgs) {
        const bid = Object.keys(BOT_IDS).find(k => BOT_IDS[k] === m.bot_id);
        if (bid && stats.perBot[bid]) {
          stats.perBot[bid].messages++;
        }
        stats.totalTokens += m.tokens_used || 0;
        stats.totalCost += parseFloat(m.cost || 0);
      }
    }

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Search Endpoint ─────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json([]);
    
    // Search in messages
    const msgsResp = await fetch(
      `${SB_URL}/rest/v1/messages?content=ilike.%25${encodeURIComponent(q)}%25&order=created_at.desc&limit=50`,
      { headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` } }
    );
    const msgs = await msgsResp.json();

    // Search in conversations
    const convosResp = await fetch(
      `${SB_URL}/rest/v1/conversations?or=(username.ilike.%25${encodeURIComponent(q)}%25,telegram_user_id.ilike.%25${encodeURIComponent(q)}%25)&order=updated_at.desc&limit=50`,
      { headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` } }
    );
    const convos = await convosResp.json();

    res.json({
      messages: Array.isArray(msgs) ? msgs : [],
      conversations: Array.isArray(convos) ? convos : []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Export Endpoint ─────────────────────────────────────────
app.get('/api/export/:botId', async (req, res) => {
  try {
    const botId = BOT_IDS[req.params.botId];
    if (!botId) return res.status(400).json({ error: 'Invalid bot ID' });

    const msgsResp = await fetch(
      `${SB_URL}/rest/v1/messages?bot_id=eq.${botId}&order=created_at.asc&limit=1000`,
      { headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` } }
    );
    const msgs = await msgsResp.json();

    const convosResp = await fetch(
      `${SB_URL}/rest/v1/conversations?bot_id=eq.${botId}&order=updated_at.desc&limit=100`,
      { headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` } }
    );
    const convos = await convosResp.json();

    res.json({
      bot: BOTS.find(b => b.id === req.params.botId),
      exportedAt: new Date().toISOString(),
      conversations: Array.isArray(convos) ? convos : [],
      messages: Array.isArray(msgs) ? msgs : []
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health
app.get('/api/health', (_, res) => res.json({ ok: true, uptime: process.uptime() }));

// SPA fallback
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`🤖 Telegram Bots Dashboard on :${PORT}`));
