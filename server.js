const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

const SB_URL = process.env.SUPABASE_URL || 'https://jzfamdshbfbwolupywrw.supabase.co';
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Proxy to Supabase
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

// Health
app.get('/api/health', (_, res) => res.json({ ok: true }));

app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`🤖 Telegram Bots Dashboard on :${PORT}`));
