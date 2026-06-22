# Session Persistence Fix — Run 994

## Problem
`server.js:24` — `const sessions = new Map()` is purely in-memory. All authenticated sessions are lost on server restart, forcing every dashboard user to re-login. Since the dashboard has a DASHBOARD_PASSWORD, this is an unnecessary friction point.

## Fix
1. Add `fs` import for file I/O
2. Define `SESSION_FILE` path (`/tmp/tgb-sessions.json` for Render compat)
3. Implement `saveSessions()` — serialize Map to JSON, write atomically (write temp file + rename)
4. Implement `loadSessions()` — read JSON, hydrate Map, skip expired sessions (>24h), return count
5. Call `loadSessions()` at startup before server.listen()
6. Call `saveSessions()` after each successful login
7. Add session expiry cleanup on load

## Why /tmp/ on Render
Render's persistent disk (`/opt/render/project/`) is available but `/tmp/` is simpler and survives restarts within the same deploy. Cold deploys lose sessions, which is the same as current behavior.

## Changes
- server.js: +30 lines, -1 line
