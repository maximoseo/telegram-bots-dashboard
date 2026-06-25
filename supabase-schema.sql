-- Telegram Bots Dashboard Supabase schema
-- Run this in Supabase SQL Editor for the project configured by SUPABASE_URL.
-- Do not paste bot tokens here; tokens are saved by the dashboard after the table exists.

create table if not exists public.bot_tokens (
  bot_id text primary key,
  token text not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  bot_id uuid,
  conversation_id uuid,
  direction text,
  sender_type text,
  content_type text default 'text',
  content text,
  text text,
  role text,
  llm_model text,
  tokens_used integer default 0,
  cost numeric default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  bot_id uuid,
  telegram_user_id text,
  username text,
  last_message text,
  message_count integer default 0,
  total_tokens integer default 0,
  total_cost numeric default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists messages_bot_id_created_at_idx on public.messages (bot_id, created_at desc);
create index if not exists conversations_bot_id_updated_at_idx on public.conversations (bot_id, updated_at desc);
create unique index if not exists conversations_bot_id_telegram_user_id_uidx on public.conversations (bot_id, telegram_user_id);
