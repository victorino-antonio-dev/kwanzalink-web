-- KwanzaLink: esquema idempotente (executado no arranque)
create table if not exists users(
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  username text unique not null,
  pw_hash text not null,
  type text not null default 'Criador',
  role text not null default 'user',
  suspended boolean not null default false,
  doc jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists sessions(
  token_hash text primary key,
  user_id uuid not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists sessions_user_idx on sessions(user_id);
create table if not exists public_pages(
  username text primary key references users(username) on update cascade on delete cascade,
  snapshot jsonb not null,
  updated_at timestamptz not null default now()
);
create table if not exists inbox(
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references users(id) on delete cascade,
  kind text not null check (kind in ('order','booking','lead')),
  key text not null,
  data jsonb not null,
  created_at timestamptz not null default now(),
  delivered_at timestamptz,
  unique(owner_id,key)
);
create index if not exists inbox_pending_idx on inbox(owner_id) where delivered_at is null;
create table if not exists events(
  day date not null,
  username text not null,
  type text not null,
  ref text not null default '',
  n integer not null default 0,
  primary key(day,username,type,ref)
);
create table if not exists audit_log(
  id bigserial primary key,
  at timestamptz not null default now(),
  actor text not null,
  action text not null,
  detail jsonb not null default '{}'::jsonb
);
create table if not exists settings(key text primary key, value jsonb not null);
insert into settings(key,value) values('fee','5'),('min_payout','5000') on conflict do nothing;
