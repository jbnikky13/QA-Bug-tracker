-- QA Bug Tracker persistent scan history
-- Run this once in the Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.scan_history (
  id uuid primary key default gen_random_uuid(),
  scan_id text not null unique,
  scan_type text not null check (scan_type in ('website','solidity','contract_address')),
  target text not null,
  network text,
  risk_score integer check (risk_score between 0 and 100),
  risk_label text,
  status text not null default 'completed',
  finding_count integer not null default 0,
  summary jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  report jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists scan_history_created_at_idx on public.scan_history(created_at desc);
create index if not exists scan_history_type_idx on public.scan_history(scan_type);
create index if not exists scan_history_target_idx on public.scan_history(target);

-- This table is intended to be written/read by the server-side Streamlit app
-- using SUPABASE_SERVICE_ROLE_KEY. Keep that key in Streamlit Secrets only.
-- No public anon policies are created here.
