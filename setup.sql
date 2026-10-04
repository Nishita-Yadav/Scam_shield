-- Run this in Supabase: SQL Editor > New query > Run

create table if not exists public.reports (
  id         bigint generated always as identity primary key,
  domain     text not null check (domain ~ '^[a-z0-9.-]{3,100}$'),
  kind       text not null check (kind in ('scam','ok')),
  created_at timestamptz not null default now()
);

alter table public.reports enable row level security;

-- Anyone may add a report. Nobody can read, edit or delete rows directly.
create policy "anyone can report" on public.reports
  for insert to anon with check (true);

-- Public, read-only totals per domain (no raw rows exposed)
create or replace view public.report_counts as
  select domain,
         count(*) filter (where kind = 'scam') as scam,
         count(*) filter (where kind = 'ok')   as ok
  from public.reports
  group by domain;

grant select on public.report_counts to anon;
grant insert on public.reports to anon;
