-- Courtside Padel: Supabase schema
-- Run once in Supabase: Dashboard → SQL Editor → New query → paste this file → Run.
-- Safe to re-run: every statement is idempotent.
--
-- Each app record is a row: `id` + a JSON `data` object (the same shape the app already uses).
-- Who can change what is enforced here with row-level security, not just by the app's screens:
--   admin      – anyone whose Google email is in app_admins (seeded with mink.sumana@gmail.com)
--   organiser  – a player listed in a location's organiserIds (admins count as organisers everywhere)
--   player     – any signed-in person; can create and edit only their own profile and sign-ups


-- ---------- admins ----------
create table if not exists public.app_admins (
  email text primary key
);
insert into public.app_admins(email) values ('mink.sumana@gmail.com') on conflict do nothing;

-- ---------- record tables ----------
do $$
declare t text;
begin
  foreach t in array array['locations','players','games','leagues','memberships','signups','settings','levels'] loop
    execute format($f$
      create table if not exists public.%I (
        id          text primary key,
        data        jsonb not null default '{}'::jsonb,
        updated_at  timestamptz not null default now(),
        updated_by  uuid default auth.uid()
      )$f$, t);
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;

-- games and leagues belong to a location; keep it as a real column for rules and queries
alter table public.games   add column if not exists loc_id text generated always as (data->>'locId') stored;
alter table public.leagues add column if not exists loc_id text generated always as (data->>'locId') stored;
create index if not exists games_loc_idx   on public.games(loc_id);
create index if not exists leagues_loc_idx on public.leagues(loc_id);

-- private contact details: only the player and admins can see them
create table if not exists public.player_emails (
  id     text primary key,
  email  text not null,
  updated_at timestamptz not null default now()
);
alter table public.player_emails enable row level security;
alter table public.app_admins    enable row level security;

-- ---------- role helpers ----------
-- Kept in a private schema so they can't be called through the public API; policies still use them.
create schema if not exists app;
grant usage on schema app to authenticated;
create or replace function app.is_admin() returns boolean
language sql stable security definer set search_path = public, app as $$
  select exists (select 1 from public.app_admins a where lower(a.email) = lower(coalesce(auth.jwt()->>'email','')));
$$;

create or replace function app.is_organiser_at(loc text) returns boolean
language sql stable security definer set search_path = public, app as $$
  select app.is_admin() or exists (
    select 1 from public.locations l
    where l.id = loc and coalesce(l.data->'organiserIds','[]'::jsonb) ? (auth.uid()::text)
  );
$$;

-- true when the signed-in person organises at any club this player belongs to
create or replace function app.organises_player(pid text) returns boolean
language sql stable security definer set search_path = public, app as $$
  select app.is_admin() or exists (
    select 1 from public.players p, jsonb_array_elements_text(coalesce(p.data->'locations','[]'::jsonb)) loc
    where p.id = pid and app.is_organiser_at(loc)
  );
$$;

-- ---------- policies ----------
-- Everyone signed in reads the club's records (names, games, tables). Nothing is public to signed-out visitors.
do $$
declare t text;
begin
  foreach t in array array['locations','players','games','leagues','memberships','signups','settings','levels'] loop
    execute format('drop policy if exists "signed-in read" on public.%I', t);
    execute format('create policy "signed-in read" on public.%I for select to authenticated using (true)', t);
  end loop;
end $$;

-- Write rules. Each is split into insert / update / delete so reads use only "signed-in read".
-- (select auth.uid()) is evaluated once per query rather than once per row.
create or replace function app._write_policies(tbl text, cond text) returns void
language plpgsql set search_path = public, app as $$
begin
  execute format('drop policy if exists "admin write" on public.%I', tbl);
  execute format('drop policy if exists "organiser write" on public.%I', tbl);
  execute format('drop policy if exists "organiser levels" on public.%I', tbl);
  execute format('drop policy if exists "own signups" on public.%I', tbl);
  execute format('drop policy if exists "own email" on public.%I', tbl);
  execute format('drop policy if exists "write insert" on public.%I', tbl);
  execute format('drop policy if exists "write update" on public.%I', tbl);
  execute format('drop policy if exists "write delete" on public.%I', tbl);
  execute format('create policy "write insert" on public.%I for insert to authenticated with check (%s)', tbl, cond);
  execute format('create policy "write update" on public.%I for update to authenticated using (%s) with check (%s)', tbl, cond, cond);
  execute format('create policy "write delete" on public.%I for delete to authenticated using (%s)', tbl, cond);
end $$;

-- admin-only records
select app._write_policies('locations',   '(select app.is_admin())');
select app._write_policies('memberships', '(select app.is_admin())');
select app._write_policies('settings',    '(select app.is_admin())');
-- games and leagues: organisers of that location (checked before and after the change)
select app._write_policies('games',   'app.is_organiser_at(loc_id)');
select app._write_policies('leagues', 'app.is_organiser_at(loc_id)');
-- starting-level resets: organisers of that player's club, or admin
select app._write_policies('levels',  'app.organises_player(id)');
-- sign-ups and private emails: your own row only (admin any)
select app._write_policies('signups',       'id = (select auth.uid())::text or (select app.is_admin())');
select app._write_policies('player_emails', 'id = (select auth.uid())::text or (select app.is_admin())');
-- players: create/edit your own profile; admin can create/edit/delete anyone (e.g. test players)
drop policy if exists "own profile insert" on public.players;
drop policy if exists "own profile update" on public.players;
drop policy if exists "admin delete players" on public.players;
select app._write_policies('players', 'id = (select auth.uid())::text or (select app.is_admin())');
drop policy if exists "write delete" on public.players;
create policy "write delete" on public.players for delete to authenticated using ((select app.is_admin()));
-- the player and admins read emails; nobody else
drop policy if exists "own email read" on public.player_emails;
create policy "own email read" on public.player_emails for select to authenticated using (id = (select auth.uid())::text or (select app.is_admin()));
drop policy if exists "admins list" on public.app_admins;
create policy "admins list" on public.app_admins for select to authenticated using ((select app.is_admin()));

-- a player may not change their own starting level after sign-up (organisers use the levels table)
create or replace function app.guard_player_level() returns trigger
language plpgsql security definer set search_path = public, app as $$
begin
  if not app.is_admin() and (old.data->'level') is distinct from (new.data->'level') then
    new.data := jsonb_set(new.data, '{level}', old.data->'level');
  end if;
  if not app.is_admin() and (old.data->'joinedAt') is distinct from (new.data->'joinedAt') then
    new.data := jsonb_set(new.data, '{joinedAt}', old.data->'joinedAt');
  end if;
  return new;
end $$;
drop trigger if exists players_guard_level on public.players;
create trigger players_guard_level before update on public.players
  for each row execute function app.guard_player_level();


-- ---------- housekeeping ----------
create or replace function app.touch() returns trigger language plpgsql set search_path = public, app as $$
begin new.updated_at := now(); new.updated_by := auth.uid(); return new; end $$;
do $$
declare t text;
begin
  foreach t in array array['locations','players','games','leagues','memberships','signups','settings','levels'] loop
    execute format('drop trigger if exists %I on public.%I', t||'_touch', t);
    execute format('create trigger %I before update on public.%I for each row execute function app.touch()', t||'_touch', t);
  end loop;
end $$;

-- ---------- live updates ----------
do $$
declare t text;
begin
  foreach t in array array['locations','players','games','leagues','memberships','signups','settings','levels'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
             when undefined_object then null;   -- publication missing outside Supabase
    end;
  end loop;
end $$;

-- helpers used to live in public (first version); remove them and lock the private ones down
drop function if exists public.organises_player(text);
drop function if exists public.is_organiser_at(text);
drop function if exists public.is_admin();
drop function if exists public.guard_player_level();
drop function if exists public.touch();
revoke all on all functions in schema app from public, anon, authenticated;
grant execute on function app.is_admin(), app.is_organiser_at(text), app.organises_player(text) to authenticated;

-- ---------- hand-over of existing profiles ----------
-- A person who used the earlier version of the app had a different id. List them here (email → old id);
-- the first time they sign in with Google, every record that mentions the old id moves to their new account.
create table if not exists app.pending_claims (
  email  text primary key,
  old_id text not null
);
create or replace function app.claim_on_signup() returns trigger
language plpgsql security definer set search_path = public, app as $$
declare c record; t text; new_id text := new.id::text;
begin
  select * into c from app.pending_claims where lower(email) = lower(new.email);
  if not found then return new; end if;
  foreach t in array array['locations','players','games','leagues','memberships','signups','settings','levels'] loop
    execute format('update public.%I set data = replace(data::text, $1, $2)::jsonb where strpos(data::text, $1) > 0', t) using c.old_id, new_id;
    execute format('update public.%I set id = $2 where id = $1', t) using c.old_id, new_id;
  end loop;
  insert into public.player_emails(id, email) values (new_id, lower(new.email))
    on conflict (id) do update set email = excluded.email;
  delete from app.pending_claims where email = c.email;
  return new;
end $$;
revoke all on function app.claim_on_signup() from public, anon, authenticated;
drop trigger if exists courtside_claim_on_signup on auth.users;
create trigger courtside_claim_on_signup after insert on auth.users
  for each row execute function app.claim_on_signup();

-- ---------- organiser applications ----------
-- One row per applicant (id = their account). They can create, edit and withdraw their own while it is
-- pending; only the admin can approve or decline. Only the applicant and the admin can see it.
create table if not exists public.organiser_requests (
  id          text primary key,
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);
alter table public.organiser_requests enable row level security;
drop policy if exists "own or admin read" on public.organiser_requests;
create policy "own or admin read" on public.organiser_requests for select to authenticated
  using (id = (select auth.uid())::text or (select app.is_admin()));
drop policy if exists "write insert" on public.organiser_requests;
create policy "write insert" on public.organiser_requests for insert to authenticated
  with check ((id = (select auth.uid())::text and data->>'status' = 'pending') or (select app.is_admin()));
drop policy if exists "write update" on public.organiser_requests;
create policy "write update" on public.organiser_requests for update to authenticated
  using (id = (select auth.uid())::text or (select app.is_admin()))
  with check ((id = (select auth.uid())::text and data->>'status' = 'pending') or (select app.is_admin()));
drop policy if exists "write delete" on public.organiser_requests;
create policy "write delete" on public.organiser_requests for delete to authenticated
  using (id = (select auth.uid())::text or (select app.is_admin()));
drop trigger if exists organiser_requests_touch on public.organiser_requests;
create trigger organiser_requests_touch before update on public.organiser_requests for each row execute function app.touch();
do $$ begin
  alter publication supabase_realtime add table public.organiser_requests;
exception when duplicate_object then null; when undefined_object then null; end $$;

-- ---------- level nudges ----------
-- Organisers may nudge a player's level up or down by one; only the admin may reset the starting level.
-- For anyone but the admin, everything except the nudges list is kept as it was, each nudge must be ±1,
-- and earlier nudges cannot be removed.
create or replace function app.guard_levels() returns trigger
language plpgsql security definer set search_path = public, app as $$
declare base jsonb := case when tg_op = 'UPDATE' then old.data else '{}'::jsonb end;
begin
  if app.is_admin() then return new; end if;
  if jsonb_typeof(coalesce(new.data->'nudges','[]'::jsonb)) <> 'array'
     or exists (select 1 from jsonb_array_elements(coalesce(new.data->'nudges','[]'::jsonb)) n
                where (n->>'d') not in ('1','-1'))
     or not (coalesce(new.data->'nudges','[]'::jsonb) @> coalesce(base->'nudges','[]'::jsonb)) then
    raise exception 'Organisers can only nudge a level by one step at a time';
  end if;
  new.data := base || jsonb_build_object('nudges', coalesce(new.data->'nudges','[]'::jsonb));
  return new;
end $$;
drop trigger if exists levels_guard on public.levels;
create trigger levels_guard before insert or update on public.levels
  for each row execute function app.guard_levels();

-- true when the signed-in person organises at any club
create or replace function app.is_organiser_anywhere() returns boolean
language sql stable security definer set search_path = public, app as $$
  select app.is_admin() or exists (
    select 1 from public.locations l where coalesce(l.data->'organiserIds','[]'::jsonb) ? (auth.uid()::text)
  );
$$;

-- ---------- blocked players ----------
-- One row per player (id = their account): {"blocked": [up to 2 player ids]}.
-- Seen only by the player, organisers (the round planner needs it) and the admin.
create table if not exists public.player_blocks (
  id          text primary key,
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid(),
  constraint max_two_blocks check (jsonb_typeof(coalesce(data->'blocked','[]'::jsonb)) = 'array'
                                   and jsonb_array_length(coalesce(data->'blocked','[]'::jsonb)) <= 2)
);
alter table public.player_blocks enable row level security;
drop policy if exists "own organiser admin read" on public.player_blocks;
create policy "own organiser admin read" on public.player_blocks for select to authenticated
  using (id = (select auth.uid())::text or (select app.is_organiser_anywhere()));
select app._write_policies('player_blocks', 'id = (select auth.uid())::text or (select app.is_admin())');
drop trigger if exists player_blocks_touch on public.player_blocks;
create trigger player_blocks_touch before update on public.player_blocks for each row execute function app.touch();

-- ---------- in-app notices (drop-outs) ----------
-- {"type":"dropout","gameId","locId","pid","at","declined"}. A player posts their own; organisers may post any.
create table if not exists public.notices (
  id          text primary key,
  data        jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);
alter table public.notices enable row level security;
drop policy if exists "signed-in read" on public.notices;
create policy "signed-in read" on public.notices for select to authenticated using (true);
drop policy if exists "write insert" on public.notices;
create policy "write insert" on public.notices for insert to authenticated
  with check (data->>'pid' = (select auth.uid())::text or app.is_organiser_at(data->>'locId'));
drop policy if exists "write delete" on public.notices;
create policy "write delete" on public.notices for delete to authenticated
  using (app.is_organiser_at(data->>'locId'));

-- ---------- match chat ----------
create table if not exists public.game_messages (
  id          uuid primary key default gen_random_uuid(),
  game_id     text not null,
  author      text not null default (auth.uid())::text,
  body        text not null check (char_length(body) between 1 and 1000),
  created_at  timestamptz not null default now()
);
create index if not exists game_messages_game_idx on public.game_messages(game_id, created_at);
alter table public.game_messages enable row level security;
drop policy if exists "signed-in read" on public.game_messages;
create policy "signed-in read" on public.game_messages for select to authenticated using (true);
drop policy if exists "own insert" on public.game_messages;
create policy "own insert" on public.game_messages for insert to authenticated
  with check (author = (select auth.uid())::text);
drop policy if exists "own or organiser delete" on public.game_messages;
create policy "own or organiser delete" on public.game_messages for delete to authenticated
  using (author = (select auth.uid())::text
         or exists (select 1 from public.games g where g.id = game_id and app.is_organiser_at(g.loc_id)));

do $$
declare t text;
begin
  foreach t in array array['player_blocks','notices','game_messages'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null; when undefined_object then null;
    end;
  end loop;
end $$;
revoke execute on all functions in schema app from public, anon;
grant execute on function app.is_admin(), app.is_organiser_at(text), app.organises_player(text), app.is_organiser_anywhere() to authenticated;

-- ---------- profile photos ----------
-- Public bucket "avatars"; each person uploads only into a folder named after their account (admin anywhere).
do $$ begin
  if exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
    values ('avatars', 'avatars', true, 2097152, array['image/jpeg','image/png','image/webp'])
    on conflict (id) do update set public = true, file_size_limit = 2097152,
      allowed_mime_types = array['image/jpeg','image/png','image/webp'];
    drop policy if exists "avatars own insert" on storage.objects;
    create policy "avatars own insert" on storage.objects for insert to authenticated
      with check (bucket_id = 'avatars' and ((storage.foldername(name))[1] = (select auth.uid())::text or (select app.is_admin())));
    drop policy if exists "avatars own update" on storage.objects;
    create policy "avatars own update" on storage.objects for update to authenticated
      using (bucket_id = 'avatars' and ((storage.foldername(name))[1] = (select auth.uid())::text or (select app.is_admin())));
    drop policy if exists "avatars own delete" on storage.objects;
    create policy "avatars own delete" on storage.objects for delete to authenticated
      using (bucket_id = 'avatars' and ((storage.foldername(name))[1] = (select auth.uid())::text or (select app.is_admin())));
    drop policy if exists "avatars own select" on storage.objects;
    create policy "avatars own select" on storage.objects for select to authenticated
      using (bucket_id = 'avatars' and ((storage.foldername(name))[1] = (select auth.uid())::text or (select app.is_admin())));
  end if;
end $$;
