-- Courtside Padel update (2 Oct 2026): organiser applications, level nudges, blocked players,
-- drop-out notices, match chat and profile photos. Paste into Supabase → SQL Editor → Run. Safe to re-run.

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
