-- Kalender, To-Dos und Buchungen für das Kontakt-Dashboard.
-- Einmal im Supabase SQL Editor ausführen (zusätzlich zu schema.sql, das schon läuft).
-- Kann gefahrlos mehrfach ausgeführt werden.

-- ---------- Tabellen ----------
create table if not exists public.cal_settings (
  owner uuid primary key references public.profiles (id) on delete cascade,
  avail jsonb not null default '[]'::jsonb,      -- buchbare Zeiten pro Wochentag: [{day:1..7, start:"18:00", end:"20:00"}]
  focus jsonb not null default '[]'::jsonb,      -- Zeit für To-Dos, gleiches Format
  slot_min integer not null default 60 check (slot_min between 15 and 240),
  weeks integer not null default 4 check (weeks between 1 and 12),
  blocked jsonb not null default '[]'::jsonb,    -- freie Tage: ["2026-12-24", ...]
  updated_at timestamptz not null default now()
);

create table if not exists public.cal_access (
  owner uuid not null references public.profiles (id) on delete cascade,
  viewer uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (owner, viewer),
  check (owner <> viewer)
);

create table if not exists public.todos (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references public.profiles (id) on delete cascade,
  title text not null default '',
  done boolean not null default false,
  due date,
  duration_min integer not null default 30 check (duration_min between 5 and 480),
  priority integer not null default 2 check (priority between 1 and 3),
  planned_start timestamptz,
  contact_id uuid references public.contacts (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists todos_owner_idx on public.todos (owner);

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references public.profiles (id) on delete cascade,
  booker uuid not null references public.profiles (id) on delete cascade,
  owner_name text not null default '',
  booker_name text not null default '',
  title text not null default 'Termin',
  note text not null default '',
  start_at timestamptz not null,
  end_at timestamptz not null,
  created_at timestamptz not null default now(),
  check (end_at > start_at)
);
create index if not exists bookings_owner_idx on public.bookings (owner, start_at);
create index if not exists bookings_booker_idx on public.bookings (booker, start_at);

-- ---------- Hilfsfunktionen ----------
create or replace function public.can_see_cal(cal_owner uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_active() and (
    cal_owner = auth.uid()
    or exists (select 1 from cal_access where owner = cal_owner and viewer = auth.uid())
  );
$$;

create or replace function public.member_name(p uuid) returns text
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(name, ''), split_part(email, '@', 1)) from profiles where id = p;
$$;

-- Alle freigeschalteten Mitglieder (nur Name, keine E-Mail), damit man Freigaben auswählen kann.
create or replace function public.list_members() returns table (id uuid, name text)
language sql stable security definer set search_path = public as $$
  select p.id, coalesce(nullif(p.name, ''), split_part(p.email, '@', 1))
  from profiles p where p.active and public.is_active()
  order by 2;
$$;

-- Belegte Zeiten eines Kalenders ohne Details (Buchungen und eingeplante To-Dos).
create or replace function public.cal_busy(p_owner uuid, p_from timestamptz, p_to timestamptz)
returns table (start_at timestamptz, end_at timestamptz)
language sql stable security definer set search_path = public as $$
  select b.start_at, b.end_at from bookings b
   where public.can_see_cal(p_owner) and b.owner = p_owner and b.end_at > p_from and b.start_at < p_to
  union all
  select t.planned_start, t.planned_start + make_interval(mins => t.duration_min) from todos t
   where public.can_see_cal(p_owner) and t.owner = p_owner and not t.done and t.planned_start is not null
     and t.planned_start + make_interval(mins => t.duration_min) > p_from and t.planned_start < p_to;
$$;

-- Buchung prüfen: nur mit Freigabe, nicht in der Vergangenheit, keine Überschneidung.
create or replace function public.check_booking() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.booker := auth.uid();
  if not public.can_see_cal(new.owner) then
    raise exception 'Du hast keinen Zugriff auf diesen Kalender.';
  end if;
  if new.start_at < now() - interval '5 minutes' then
    raise exception 'Dieser Termin liegt in der Vergangenheit.';
  end if;
  perform pg_advisory_xact_lock(hashtext(new.owner::text));
  if exists (
    select 1 from public.cal_busy(new.owner, new.start_at, new.end_at)
  ) then
    raise exception 'Diese Zeit ist leider schon vergeben.';
  end if;
  new.owner_name := coalesce(public.member_name(new.owner), '');
  new.booker_name := coalesce(public.member_name(new.booker), '');
  return new;
end;
$$;
drop trigger if exists check_booking on public.bookings;
create trigger check_booking before insert on public.bookings
  for each row execute function public.check_booking();

drop trigger if exists touch_todos on public.todos;
create trigger touch_todos before update on public.todos
  for each row execute function public.touch_updated();

-- ---------- Row Level Security ----------
alter table public.cal_settings enable row level security;
alter table public.cal_access enable row level security;
alter table public.todos enable row level security;
alter table public.bookings enable row level security;

drop policy if exists cal_settings_read on public.cal_settings;
create policy cal_settings_read on public.cal_settings for select to authenticated using (public.can_see_cal(owner));
drop policy if exists cal_settings_write on public.cal_settings;
create policy cal_settings_write on public.cal_settings for all to authenticated
  using (owner = auth.uid() and public.is_active()) with check (owner = auth.uid() and public.is_active());

-- Jede Person stellt selbst ein, wer ihren Kalender sehen und buchen darf.
drop policy if exists cal_access_read on public.cal_access;
create policy cal_access_read on public.cal_access for select to authenticated using (owner = auth.uid() or viewer = auth.uid());
drop policy if exists cal_access_write on public.cal_access;
create policy cal_access_write on public.cal_access for all to authenticated
  using (owner = auth.uid() and public.is_active()) with check (owner = auth.uid() and public.is_active());

drop policy if exists todos_own on public.todos;
create policy todos_own on public.todos for all to authenticated
  using (owner = auth.uid() and public.is_active()) with check (owner = auth.uid() and public.is_active());

drop policy if exists bookings_read on public.bookings;
create policy bookings_read on public.bookings for select to authenticated using (owner = auth.uid() or booker = auth.uid());
drop policy if exists bookings_insert on public.bookings;
create policy bookings_insert on public.bookings for insert to authenticated with check (public.can_see_cal(owner));
drop policy if exists bookings_delete on public.bookings;
create policy bookings_delete on public.bookings for delete to authenticated using (owner = auth.uid() or booker = auth.uid());

-- ---------- Live-Aktualisierung ----------
do $$ begin
  alter publication supabase_realtime add table public.bookings;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.todos;
exception when duplicate_object then null; end $$;

-- Arbeitszeit für den Zeitstrahl auf der Startseite (z. B. {"start": 7, "end": 21}). Ohne diese Spalte merkt sich die App die Zeit nur pro Gerät.
alter table public.cal_settings add column if not exists day_hours jsonb;
