-- Kontakt-Dashboard: Datenbank, Rechte und Freigaben für Supabase.
-- Einmal komplett im Supabase SQL Editor ausführen.
-- Das erste Konto, das sich registriert, wird automatisch Admin und ist sofort freigeschaltet.
-- Alle weiteren Konten müssen vom Admin freigeschaltet werden.

-- ---------- Tabellen ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  name text not null default '',
  role text not null default 'user' check (role in ('admin', 'user')),
  active boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.access (
  owner uuid not null references public.profiles (id) on delete cascade,
  viewer uuid not null references public.profiles (id) on delete cascade,
  can_edit boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (owner, viewer),
  check (owner <> viewer)
);

create table if not exists public.contacts (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references public.profiles (id) on delete cascade,
  name text not null default '',
  soziotop text not null default '',
  beruf text not null default '',
  info text not null default '',
  next_step text not null default '',
  next_date date,
  pp text not null default '',
  custom jsonb not null default '{}'::jsonb,
  lists text[] not null default array['haupt'],
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists contacts_owner_idx on public.contacts (owner);

create table if not exists public.field_settings (
  owner uuid primary key references public.profiles (id) on delete cascade,
  fields jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

-- ---------- Hilfsfunktionen (laufen mit Datenbankrechten, damit RLS sich nicht selbst blockiert) ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin' and active);
$$;

create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and active);
$$;

create or replace function public.can_read(list_owner uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_active() and (
    list_owner = auth.uid()
    or exists (select 1 from access where owner = list_owner and viewer = auth.uid())
  );
$$;

create or replace function public.can_write(list_owner uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_active() and (
    list_owner = auth.uid()
    or exists (select 1 from access where owner = list_owner and viewer = auth.uid() and can_edit)
  );
$$;

-- ---------- Neues Konto -> Profil anlegen ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare first_user boolean;
begin
  select not exists (select 1 from profiles) into first_user;
  insert into profiles (id, email, name, role, active)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'name', ''),
    case when first_user then 'admin' else 'user' end,
    first_user
  );
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Nur Admins dürfen Rolle und Freischaltung ändern; niemand ändert seine E-Mail hier.
create or replace function public.guard_profile() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if new.role is distinct from old.role or new.active is distinct from old.active then
      raise exception 'Nur Admins dürfen Rollen und Freischaltungen ändern.';
    end if;
  end if;
  if new.email is distinct from old.email then new.email := old.email; end if;
  -- Der letzte Admin kann sich nicht selbst entmachten.
  if old.role = 'admin' and (new.role <> 'admin' or not new.active)
     and not exists (select 1 from profiles where role = 'admin' and active and id <> old.id) then
    raise exception 'Es muss mindestens einen aktiven Admin geben.';
  end if;
  return new;
end;
$$;
drop trigger if exists guard_profile on public.profiles;
create trigger guard_profile before update on public.profiles
  for each row execute function public.guard_profile();

create or replace function public.touch_updated() returns trigger
language plpgsql as $$ begin new.updated_at := now(); return new; end; $$;
drop trigger if exists touch_contacts on public.contacts;
create trigger touch_contacts before update on public.contacts
  for each row execute function public.touch_updated();

-- ---------- Row Level Security ----------
alter table public.profiles enable row level security;
alter table public.access enable row level security;
alter table public.contacts enable row level security;
alter table public.field_settings enable row level security;

drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated using (
  id = auth.uid() or public.is_admin()
  or exists (select 1 from access a where a.owner = profiles.id and a.viewer = auth.uid())
);
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());

drop policy if exists access_read on public.access;
create policy access_read on public.access for select to authenticated using (
  owner = auth.uid() or viewer = auth.uid() or public.is_admin()
);
drop policy if exists access_admin on public.access;
create policy access_admin on public.access for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists contacts_read on public.contacts;
create policy contacts_read on public.contacts for select to authenticated using (public.can_read(owner));
drop policy if exists contacts_insert on public.contacts;
create policy contacts_insert on public.contacts for insert to authenticated with check (public.can_write(owner));
drop policy if exists contacts_update on public.contacts;
create policy contacts_update on public.contacts for update to authenticated
  using (public.can_write(owner)) with check (public.can_write(owner));
drop policy if exists contacts_delete on public.contacts;
create policy contacts_delete on public.contacts for delete to authenticated using (public.can_write(owner));

drop policy if exists fields_read on public.field_settings;
create policy fields_read on public.field_settings for select to authenticated using (public.can_read(owner));
drop policy if exists fields_write on public.field_settings;
create policy fields_write on public.field_settings for all to authenticated
  using (public.can_write(owner)) with check (public.can_write(owner));

-- ---------- Live-Aktualisierung ----------
do $$ begin
  alter publication supabase_realtime add table public.contacts;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.field_settings;
exception when duplicate_object then null; end $$;
