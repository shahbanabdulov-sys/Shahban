create table if not exists public.history_points (
  id bigserial primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  t bigint not null,
  y double precision not null,
  created_at timestamptz not null default now(),
  unique (user_id, t)
);

create index if not exists history_points_user_t_desc_idx
on public.history_points (user_id, t desc);

alter table public.history_points enable row level security;

drop policy if exists "history_points_select_own" on public.history_points;
create policy "history_points_select_own"
on public.history_points
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "history_points_insert_own" on public.history_points;
create policy "history_points_insert_own"
on public.history_points
for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "history_points_update_own" on public.history_points;
create policy "history_points_update_own"
on public.history_points
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

insert into public.history_points (user_id, t, y)
select
  user_data.user_id,
  floor((point.value ->> 't')::numeric)::bigint as t,
  (point.value ->> 'y')::double precision as y
from public.user_data
cross join lateral jsonb_array_elements(
  case
    when jsonb_typeof(user_data.data -> 'history') = 'array' then user_data.data -> 'history'
    else '[]'::jsonb
  end
) as point(value)
where (point.value ->> 't') ~ '^[0-9]+(\.[0-9]+)?$'
  and (point.value ->> 'y') ~ '^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$'
on conflict (user_id, t) do update
set y = excluded.y;

update public.user_data
set data = data - 'history'
where data ? 'history';
