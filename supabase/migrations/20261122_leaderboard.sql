create or replace function public.top_global(p_token text, p_modo text default '30')
returns table(posicion bigint, username text, mejor_wpm numeric)
language sql security definer set search_path=public,pg_temp as $$
with caller as (select jugador from public.sesiones where token=p_token and expira>now()),
scores as (select j.id,j.username,case when p_modo='60' then coalesce(j.mejor_wpm_60,0) else coalesce(j.mejor_wpm_30,0) end as score from public.jugadores j),
ranks as (select *,rank() over(order by score desc) as place,row_number() over(order by score desc,lower(username),id) as row from scores)
select place, r.username,score from ranks r where exists(select 1 from caller) and (r.row<=5 or r.id=(select jugador from caller)) order by r.row;
$$;
revoke all on function public.top_global(text,text) from public;
grant execute on function public.top_global(text,text) to anon,authenticated;
