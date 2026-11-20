create or replace function public.usuario_disponible(p_usuario text)
returns boolean language sql stable security definer set search_path = public
as $$ select not exists (select 1 from public.jugadores where lower(username) = lower(trim(p_usuario))); $$;
revoke all on function public.usuario_disponible(text) from public;
grant execute on function public.usuario_disponible(text) to anon, authenticated;
