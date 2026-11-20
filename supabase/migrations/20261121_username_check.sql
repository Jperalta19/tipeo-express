create or replace function public.usuario_disponible(p_usuario text)
returns boolean language sql stable security definer set search_path = public
as $$ select not exists (select 1 from public.jugadores where lower(username) = lower(trim(p_usuario))); $$;
revoke all on function public.usuario_disponible(text) from public;
grant execute on function public.usuario_disponible(text) to anon, authenticated;

create or replace function public.registrar(p_usuario text,p_password text) returns table(token text,username text) language plpgsql security definer set search_path=public,extensions,pg_temp as $$ declare j uuid; t text; begin
if p_usuario is null or p_usuario !~ '^[A-Za-z0-9_]{6,10}$' then raise exception 'El usuario debe tener entre 6 y 10 caracteres (letras, números o guion bajo)'; end if;
if p_password is null or p_password !~ '^[0-9]{6}$' then raise exception 'La contraseña debe ser de 6 dígitos'; end if;
begin insert into public.jugadores(username,password_hash) values(p_usuario,crypt(p_password,gen_salt('bf'))) returning id into j; exception when unique_violation then raise exception 'Ese usuario ya existe'; end;
t:=encode(gen_random_bytes(32),'hex');insert into public.sesiones(token,jugador) values(t,j);return query select t,p_usuario;end $$;
