create or replace function public.registrar(p_usuario text,p_password text) returns table(token text,username text) language plpgsql security definer set search_path=public,extensions,pg_temp as $$ declare j uuid; t text; begin
if p_usuario is null or p_usuario !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'Usa entre 3 y 20 letras, números o guion bajo'; end if;
if p_password is null or p_password !~ '^[0-9]{6}$' then raise exception 'La contraseña debe ser de 6 dígitos'; end if;
begin insert into public.jugadores(username,password_hash) values(p_usuario,crypt(p_password,gen_salt('bf'))) returning id into j; exception when unique_violation then raise exception 'Ese usuario ya existe'; end;
t:=encode(gen_random_bytes(32),'hex');insert into public.sesiones(token,jugador) values(t,j);return query select t,p_usuario;end $$;
create or replace function public.iniciar_sesion(p_usuario text,p_password text) returns table(token text,username text) language plpgsql security definer set search_path=public,extensions,pg_temp as $$ declare j public.jugadores; t text;begin
select * into j from public.jugadores a where lower(a.username)=lower(p_usuario);
if j.id is null then raise exception 'El usuario no existe'; end if;
if p_password is null or j.password_hash<>crypt(p_password,j.password_hash) then raise exception 'Usuario o contraseña incorrectos'; end if;
t:=encode(gen_random_bytes(32),'hex');insert into public.sesiones(token,jugador) values(t,j.id);return query select t,j.username;end $$;
