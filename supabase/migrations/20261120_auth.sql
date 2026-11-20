create extension if not exists pgcrypto with schema extensions;
create table public.jugadores(id uuid primary key default gen_random_uuid(),username text not null,password_hash text not null,creado timestamptz default now(),mejor_wpm_30 numeric default 0,mejor_wpm_60 numeric default 0);
create unique index jugadores_username_ci on public.jugadores(lower(username));
create table public.sesiones(token text primary key,jugador uuid not null references public.jugadores(id) on delete cascade,creado timestamptz default now(),expira timestamptz not null default(now()+interval '30 days'));
alter table public.jugadores enable row level security;
alter table public.sesiones enable row level security;
revoke all on public.jugadores,public.sesiones from anon,authenticated;
create function public.registrar(p_usuario text,p_password text) returns table(token text,username text) language plpgsql security definer set search_path=public,extensions,pg_temp as $$ declare j uuid; t text; begin
if p_usuario is null or p_usuario !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'Usa entre 3 y 20 letras, números o guion bajo'; end if;
if p_password is null or length(p_password)<6 or octet_length(p_password)>72 then raise exception 'La contraseña debe tener al menos 6 caracteres y como máximo 72 bytes'; end if;
begin insert into public.jugadores(username,password_hash) values(p_usuario,crypt(p_password,gen_salt('bf'))) returning id into j; exception when unique_violation then raise exception 'Ese usuario ya existe'; end;
t:=encode(gen_random_bytes(32),'hex');insert into public.sesiones(token,jugador) values(t,j);return query select t,p_usuario;end $$;
create function public.iniciar_sesion(p_usuario text,p_password text) returns table(token text,username text) language plpgsql security definer set search_path=public,extensions,pg_temp as $$ declare j public.jugadores; t text;begin
select * into j from public.jugadores a where lower(a.username)=lower(p_usuario) and a.password_hash=crypt(p_password,a.password_hash);
if j.id is null then raise exception 'Usuario o contraseña incorrectos'; end if;
t:=encode(gen_random_bytes(32),'hex');insert into public.sesiones(token,jugador) values(t,j.id);return query select t,j.username;end $$;
create function public.cerrar_sesion(p_token text) returns void language sql security definer set search_path=public,pg_temp as $$ delete from public.sesiones where token=p_token $$;
create function public.mi_perfil(p_token text) returns table(username text,mejor_wpm_30 numeric,mejor_wpm_60 numeric) language plpgsql security definer set search_path=public,pg_temp as $$ begin delete from public.sesiones where expira<=now();return query select j.username,j.mejor_wpm_30,j.mejor_wpm_60 from public.jugadores j join public.sesiones s on s.jugador=j.id where s.token=p_token and s.expira>now();end $$;
create function public.guardar_record(p_token text,p_modo text,p_wpm numeric) returns void language plpgsql security definer set search_path=public,pg_temp as $$ begin
if p_modo not in ('30','60') then raise exception 'Modo no válido';end if;
if p_wpm is null or p_wpm<0 or p_wpm>1000 or p_wpm='NaN'::numeric then raise exception 'WPM no válido';end if;
update public.jugadores j set mejor_wpm_30=case when p_modo='30' then greatest(j.mejor_wpm_30,p_wpm) else j.mejor_wpm_30 end,mejor_wpm_60=case when p_modo='60' then greatest(j.mejor_wpm_60,p_wpm) else j.mejor_wpm_60 end where j.id in(select s.jugador from public.sesiones s where s.token=p_token and s.expira>now());end $$;
revoke all on function public.registrar(text,text),public.iniciar_sesion(text,text),public.cerrar_sesion(text),public.mi_perfil(text),public.guardar_record(text,text,numeric) from public;
grant execute on function public.registrar(text,text),public.iniciar_sesion(text,text),public.cerrar_sesion(text),public.mi_perfil(text),public.guardar_record(text,text,numeric) to anon;
