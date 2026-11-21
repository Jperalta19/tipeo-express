ALTER TABLE public.jugadores ADD COLUMN IF NOT EXISTS ultimo_record timestamptz;
CREATE TABLE IF NOT EXISTS public.intentos_login (usuario text PRIMARY KEY, fallos integer NOT NULL DEFAULT 0, inicio timestamptz NOT NULL DEFAULT now(), ultimo timestamptz NOT NULL DEFAULT now());
ALTER TABLE public.intentos_login ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.intentos_login FROM anon, authenticated;
CREATE OR REPLACE FUNCTION public.guardar_record(p_token text,p_modo text,p_wpm numeric) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
 IF p_modo NOT IN ('30','60','90') OR p_modo IS NULL THEN RETURN; END IF;
 IF p_wpm IS NULL OR p_wpm<=0 OR p_wpm>300 OR p_wpm='NaN'::numeric THEN RETURN; END IF;
 UPDATE public.jugadores j SET ultimo_record=clock_timestamp(),
 mejor_wpm_30=CASE WHEN p_modo='30' THEN greatest(j.mejor_wpm_30,p_wpm) ELSE j.mejor_wpm_30 END,
 mejor_wpm_60=CASE WHEN p_modo='60' THEN greatest(j.mejor_wpm_60,p_wpm) ELSE j.mejor_wpm_60 END,
 mejor_wpm_90=CASE WHEN p_modo='90' THEN greatest(j.mejor_wpm_90,p_wpm) ELSE j.mejor_wpm_90 END
 WHERE j.id IN(SELECT s.jugador FROM public.sesiones s WHERE s.token=p_token AND s.expira>now())
 AND (j.ultimo_record IS NULL OR j.ultimo_record<=clock_timestamp()-interval '30 seconds');
END $$;
-- Failed logins return a null token and the Spanish error in username.
-- Raising an exception would roll back the failure counter.
CREATE OR REPLACE FUNCTION public.iniciar_sesion(p_usuario text,p_password text) RETURNS TABLE(token text,username text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,extensions,pg_temp AS $$
DECLARE j public.jugadores; a public.intentos_login; u text:=lower(coalesce(p_usuario,'')); t text; mensaje text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtext(u));
 SELECT * INTO a FROM public.intentos_login WHERE usuario=u;
 IF a.fallos>=10 AND a.ultimo>clock_timestamp()-interval '15 minutes' THEN
 RETURN QUERY SELECT NULL::text,'Demasiados intentos fallidos. Espera unos minutos e intenta de nuevo.'::text; RETURN;
 END IF;
 IF a.inicio<=clock_timestamp()-interval '15 minutes' THEN DELETE FROM public.intentos_login WHERE usuario=u; END IF;
 SELECT * INTO j FROM public.jugadores x WHERE lower(x.username)=u;
 IF j.id IS NULL THEN mensaje:='El usuario no existe';
 ELSIF p_password IS NULL OR j.password_hash<>crypt(p_password,j.password_hash) THEN mensaje:='Usuario o contraseña incorrectos'; END IF;
 IF mensaje IS NOT NULL THEN
 INSERT INTO public.intentos_login(usuario,fallos,inicio,ultimo) VALUES(u,1,clock_timestamp(),clock_timestamp())
 ON CONFLICT(usuario) DO UPDATE SET fallos=intentos_login.fallos+1,ultimo=clock_timestamp();
 RETURN QUERY SELECT NULL::text,mensaje; RETURN;
 END IF;
 DELETE FROM public.intentos_login WHERE usuario=u;
 t:=encode(gen_random_bytes(32),'hex'); INSERT INTO public.sesiones(token,jugador) VALUES(t,j.id);
 RETURN QUERY SELECT t,j.username;
END $$;
REVOKE ALL ON FUNCTION public.iniciar_sesion(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.iniciar_sesion(text,text) TO anon;
