-- Modo 90: additive, preserves 30s records and legacy profile RPC.
ALTER TABLE public.jugadores ADD COLUMN IF NOT EXISTS mejor_wpm_90 numeric DEFAULT 0;
CREATE OR REPLACE FUNCTION public.mi_perfil(p_token text, p_version integer)
RETURNS TABLE(username text, mejor_wpm_30 numeric, mejor_wpm_60 numeric, mejor_wpm_90 numeric)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN DELETE FROM public.sesiones WHERE expira<=now();
RETURN QUERY SELECT j.username,j.mejor_wpm_30,j.mejor_wpm_60,j.mejor_wpm_90 FROM public.jugadores j JOIN public.sesiones s ON s.jugador=j.id WHERE s.token=p_token AND s.expira>now(); END $$;
REVOKE ALL ON FUNCTION public.mi_perfil(text,integer) FROM public;
GRANT EXECUTE ON FUNCTION public.mi_perfil(text,integer) TO anon,authenticated;
CREATE OR REPLACE FUNCTION public.guardar_record(p_token text,p_modo text,p_wpm numeric) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
IF p_modo NOT IN ('30','60','90') THEN RAISE EXCEPTION 'Modo no válido'; END IF;
IF p_wpm IS NULL OR p_wpm<0 OR p_wpm>1000 OR p_wpm='NaN'::numeric THEN RAISE EXCEPTION 'WPM no válido'; END IF;
UPDATE public.jugadores j SET
mejor_wpm_30=CASE WHEN p_modo='30' THEN greatest(j.mejor_wpm_30,p_wpm) ELSE j.mejor_wpm_30 END,
mejor_wpm_60=CASE WHEN p_modo='60' THEN greatest(j.mejor_wpm_60,p_wpm) ELSE j.mejor_wpm_60 END,
mejor_wpm_90=CASE WHEN p_modo='90' THEN greatest(j.mejor_wpm_90,p_wpm) ELSE j.mejor_wpm_90 END
WHERE j.id IN(SELECT s.jugador FROM public.sesiones s WHERE s.token=p_token AND s.expira>now()); END $$;
CREATE OR REPLACE FUNCTION public.top_global(p_token text,p_modo text DEFAULT '30')
RETURNS TABLE(posicion bigint,username text,mejor_wpm numeric)
LANGUAGE sql SECURITY DEFINER SET search_path=public,pg_temp AS $$
WITH caller AS (SELECT jugador FROM public.sesiones WHERE token=p_token AND expira>now()),
scores AS (SELECT j.id,j.username, CASE WHEN p_modo='90' THEN coalesce(j.mejor_wpm_90,0) WHEN p_modo='60' THEN coalesce(j.mejor_wpm_60,0) ELSE coalesce(j.mejor_wpm_30,0) END AS score FROM public.jugadores j),
ranks AS (SELECT *,rank() OVER(ORDER BY score DESC) AS place,row_number() OVER(ORDER BY score DESC,lower(username),id) AS row FROM scores)
SELECT place,r.username,score FROM ranks r WHERE EXISTS(SELECT 1 FROM caller) AND(r.row<=5 OR r.id=(SELECT jugador FROM caller)) ORDER BY r.row;
$$;
REVOKE ALL ON FUNCTION public.top_global(text,text) FROM public;
GRANT EXECUTE ON FUNCTION public.top_global(text,text) TO anon,authenticated;
