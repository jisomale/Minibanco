-- Private password gate for the existing authorized parent. No business rows change.
CREATE TABLE IF NOT EXISTS minibank_private.admin_password (
  id boolean PRIMARY KEY DEFAULT true CHECK(id),
  password_hash text NOT NULL
);
INSERT INTO minibank_private.admin_password(id,password_hash)
VALUES(true,extensions.crypt('2026',extensions.gen_salt('bf',10))) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS minibank_private.admin_access (
  user_id uuid NOT NULL,
  session_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(user_id,session_id)
);
CREATE TABLE IF NOT EXISTS minibank_private.admin_attempts (
  user_id uuid PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  failures integer NOT NULL DEFAULT 0
);
REVOKE ALL ON minibank_private.admin_password,minibank_private.admin_access,minibank_private.admin_attempts FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.require_admin() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE actor uuid := minibank_private.require_parent(); sid text := auth.jwt()->>'session_id';
BEGIN
  IF sid IS NULL OR NOT EXISTS(SELECT 1 FROM minibank_private.admin_access a WHERE a.user_id=actor AND a.session_id=sid AND a.expires_at>now()) THEN
    RAISE EXCEPTION 'Ingresá la contraseña de Administración para continuar.' USING ERRCODE='42501';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION minibank_private.require_admin() FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION public.minibank_admin_unlock(p_password text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE actor uuid := minibank_private.require_parent(); sid text := auth.jwt()->>'session_id'; attempt minibank_private.admin_attempts%ROWTYPE; hash text;
BEGIN
  IF sid IS NULL OR length(sid)>200 THEN
    RAISE EXCEPTION 'Volvé a iniciar sesión en MiniBank.' USING ERRCODE='42501';
  END IF;
  INSERT INTO minibank_private.admin_attempts(user_id) VALUES(actor) ON CONFLICT DO NOTHING;
  SELECT * INTO attempt FROM minibank_private.admin_attempts WHERE user_id=actor FOR UPDATE;
  IF attempt.started_at<=now()-interval '15 minutes' THEN
    UPDATE minibank_private.admin_attempts SET started_at=now(),failures=0 WHERE user_id=actor;
    attempt.failures:=0;
  END IF;
  IF attempt.failures>=5 THEN
    RETURN jsonb_build_object('ok',false,'message','Demasiados intentos. Esperá 15 minutos antes de volver a intentar.');
  END IF;
  SELECT password_hash INTO hash FROM minibank_private.admin_password WHERE id=true;
  IF p_password IS NULL OR length(p_password)>128 OR extensions.crypt(p_password,hash)<>hash THEN
    UPDATE minibank_private.admin_attempts SET failures=failures+1 WHERE user_id=actor;
    RETURN jsonb_build_object('ok',false,'message','Contraseña incorrecta.');
  END IF;
  UPDATE minibank_private.admin_attempts SET failures=0,started_at=now() WHERE user_id=actor;
  INSERT INTO minibank_private.admin_access(user_id,session_id,expires_at) VALUES(actor,sid,now()+interval '15 minutes')
  ON CONFLICT(user_id,session_id) DO UPDATE SET expires_at=excluded.expires_at;
  RETURN jsonb_build_object('ok',true,'expires_at',now()+interval '15 minutes');
END;
$$;
REVOKE ALL ON FUNCTION public.minibank_admin_unlock(text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.minibank_admin_unlock(text) TO authenticated;

CREATE OR REPLACE FUNCTION public.minibank_admin_lock() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE actor uuid := minibank_private.require_parent();
BEGIN
  DELETE FROM minibank_private.admin_access WHERE user_id=actor AND session_id=auth.jwt()->>'session_id';
END;
$$;
REVOKE ALL ON FUNCTION public.minibank_admin_lock() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.minibank_admin_lock() TO authenticated;

-- Apply the gate before idempotent replay or any admin business action.
DO $$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('public.minibank_web_action(text,jsonb,uuid)'::regprocedure) INTO definition;
  IF strpos(definition,'minibank_private.require_admin()')=0 THEN
    IF strpos(definition,'actor := minibank_private.require_parent();')=0 THEN RAISE EXCEPTION 'Unexpected action function version'; END IF;
    definition:=replace(definition,'actor := minibank_private.require_parent();',
      'actor := minibank_private.require_parent(); IF p_action IS NULL OR p_action NOT IN (''allocate'',''expense'') THEN PERFORM minibank_private.require_admin(); END IF;');
    EXECUTE definition;
  END IF;
  SELECT pg_get_functiondef('public.minibank_web_backup()'::regprocedure) INTO definition;
  IF strpos(definition,'minibank_private.require_admin()')=0 THEN
    IF strpos(definition,'PERFORM minibank_private.require_parent();')=0 THEN RAISE EXCEPTION 'Unexpected backup function version'; END IF;
    EXECUTE replace(definition,'PERFORM minibank_private.require_parent();','PERFORM minibank_private.require_parent(); PERFORM minibank_private.require_admin();');
  END IF;
END;
$$;
NOTIFY pgrst,'reload schema';
