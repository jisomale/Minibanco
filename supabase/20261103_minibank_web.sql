-- MiniBank web: additive RPC layer. Existing tables and RLS policies are preserved.
-- The deployment script provisions ONLY the already-authorized parent's UUID.
-- Also supplies the conflict target already expected by Streamlit's allowance generator.
CREATE UNIQUE INDEX IF NOT EXISTS minibank_pending_source_unique ON public.pending_incomes(child_id,due_date,source_type);
CREATE SCHEMA IF NOT EXISTS minibank_private;
REVOKE ALL ON SCHEMA minibank_private FROM PUBLIC, anon, authenticated;
CREATE TABLE IF NOT EXISTS minibank_private.web_admins (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS minibank_private.web_requests (
  user_id uuid NOT NULL,
  request_id uuid NOT NULL,
  action text NOT NULL,
  payload jsonb NOT NULL,
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(user_id,request_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA minibank_private FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.require_parent() RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE actor uuid := auth.uid();
BEGIN
  IF actor IS NULL OR NOT EXISTS(SELECT 1 FROM minibank_private.web_admins WHERE user_id=actor) THEN
    RAISE EXCEPTION 'Tu cuenta no tiene permiso para esta operación.' USING ERRCODE='42501';
  END IF;
  RETURN actor;
END;
$$;
REVOKE ALL ON FUNCTION minibank_private.require_parent() FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.today() RETURNS date
LANGUAGE sql STABLE SET search_path = '' AS $$
  SELECT (now() AT TIME ZONE 'America/Guayaquil')::date;
$$;
REVOKE ALL ON FUNCTION minibank_private.today() FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.amount(value text, positive boolean DEFAULT false) RETURNS numeric
LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE n numeric;
BEGIN
  IF value IS NULL OR value !~ '^[0-9]+(\.[0-9]{1,2})?$' THEN
    RAISE EXCEPTION 'Ingresá un monto con hasta dos decimales.' USING ERRCODE='22023';
  END IF;
  n := value::numeric;
  IF n > 1000000000 OR (positive AND n <= 0) THEN
    RAISE EXCEPTION 'El monto está fuera del rango permitido.' USING ERRCODE='22023';
  END IF;
  RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION minibank_private.amount(text,boolean) FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.ensure_allowances() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  -- Shared lock and NOT EXISTS keep this safe even on the migrated schema without a unique index.
  PERFORM pg_advisory_xact_lock(724619203);
  INSERT INTO public.pending_incomes(child_id,due_date,concept,amount,grow_pct,spend_pct,share_pct,source_type,status)
  SELECT c.id,d.due_date::date,'Mensualidad',r.amount,r.grow_pct,r.spend_pct,r.share_pct,'allowance','pending'
  FROM public.children c
  CROSS JOIN LATERAL generate_series(date_trunc('month',c.opening_date::timestamp),date_trunc('month',minibank_private.today()::timestamp),interval '1 month') d(due_date)
  CROSS JOIN LATERAL (
    SELECT ar.* FROM public.allowance_rules ar
    WHERE ar.child_id=c.id AND ar.effective_from<=d.due_date::date
    ORDER BY ar.effective_from DESC,ar.id DESC LIMIT 1
  ) r
  WHERE d.due_date::date>=c.opening_date AND d.due_date::date<=minibank_private.today() AND r.amount>0
    AND NOT EXISTS(SELECT 1 FROM public.pending_incomes p WHERE p.child_id=c.id AND p.due_date=d.due_date::date AND p.source_type='allowance')
  ON CONFLICT DO NOTHING;
END;
$$;
REVOKE ALL ON FUNCTION minibank_private.ensure_allowances() FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION minibank_private.snapshot() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT jsonb_build_object(
    'children',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM public.children x),'[]'::jsonb),
    'transactions',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.date,x.id) FROM public.transactions x),'[]'::jsonb),
    'pending_incomes',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.due_date,x.id) FROM public.pending_incomes x),'[]'::jsonb),
    'allowance_rules',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.effective_from,x.id) FROM public.allowance_rules x),'[]'::jsonb),
    'goals',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id) FROM public.goals x),'[]'::jsonb)
  );
$$;
REVOKE ALL ON FUNCTION minibank_private.snapshot() FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION public.minibank_web_bootstrap() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM minibank_private.require_parent();
  PERFORM minibank_private.ensure_allowances();
  RETURN minibank_private.snapshot() || jsonb_build_object('today',minibank_private.today(),'role','parent','version','2026-11-03.1');
END;
$$;
REVOKE ALL ON FUNCTION public.minibank_web_bootstrap() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.minibank_web_bootstrap() TO authenticated;

CREATE OR REPLACE FUNCTION public.minibank_web_backup() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM minibank_private.require_parent();
  RETURN jsonb_build_object('application','MiniBank','version',1,'generated_at',now(),'source','Supabase/PostgreSQL','data',minibank_private.snapshot());
END;
$$;
REVOKE ALL ON FUNCTION public.minibank_web_backup() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.minibank_web_backup() TO authenticated;

CREATE OR REPLACE FUNCTION public.minibank_web_action(p_action text,p_data jsonb,p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
#variable_conflict use_variable
DECLARE
  actor uuid;
  prior minibank_private.web_requests%ROWTYPE;
  cid bigint;
  rid bigint;
  income public.pending_incomes%ROWTYPE;
  tx public.transactions%ROWTYPE;
  child public.children%ROWTYPE;
  amount numeric;
  ga numeric;
  sa numeric;
  ha numeric;
  gp integer;
  sp integer;
  hp integer;
  when_date date;
  born date;
  opened date;
  rate double precision;
  bucket text;
  kind text;
  concept text;
  note text;
  available numeric;
  result jsonb;
BEGIN
  actor := minibank_private.require_parent();
  IF p_request_id IS NULL OR p_data IS NULL OR jsonb_typeof(p_data)<>'object' THEN
    RAISE EXCEPTION 'Solicitud inválida.' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(actor::text || p_request_id::text,0));
  SELECT * INTO prior FROM minibank_private.web_requests WHERE user_id=actor AND request_id=p_request_id;
  IF FOUND THEN
    IF prior.action<>p_action OR prior.payload<>p_data THEN
      RAISE EXCEPTION 'Esta solicitud ya se utilizó para otra operación.' USING ERRCODE='22023';
    END IF;
    RETURN prior.result;
  END IF;
  IF p_action NOT IN ('allocate','expense','income','rule','profile','transaction','edit','delete','cancel') THEN
    RAISE EXCEPTION 'Operación desconocida.' USING ERRCODE='22023';
  END IF;
  IF p_action IN ('allocate','cancel') THEN
    SELECT child_id INTO cid FROM public.pending_incomes WHERE id=(p_data->>'id')::bigint;
  ELSIF p_action IN ('edit','delete') THEN
    SELECT child_id INTO cid FROM public.transactions WHERE id=(p_data->>'id')::bigint;
  ELSE
    cid := (p_data->>'child_id')::bigint;
  END IF;
  SELECT * INTO child FROM public.children WHERE id=cid FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'El registro ya no existe. Actualizá los datos.' USING ERRCODE='P0001';
  END IF;
  concept := left(COALESCE(NULLIF(trim(p_data->>'concept'),''),'Movimiento'),200);
  note := left(COALESCE(p_data->>'note',''),2000);

  IF p_action='allocate' THEN
    SELECT * INTO income FROM public.pending_incomes WHERE id=(p_data->>'id')::bigint FOR UPDATE;
    IF NOT FOUND OR income.status<>'pending' THEN
      RAISE EXCEPTION 'Este ingreso ya fue repartido o cancelado.' USING ERRCODE='P0001';
    END IF;
    ga := minibank_private.amount(p_data->>'grow');
    sa := minibank_private.amount(p_data->>'spend');
    ha := minibank_private.amount(p_data->>'share');
    amount := round(income.amount::numeric,2);
    IF amount<=0 OR ga+sa+ha<>amount THEN
      RAISE EXCEPTION 'El reparto debe sumar exactamente el ingreso.' USING ERRCODE='22023';
    END IF;
    FOR bucket,available IN SELECT * FROM (VALUES ('grow',ga),('spend',sa),('share',ha)) AS a(b,v) LOOP
      IF available>0 THEN
        INSERT INTO public.transactions(child_id,date,type,concept,amount,note,bucket,source_income_id)
        VALUES(cid,income.due_date,'Asignación',income.concept,available::double precision,
          format('Reparto por monto: Crecer USD %s / Disfrutar USD %s / Compartir USD %s',ga,sa,ha),bucket,income.id);
      END IF;
    END LOOP;
    gp := round(ga/amount*100); sp := least(100-gp,round(sa/amount*100)); hp := 100-gp-sp;
    UPDATE public.pending_incomes SET status='confirmed',confirmed_at=now(),grow_pct=gp,spend_pct=sp,share_pct=hp WHERE id=income.id;
    rid := income.id;

  ELSIF p_action='expense' THEN
    amount := minibank_private.amount(p_data->>'amount',true);
    bucket := p_data->>'bucket';
    IF bucket IS NULL OR bucket NOT IN ('spend','share') THEN
      RAISE EXCEPTION 'Cuenta inválida.' USING ERRCODE='22023';
    END IF;
    SELECT COALESCE(sum(CASE WHEN type IN ('Retiro','Gasto','Donación') THEN -t.amount::numeric ELSE t.amount::numeric END),0)
    INTO available FROM public.transactions t WHERE child_id=cid AND t.bucket=bucket;
    IF amount>available THEN
      RAISE EXCEPTION 'Saldo insuficiente. Actualizá los datos antes de continuar.' USING ERRCODE='P0001';
    END IF;
    INSERT INTO public.transactions(child_id,date,type,concept,amount,note,bucket)
    VALUES(cid,minibank_private.today(),CASE WHEN bucket='spend' THEN 'Gasto' ELSE 'Donación' END,concept,amount::double precision,'',bucket) RETURNING id INTO rid;

  ELSIF p_action IN ('income','rule') THEN
    amount := minibank_private.amount(p_data->>'amount',p_action='income');
    gp := (p_data->>'grow_pct')::integer; sp := (p_data->>'spend_pct')::integer; hp := (p_data->>'share_pct')::integer;
    IF gp IS NULL OR sp IS NULL OR hp IS NULL OR gp<0 OR sp<0 OR hp<0 OR gp>100 OR sp>100 OR hp>100 OR gp+sp+hp<>100 THEN
      RAISE EXCEPTION 'Los porcentajes deben sumar 100%%.' USING ERRCODE='22023';
    END IF;
    when_date := (p_data->>'date')::date;
    IF when_date IS NULL OR when_date<child.opening_date THEN
      RAISE EXCEPTION 'La fecha debe ser desde la apertura de la cuenta.' USING ERRCODE='22023';
    END IF;
    IF p_action='income' THEN
      INSERT INTO public.pending_incomes(child_id,due_date,concept,amount,grow_pct,spend_pct,share_pct,source_type,status)
      VALUES(cid,when_date,concept,amount::double precision,gp,sp,hp,'manual_'||p_request_id::text,'pending') RETURNING id INTO rid;
    ELSE
      INSERT INTO public.allowance_rules(child_id,effective_from,amount,grow_pct,spend_pct,share_pct)
      VALUES(cid,when_date,amount::double precision,gp,sp,hp) RETURNING id INTO rid;
      UPDATE public.pending_incomes SET amount=amount::double precision,grow_pct=gp,spend_pct=sp,share_pct=hp
      WHERE child_id=cid AND source_type='allowance' AND status='pending' AND due_date>=when_date;
      PERFORM minibank_private.ensure_allowances();
    END IF;

  ELSIF p_action='cancel' THEN
    SELECT * INTO income FROM public.pending_incomes WHERE id=(p_data->>'id')::bigint FOR UPDATE;
    IF NOT FOUND OR income.status<>'pending' THEN
      RAISE EXCEPTION 'El ingreso ya cambió de estado. Actualizá los datos.' USING ERRCODE='P0001';
    END IF;
    UPDATE public.pending_incomes SET status='cancelled' WHERE id=income.id;
    rid := income.id;

  ELSIF p_action='profile' THEN
    IF p_data->'expected' IS NULL OR p_data->'expected'<>to_jsonb(child) THEN
      RAISE EXCEPTION 'El perfil cambió desde que lo abriste. Actualizá antes de guardar.' USING ERRCODE='P0001';
    END IF;
    born := (p_data->>'birth_date')::date; opened := (p_data->>'opening_date')::date;
    rate := (p_data->>'annual_rate')::double precision;
    IF born IS NULL OR opened IS NULL OR rate IS NULL OR NOT (rate>=0 AND rate<=1) OR born>opened OR opened>minibank_private.today() THEN
      RAISE EXCEPTION 'Revisá las fechas y la tasa (0 a 100%%).' USING ERRCODE='22023';
    END IF;
    UPDATE public.children SET birth_date=born,opening_date=opened,annual_rate=rate WHERE id=cid;
    rid := cid;

  ELSIF p_action IN ('transaction','edit','delete') THEN
    IF p_action IN ('edit','delete') THEN
      SELECT * INTO tx FROM public.transactions WHERE id=(p_data->>'id')::bigint FOR UPDATE;
      IF NOT FOUND OR p_data->'expected' IS NULL OR p_data->'expected'<>to_jsonb(tx) THEN
        RAISE EXCEPTION 'El movimiento cambió desde que lo abriste. Actualizá antes de guardar.' USING ERRCODE='P0001';
      END IF;
    END IF;
    IF p_action='delete' THEN
      DELETE FROM public.transactions WHERE id=tx.id;
      rid := tx.id;
    ELSE
      amount := minibank_private.amount(p_data->>'amount');
      bucket := p_data->>'bucket'; kind := p_data->>'type'; when_date := (p_data->>'date')::date;
      IF bucket IS NULL OR kind IS NULL OR bucket NOT IN ('grow','spend','share') OR kind NOT IN ('Aporte','Bonificación','Asignación','Ingreso','Retiro','Gasto','Donación') OR when_date IS NULL OR when_date<child.opening_date OR when_date>minibank_private.today() THEN
        RAISE EXCEPTION 'Revisá el tipo, la cuenta y la fecha del movimiento.' USING ERRCODE='22023';
      END IF;
      IF p_action='edit' THEN
        UPDATE public.transactions SET date=when_date,type=kind,concept=concept,amount=amount::double precision,note=note,bucket=bucket WHERE id=tx.id;
        rid := tx.id;
      ELSE
        INSERT INTO public.transactions(child_id,date,type,concept,amount,note,bucket)
        VALUES(cid,when_date,kind,concept,amount::double precision,note,bucket) RETURNING id INTO rid;
      END IF;
    END IF;
  END IF;
  result := jsonb_build_object('ok',true,'id',rid,'action',p_action);
  INSERT INTO minibank_private.web_requests(user_id,request_id,action,payload,result) VALUES(actor,p_request_id,p_action,p_data,result);
  RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION public.minibank_web_action(text,jsonb,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.minibank_web_action(text,jsonb,uuid) TO authenticated;

NOTIFY pgrst,'reload schema';
