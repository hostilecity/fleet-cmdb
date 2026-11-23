CREATE OR REPLACE FUNCTION finding_decisions_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Operator decisions are kept as the record of what was decided (VT-OVERRIDES #261): never deleted.
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'finding decisions are never deleted: % is not allowed', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- A decision starts active.
  IF TG_OP = 'INSERT' THEN
    IF NEW.ended_at IS NOT NULL THEN
      RAISE EXCEPTION 'new finding decisions start active'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- Ended is final: an ended decision never changes.
  IF OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'finding decision % ended (%); it cannot change', OLD.id, OLD.ended_why
      USING ERRCODE = 'check_violation';
  END IF;

  -- What a decision is, on what, by whom, and the evidence it was recorded on never change. Only its reason and
  -- expiry (an operator's change) and its end may.
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.host_id IS DISTINCT FROM OLD.host_id OR NEW.advisory_id IS DISTINCT FROM OLD.advisory_id
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.evidence IS DISTINCT FROM OLD.evidence
     OR NEW.confirmed IS DISTINCT FROM OLD.confirmed OR NEW.request_id IS DISTINCT FROM OLD.request_id THEN
    RAISE EXCEPTION 'a finding decision''s host, advisory, kind, author, evidence, and confirmation never change'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
