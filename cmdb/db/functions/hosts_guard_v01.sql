CREATE OR REPLACE FUNCTION hosts_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Hosts are retired, never deleted (P1-S02).
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'hosts are retired, never deleted: % is not allowed', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- New hosts start pending (FR-1.1).
  IF TG_OP = 'INSERT' THEN
    IF NEW.enrollment_state <> 'pending' THEN
      RAISE EXCEPTION 'new hosts start pending, not %', NEW.enrollment_state
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- Only the FR-1.1 transitions, whichever code path writes the column; retired is terminal.
  IF NEW.enrollment_state IS DISTINCT FROM OLD.enrollment_state
     AND (OLD.enrollment_state::text, NEW.enrollment_state::text) NOT IN (
       ('pending', 'active'),
       ('active', 'revoked'),
       ('revoked', 'pending'),
       ('active', 'pending'),
       ('pending', 'retired'),
       ('active', 'retired'),
       ('revoked', 'retired')
     ) THEN
    RAISE EXCEPTION 'invalid enrollment state transition: % -> %', OLD.enrollment_state, NEW.enrollment_state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
