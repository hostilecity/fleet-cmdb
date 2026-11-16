CREATE OR REPLACE FUNCTION host_liveness_follow_enrollment()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Only active hosts are evaluated (FR-1.4, #192). A host's host_liveness row records whether it is, so the liveness
  -- run never finds revoked, pending, or retired hosts again: retired is terminal and hosts are never deleted, so
  -- without this every run would read them all, forever. Runs in the transaction that changed the enrollment state,
  -- which holds the host row lock, as every writer of host_liveness does.
  UPDATE host_liveness
     SET evaluated = (NEW.enrollment_state = 'active')
   WHERE host_id = NEW.id AND evaluated IS DISTINCT FROM (NEW.enrollment_state = 'active');
  RETURN NULL;
END;
$$;
