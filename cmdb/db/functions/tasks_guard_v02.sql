CREATE OR REPLACE FUNCTION tasks_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Tasks are kept as the record of what ran (P3-S02, P3-S07).
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'tasks are never deleted: % is not allowed', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- A task starts queued, with no lease, claim, start, or result (P3-S02).
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'queued' OR NEW.claimed_at IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
       OR NEW.lease_expires_at IS NOT NULL THEN
      RAISE EXCEPTION 'new tasks start queued, not %', NEW.state
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- Terminal states are immutable: nothing about a finished task changes.
  IF OLD.state IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'refused', 'expired') THEN
    RAISE EXCEPTION 'task % is %, which is final; it cannot change', OLD.id, OLD.state
      USING ERRCODE = 'check_violation';
  END IF;

  -- What a task is never changes: no code path can retarget it or change its parameters after validation.
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.uuid IS DISTINCT FROM OLD.uuid
     OR NEW.task_batch_id IS DISTINCT FROM OLD.task_batch_id OR NEW.host_id IS DISTINCT FROM OLD.host_id
     OR NEW.task_type IS DISTINCT FROM OLD.task_type OR NEW.parameters IS DISTINCT FROM OLD.parameters
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.timeout_seconds IS DISTINCT FROM OLD.timeout_seconds
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'a task''s id, batch, host, type, parameters, expiry, and timeout never change'
      USING ERRCODE = 'check_violation';
  END IF;

  -- A cancel request (P3-S05) is recorded once, on a running task, and never changed or withdrawn afterwards.
  IF OLD.cancel_requested_at IS NOT NULL
     AND (NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
          OR NEW.cancel_requested_by_id IS DISTINCT FROM OLD.cancel_requested_by_id) THEN
    RAISE EXCEPTION 'a task''s cancel request never changes once recorded'
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.cancel_requested_at IS NULL AND NEW.cancel_requested_at IS NOT NULL
     AND (OLD.state <> 'running' OR NEW.cancel_requested_by_id IS NULL) THEN
    RAISE EXCEPTION 'a cancel request is recorded only on a running task, with the operator who made it'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Only the transitions in Task::TRANSITIONS.
  IF NEW.state IS DISTINCT FROM OLD.state
     AND (OLD.state::text, NEW.state::text) NOT IN (
       ('queued', 'claimed'),
       ('queued', 'cancelled'),
       ('queued', 'refused'),
       ('queued', 'expired'),
       ('claimed', 'queued'),
       ('claimed', 'running'),
       ('claimed', 'failed'),
       ('claimed', 'cancelled'),
       ('claimed', 'refused'),
       ('running', 'succeeded'),
       ('running', 'failed'),
       ('running', 'timed_out'),
       ('running', 'cancelled'),
       ('running', 'refused')
     ) THEN
    RAISE EXCEPTION 'invalid task state transition: % -> %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
