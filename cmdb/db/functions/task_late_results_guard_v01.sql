CREATE OR REPLACE FUNCTION task_late_results_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- A late result is kept as the agent sent it, beside a task that had already ended (P3-S04): never changed or deleted.
  RAISE EXCEPTION 'late task results are never changed or deleted: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
