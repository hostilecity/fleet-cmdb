CREATE OR REPLACE FUNCTION task_batches_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- A batch records what an operator asked for and what it resolved to (P3-S02); it is never changed or deleted.
  RAISE EXCEPTION 'task batches are never changed or deleted: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
