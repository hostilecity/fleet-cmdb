CREATE TRIGGER task_batches_no_truncate
  BEFORE TRUNCATE ON task_batches
  FOR EACH STATEMENT
  EXECUTE FUNCTION task_batches_guard();
