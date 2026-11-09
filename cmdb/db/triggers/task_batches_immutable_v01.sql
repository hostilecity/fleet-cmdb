CREATE TRIGGER task_batches_immutable
  BEFORE UPDATE OR DELETE ON task_batches
  FOR EACH ROW
  EXECUTE FUNCTION task_batches_guard();
