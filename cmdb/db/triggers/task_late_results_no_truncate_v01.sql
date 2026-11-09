CREATE TRIGGER task_late_results_no_truncate
  BEFORE TRUNCATE ON task_late_results
  FOR EACH STATEMENT
  EXECUTE FUNCTION task_late_results_guard();
