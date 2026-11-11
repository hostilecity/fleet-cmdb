CREATE TRIGGER task_late_results_immutable
  BEFORE UPDATE OR DELETE ON task_late_results
  FOR EACH ROW
  EXECUTE FUNCTION task_late_results_guard();
