CREATE TRIGGER host_compliance_summaries_evaluation_update
  AFTER UPDATE ON host_vulnerability_evaluations
  FOR EACH ROW
  WHEN (OLD.state IS DISTINCT FROM NEW.state OR OLD.host_id <> NEW.host_id)
  EXECUTE FUNCTION host_compliance_summaries_changed();
