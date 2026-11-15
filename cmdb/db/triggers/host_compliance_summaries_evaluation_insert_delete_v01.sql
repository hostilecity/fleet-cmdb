CREATE TRIGGER host_compliance_summaries_evaluation_insert_delete
  AFTER INSERT OR DELETE ON host_vulnerability_evaluations
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_changed();
