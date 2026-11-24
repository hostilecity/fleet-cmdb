CREATE TRIGGER host_compliance_summaries_applicability_insert_delete
  AFTER INSERT OR DELETE ON host_applicability
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_changed();
