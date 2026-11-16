CREATE TRIGGER host_compliance_summaries_liveness_insert_delete
  AFTER INSERT OR DELETE ON host_liveness
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_changed();
