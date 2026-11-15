CREATE TRIGGER host_liveness_no_truncate
  BEFORE TRUNCATE ON host_liveness
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_truncate_guard();
