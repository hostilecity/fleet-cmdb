CREATE TRIGGER cis_results_no_truncate
  BEFORE TRUNCATE ON cis_results
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_truncate_guard();
