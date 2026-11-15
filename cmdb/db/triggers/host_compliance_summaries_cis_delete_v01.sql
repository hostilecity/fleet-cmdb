CREATE TRIGGER host_compliance_summaries_cis_delete
  AFTER DELETE ON cis_results
  REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
