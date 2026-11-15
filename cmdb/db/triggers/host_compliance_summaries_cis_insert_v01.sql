CREATE TRIGGER host_compliance_summaries_cis_insert
  AFTER INSERT ON cis_results
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
