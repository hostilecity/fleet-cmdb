CREATE TRIGGER host_compliance_summaries_findings_insert
  AFTER INSERT ON vulnerability_findings
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
