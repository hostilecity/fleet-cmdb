CREATE TRIGGER host_compliance_summaries_findings_update
  AFTER UPDATE ON vulnerability_findings
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
