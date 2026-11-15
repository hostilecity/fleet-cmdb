CREATE TRIGGER host_compliance_summaries_findings_delete
  AFTER DELETE ON vulnerability_findings
  REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
