CREATE TRIGGER host_compliance_summaries_hosts_insert
  AFTER INSERT ON hosts
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_changed();
