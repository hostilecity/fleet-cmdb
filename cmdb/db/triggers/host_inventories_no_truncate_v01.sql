CREATE TRIGGER host_inventories_no_truncate
  BEFORE TRUNCATE ON host_inventories
  FOR EACH STATEMENT
  EXECUTE FUNCTION host_compliance_summaries_truncate_guard();
