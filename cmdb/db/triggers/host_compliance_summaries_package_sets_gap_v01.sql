CREATE TRIGGER host_compliance_summaries_package_sets_gap
  AFTER UPDATE OF received_at ON host_package_sets
  FOR EACH ROW
  WHEN (NEW.received_at - OLD.received_at > interval '1 day')
  EXECUTE FUNCTION host_compliance_summaries_changed();
