CREATE TRIGGER host_compliance_summaries_rule_version
  AFTER UPDATE OF current_version_id ON cis_rules
  FOR EACH ROW
  WHEN (OLD.current_version_id IS DISTINCT FROM NEW.current_version_id)
  EXECUTE FUNCTION host_compliance_summaries_changed();
