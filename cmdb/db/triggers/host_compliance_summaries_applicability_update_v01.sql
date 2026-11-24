CREATE TRIGGER host_compliance_summaries_applicability_update
  AFTER UPDATE OF reboot_required ON host_applicability
  FOR EACH ROW
  WHEN (OLD.reboot_required IS DISTINCT FROM NEW.reboot_required)
  EXECUTE FUNCTION host_compliance_summaries_changed();
