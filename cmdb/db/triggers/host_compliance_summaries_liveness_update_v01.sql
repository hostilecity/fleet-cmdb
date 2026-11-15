CREATE TRIGGER host_compliance_summaries_liveness_update
  AFTER UPDATE OF liveness_status ON host_liveness
  FOR EACH ROW
  WHEN (OLD.liveness_status IS DISTINCT FROM NEW.liveness_status)
  EXECUTE FUNCTION host_compliance_summaries_changed();
