CREATE TRIGGER host_compliance_summaries_decisions
  AFTER INSERT OR UPDATE OF ended_at ON finding_decisions
  FOR EACH ROW
  WHEN (NEW.kind = 'accepted')
  EXECUTE FUNCTION host_compliance_summaries_changed();
