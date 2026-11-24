CREATE TRIGGER host_compliance_summaries_decisions
  AFTER INSERT OR UPDATE OF ended_at ON finding_decisions
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_changed();
