CREATE TRIGGER finding_decisions_guard
  BEFORE INSERT OR UPDATE OR DELETE ON finding_decisions
  FOR EACH ROW
  EXECUTE FUNCTION finding_decisions_guard();
