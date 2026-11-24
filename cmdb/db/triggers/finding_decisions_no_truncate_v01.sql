CREATE TRIGGER finding_decisions_no_truncate
  BEFORE TRUNCATE ON finding_decisions
  FOR EACH STATEMENT
  EXECUTE FUNCTION finding_decisions_guard();
