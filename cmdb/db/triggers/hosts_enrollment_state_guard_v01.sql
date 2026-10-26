CREATE TRIGGER hosts_enrollment_state_guard
  BEFORE INSERT OR UPDATE OF enrollment_state ON hosts
  FOR EACH ROW
  EXECUTE FUNCTION hosts_guard();
