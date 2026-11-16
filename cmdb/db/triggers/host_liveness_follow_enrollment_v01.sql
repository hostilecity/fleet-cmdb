CREATE TRIGGER host_liveness_follow_enrollment
  AFTER UPDATE OF enrollment_state ON hosts
  FOR EACH ROW
  WHEN (OLD.enrollment_state IS DISTINCT FROM NEW.enrollment_state)
  EXECUTE FUNCTION host_liveness_follow_enrollment();
