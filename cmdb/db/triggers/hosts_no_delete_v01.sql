CREATE TRIGGER hosts_no_delete
  BEFORE DELETE ON hosts
  FOR EACH ROW
  EXECUTE FUNCTION hosts_guard();
