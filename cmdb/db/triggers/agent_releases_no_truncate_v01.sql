CREATE TRIGGER agent_releases_no_truncate
  BEFORE TRUNCATE ON agent_releases
  FOR EACH STATEMENT
  EXECUTE FUNCTION agent_releases_guard();
