CREATE TRIGGER agent_releases_immutable
  BEFORE UPDATE OR DELETE ON agent_releases
  FOR EACH ROW
  EXECUTE FUNCTION agent_releases_guard();
