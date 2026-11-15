CREATE CONSTRAINT TRIGGER host_compliance_summaries_flush
  AFTER INSERT ON host_compliance_flushes
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_flush();
