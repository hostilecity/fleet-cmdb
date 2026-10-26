CREATE TRIGGER audit_entries_no_truncate
  BEFORE TRUNCATE ON audit_entries
  FOR EACH STATEMENT
  EXECUTE FUNCTION audit_entries_append_only();
