CREATE TRIGGER audit_entries_no_update_or_delete
  BEFORE UPDATE OR DELETE ON audit_entries
  FOR EACH ROW
  EXECUTE FUNCTION audit_entries_append_only();
