CREATE TRIGGER host_compliance_summaries_inventory_insert_delete
  AFTER INSERT OR DELETE ON host_inventories
  FOR EACH ROW
  EXECUTE FUNCTION host_compliance_summaries_changed();
