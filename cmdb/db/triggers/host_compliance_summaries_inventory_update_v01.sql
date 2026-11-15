CREATE TRIGGER host_compliance_summaries_inventory_update
  AFTER UPDATE ON host_inventories
  FOR EACH ROW
  WHEN ((OLD.stable #>> '{os,pretty_name}') IS DISTINCT FROM (NEW.stable #>> '{os,pretty_name}') OR OLD.host_id <> NEW.host_id)
  EXECUTE FUNCTION host_compliance_summaries_changed();
