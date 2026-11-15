CREATE OR REPLACE FUNCTION host_compliance_summaries_truncate_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- TRUNCATE fires no row or statement triggers, so it would leave the compliance summaries wrong (#193).
  RAISE EXCEPTION '% is not truncated: the compliance summaries are built from it (delete the rows instead, or run bin/rails compliance_summaries:rebuild afterwards with this trigger disabled)', TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
