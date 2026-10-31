CREATE OR REPLACE FUNCTION agent_releases_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'agent releases are not truncated'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- A release is never deleted while a host in the fleet runs it (P1-RELEASES).
  IF TG_OP = 'DELETE' THEN
    IF EXISTS (SELECT 1 FROM hosts WHERE hosts.agent_version = OLD.version AND hosts.enrollment_state <> 'retired') THEN
      RAISE EXCEPTION 'agent release % is in use by a host and cannot be deleted', OLD.version
        USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN OLD;
  END IF;

  -- A published release is never replaced (docs/releases.md): what was verified is what is served.
  IF (NEW.version, NEW.target, NEW.sha256, NEW.size, NEW.manifest, NEW.signature)
     IS DISTINCT FROM (OLD.version, OLD.target, OLD.sha256, OLD.size, OLD.manifest, OLD.signature) THEN
    RAISE EXCEPTION 'agent releases are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;
