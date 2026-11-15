CREATE OR REPLACE FUNCTION host_compliance_status_rank(enrollment_state text, liveness_status text)
RETURNS smallint
LANGUAGE sql
IMMUTABLE
AS $$
  -- The fleet list's status order (FleetList::STATUSES): online, stale, offline, awaiting first contact, pending,
  -- revoked (#193).
  SELECT (CASE
    WHEN enrollment_state = 'active' AND liveness_status = 'online' THEN 0
    WHEN enrollment_state = 'active' AND liveness_status = 'stale' THEN 1
    WHEN enrollment_state = 'active' AND liveness_status = 'offline' THEN 2
    WHEN enrollment_state = 'active' THEN 3
    WHEN enrollment_state = 'pending' THEN 4
    ELSE 5
  END)::smallint;
$$;
