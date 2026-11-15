CREATE OR REPLACE FUNCTION host_compliance_summaries_sync(host_ids bigint[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Copies the host's own fields the fleet list sorts and filters by, and its operating system name, into its
  -- summary row (#193), creating the row for a new host, so every sort has one index with the name tie-break.
  IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
    RETURN;
  END IF;

  -- Lock first, then read the hosts in a later statement (a new snapshot under READ COMMITTED), as the refresh does.
  PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (host_ids) ORDER BY s.host_id FOR UPDATE;

  INSERT INTO host_compliance_summaries AS s (host_id, enrollment_state, status_rank, name_key, hostname, tags_key, agent_key, os_name)
  SELECT h.id, h.enrollment_state,
         -- FleetList::STATUSES order: online, stale, offline, awaiting first contact, pending, revoked.
         CASE
           WHEN h.enrollment_state = 'active' AND h.liveness_status = 'online' THEN 0
           WHEN h.enrollment_state = 'active' AND h.liveness_status = 'stale' THEN 1
           WHEN h.enrollment_state = 'active' AND h.liveness_status = 'offline' THEN 2
           WHEN h.enrollment_state = 'active' THEN 3
           WHEN h.enrollment_state = 'pending' THEN 4
           ELSE 5
         END,
         lower(h.name), h.hostname,
         -- By the tag list as displayed (in entry order); no tags is NULL, so it sorts last.
         NULLIF(array_to_string(h.tags, ','), ''),
         -- Numeric by release (0.10.0 after 0.9.0); pre-release and build suffixes are ignored. numeric, not int:
         -- SemVer components are unbounded (review of #53). Anything but dotted numbers sorts last, never fails.
         CASE WHEN h.agent_version ~ '^[0-9]+(\.[0-9]+)*([-+].*)?$'
              THEN string_to_array(regexp_replace(h.agent_version, '[-+].*$', ''), '.')::numeric[] END,
         i.stable #>> '{os,pretty_name}'
    FROM hosts h
    LEFT JOIN host_inventories i ON i.host_id = h.id
   WHERE h.id = ANY (host_ids)
  ON CONFLICT (host_id) DO UPDATE
     SET enrollment_state = EXCLUDED.enrollment_state, status_rank = EXCLUDED.status_rank, name_key = EXCLUDED.name_key,
         hostname = EXCLUDED.hostname, tags_key = EXCLUDED.tags_key, agent_key = EXCLUDED.agent_key, os_name = EXCLUDED.os_name
   WHERE (s.enrollment_state, s.status_rank, s.name_key, s.hostname, s.tags_key, s.agent_key, s.os_name)
         IS DISTINCT FROM
         (EXCLUDED.enrollment_state, EXCLUDED.status_rank, EXCLUDED.name_key, EXCLUDED.hostname, EXCLUDED.tags_key,
          EXCLUDED.agent_key, EXCLUDED.os_name);
END;
$$;
