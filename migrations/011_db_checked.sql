-- The build time of the vulnerability DB a target's package inventory was last checked against on this server
-- (server scan, SBOM evaluation, re-evaluation). Null while the newest inventory came from a report scanned
-- elsewhere (CI) and no re-evaluation has looked at it yet.
alter table targets add column db_checked_at timestamptz;
