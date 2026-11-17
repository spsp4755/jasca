-- Found by the load test (2,000 targets, docs/maintaining.md): two lookups that read far more than they return.
-- The newest scan of a target that has packages (its inventory, latestInventorySQL) is looked up for every target by
-- the package search, the remediation plan, the re-evaluation and the retention pass. Without the id in an index
-- each lookup probed the packages of every scan the target ever had.
create index scans_target_id_idx on scans (target_id, id desc);
-- The package search counts the open findings of the packages it lists; by target alone that read every finding of
-- up to 1,000 targets.
create index findings_pkg_idx on findings (pkg_name) where status = 'open';
