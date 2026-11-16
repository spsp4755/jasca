-- The Harbor integration is gone: its connections (with their robot secrets), mappings and waiting images are dropped.
-- Scans, targets and findings Harbor once delivered stay as history, so 'harbor' remains a valid scans.source and
-- 'harbor_fetch' a valid jobs.kind. Those targets keep recheck_excluded (Harbor reports list vulnerable packages
-- only) until a report with a package list is uploaded to them.
drop table harbor_unmapped, harbor_mappings, harbor_links;
update jobs set state = 'canceled', finished_at = now(), error = 'the Harbor integration was removed'
  where kind = 'harbor_fetch' and state in ('queued', 'running');
