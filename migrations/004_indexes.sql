-- Hot predicates without an index: exception expiry (findings by exception), the scan list, a project's audit
-- log, and the finding-delete cascade into scan_findings.
create index findings_exception_idx on findings (exception_id) where exception_id is not null;
create index scans_project_idx on scans (project_id, id desc);
create index audit_project_idx on audit_log (project_id, id desc) where project_id is not null;
create index scan_findings_finding_idx on scan_findings (finding_id);
