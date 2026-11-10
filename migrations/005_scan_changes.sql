-- What each scan itself changed, kept so that its comparison reads the same later: findings it saw first ('new'),
-- opened again ('reopened') or resolved ('fixed'). findings.reopened_at lets an ingest tell what it re-opened.
alter table findings add column reopened_at timestamptz;
create table scan_changes (scan_id bigint not null references scans on delete cascade,
  finding_id bigint not null references findings on delete cascade,
  change text not null check (change in ('new','reopened','fixed')), primary key (scan_id, finding_id));
create index scan_changes_finding_idx on scan_changes (finding_id);
-- Earlier scans: an ingest is one transaction, so what it created or resolved carries the scan's finished_at.
-- What a scan re-opened, or resolved and a later scan re-opened, was not recorded and stays unknown.
insert into scan_changes select sf.scan_id, sf.finding_id, 'new' from scan_findings sf
  join scans s on s.id = sf.scan_id join findings f on f.id = sf.finding_id where f.first_seen_at = s.finished_at;
insert into scan_changes select s.id, f.id, 'fixed' from findings f
  join scans s on s.target_id = f.target_id and s.finished_at = f.fixed_at where f.status = 'fixed'
  on conflict do nothing;
