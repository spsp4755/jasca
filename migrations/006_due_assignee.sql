-- Who fixes a finding and by when. open_since is when the finding last became open (first seen, re-opened by a scan,
-- back from an exception); the deadline rule (due.go) derives due_at from it and the 'sla' setting unless a person
-- set the date (due_manual). due_warned / overdue_notified: each deadline is announced once.
alter table findings add column assignee_id bigint references users on delete set null,
  add column open_since timestamptz, add column due_at timestamptz, add column due_manual boolean not null default false,
  add column due_warned boolean not null default false, add column overdue_notified boolean not null default false;
-- The clock of what is already open starts at the upgrade, so nothing is overdue the moment the service comes back.
-- due_at itself is filled by the rule when the service starts (newServer), from the default below.
update findings set open_since = now() where status = 'open';
alter table findings alter column open_since set default now();
insert into settings(key, value) values ('sla', '{"enabled": true, "days": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}}')
  on conflict do nothing;
-- the overdue counts and the notice job read open findings by deadline; deleting a user clears assignee_id by this index
create index findings_due_idx on findings (due_at) where status = 'open' and due_at is not null;
create index findings_assignee_idx on findings (assignee_id) where assignee_id is not null;
