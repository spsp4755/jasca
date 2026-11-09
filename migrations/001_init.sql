create table settings (key text primary key, value jsonb not null, updated_at timestamptz not null default now());
create table users (
  id bigserial primary key, username text not null unique, email text not null default '', name text not null default '',
  source text not null check (source in ('local','sso')), oidc_sub text unique, password_hash text,
  system_role text not null default '' check (system_role in ('','admin','security')),
  role_from_sso boolean not null default false, active boolean not null default true,
  failed_logins int not null default 0, locked_until timestamptz, last_login_at timestamptz,
  created_at timestamptz not null default now());
create table kc_groups (path text primary key, deleted boolean not null default false, seen_at timestamptz not null default now());
create table user_groups (user_id bigint not null references users on delete cascade, path text not null, primary key (user_id, path));
create table user_depts  (user_id bigint not null references users on delete cascade, path text not null, primary key (user_id, path));
create table sessions (
  id bigserial primary key, token_hash bytea not null unique, user_id bigint not null references users on delete cascade,
  user_agent text not null default '', ip text not null default '', created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(), expires_at timestamptz not null);
create table projects (
  id bigserial primary key, key text not null unique check (key ~ '^[a-z0-9][a-z0-9-]{1,39}$'), name text not null,
  description text not null default '', created_by bigint references users on delete set null,
  created_at timestamptz not null default now());
create table project_members (
  project_id bigint not null references projects on delete cascade,
  principal_kind text not null check (principal_kind in ('user','group')),
  principal text not null,  -- users.id as text, or a group/department path like '/보안팀'
  role text not null check (role in ('owner','member','viewer')),
  primary key (project_id, principal_kind, principal));
create table api_tokens (
  id bigserial primary key, project_id bigint not null references projects on delete cascade, name text not null,
  prefix text not null, token_hash bytea not null unique, scopes text[] not null, expires_at timestamptz not null,
  last_used_at timestamptz, created_by bigint references users on delete set null,
  created_at timestamptz not null default now(), revoked_at timestamptz);
create table targets (
  id bigserial primary key, project_id bigint not null references projects on delete cascade,
  kind text not null check (kind in ('image','repo','fs','sbom')), name text not null,
  created_at timestamptz not null default now(), last_scan_at timestamptz,
  recheck_excluded boolean not null default false, unique (project_id, kind, name));
create table scans (
  id bigserial primary key, project_id bigint not null references projects on delete cascade,
  target_id bigint not null references targets on delete cascade,
  source text not null check (source in ('upload','server','harbor','recheck')), format text not null,
  ref text not null default '', report_sha256 bytea,
  status text not null check (status in ('queued','running','done','failed','canceled')), error text not null default '',
  created_by_user bigint references users on delete set null, created_by_token bigint references api_tokens on delete set null,
  summary jsonb not null default '{}', policy jsonb, raw bytea, created_at timestamptz not null default now(), finished_at timestamptz);
create index scans_target_idx on scans (target_id, created_at desc);
create table jobs (
  id bigserial primary key, kind text not null check (kind in ('server_scan','harbor_fetch','recheck','ai')),
  scan_id bigint references scans on delete cascade, payload jsonb not null default '{}',
  state text not null default 'queued' check (state in ('queued','running','done','failed','canceled')),
  priority int not null default 0, attempts int not null default 0, run_after timestamptz not null default now(),
  started_at timestamptz, finished_at timestamptz, error text not null default '', created_by bigint references users on delete set null,
  created_at timestamptz not null default now());
create index jobs_pick_idx on jobs (state, priority desc, run_after, id);
create table packages (
  scan_id bigint not null references scans on delete cascade, purl text not null default '', name text not null,
  version text not null, ecosystem text not null, path text not null default '');
create index packages_scan_idx on packages (scan_id);
create index packages_name_idx on packages (ecosystem, name);
create table vulns (
  id text primary key, title text not null default '', description text not null default '',
  cvss_score numeric(3,1), cvss_vector text not null default '', refs text[] not null default '{}',
  cwe_ids text[] not null default '{}', published_at timestamptz, last_modified_at timestamptz,
  ai_guide text not null default '', ai_guide_at timestamptz);
create table findings (
  id bigserial primary key, project_id bigint not null references projects on delete cascade,
  target_id bigint not null references targets on delete cascade, fingerprint bytea not null,
  kind text not null check (kind in ('vuln','misconfig','secret','sast')), tool text not null, rule_id text not null,
  title text not null default '', severity text not null check (severity in ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
  pkg_name text not null default '', pkg_version text not null default '', fixed_version text not null default '',
  pkg_path text not null default '', location text not null default '',
  status text not null default 'open' check (status in ('open','fixed','accepted','false_positive')),
  origin text not null default 'scan' check (origin in ('scan','recheck','advisory')),
  first_seen_at timestamptz not null default now(), last_seen_at timestamptz not null default now(), fixed_at timestamptz,
  reopened_count int not null default 0, exception_id bigint, details jsonb not null default '{}',
  unique (target_id, fingerprint));
create index findings_proj_idx on findings (project_id, status, severity);
create index findings_rule_idx on findings (rule_id);
create table scan_findings (scan_id bigint not null references scans on delete cascade,
  finding_id bigint not null references findings on delete cascade, primary key (scan_id, finding_id));
create table exceptions (
  id bigserial primary key, scope text not null check (scope in ('finding','project_vuln','global_vuln')),
  project_id bigint references projects on delete cascade, finding_id bigint references findings on delete cascade,
  vuln_id text, resolution text not null check (resolution in ('accepted','false_positive')), reason text not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected','expired','revoked')),
  requested_by bigint references users on delete set null, decided_by bigint references users on delete set null,
  decided_at timestamptz, decision_note text not null default '', expires_at timestamptz not null,
  expiry_warned boolean not null default false, created_at timestamptz not null default now());
create table policies (
  project_id bigint primary key references projects on delete cascade, enabled boolean not null default true,
  min_severity text not null default 'CRITICAL', max_count int not null default 0,
  new_only boolean not null default false, fixable_only boolean not null default false);
create table advisories (
  id text primary key check (id ~ '^[A-Z][A-Z0-9-]{2,40}$'), title text not null, description text not null default '',
  severity text not null, affected jsonb not null, refs text[] not null default '{}', active boolean not null default true,
  created_by bigint references users on delete set null, created_at timestamptz not null default now(),
  updated_at timestamptz not null default now());
create table harbor_links (
  id bigserial primary key, name text not null, base_url text not null, robot_user text not null,
  robot_secret text not null, webhook_secret_hash bytea not null, created_at timestamptz not null default now());
create table harbor_mappings (link_id bigint not null references harbor_links on delete cascade, harbor_project text not null,
  repo_pattern text not null default '*', project_id bigint not null references projects on delete cascade,
  primary key (link_id, harbor_project, repo_pattern));
create table harbor_unmapped (id bigserial primary key, link_id bigint not null references harbor_links on delete cascade,
  harbor_project text not null, repository text not null, digest text not null, tag text not null default '',
  received_at timestamptz not null default now(), unique (link_id, repository, digest));
create table ai_runs (
  id bigserial primary key, kind text not null check (kind in ('vuln_guide','project_report')),
  project_id bigint references projects on delete cascade, vuln_id text, requested_by bigint references users on delete set null,
  state text not null default 'queued' check (state in ('queued','running','done','failed')), output text not null default '',
  error text not null default '', created_at timestamptz not null default now(), finished_at timestamptz);
create table notify_channels (id bigserial primary key, kind text not null check (kind in ('mattermost','email')),
  name text not null, config jsonb not null, enabled boolean not null default true, created_at timestamptz not null default now());
create table notify_subs (project_id bigint not null references projects on delete cascade,
  channel_id bigint not null references notify_channels on delete cascade, events text[] not null,
  primary key (project_id, channel_id));
create table deliveries (id bigserial primary key, channel_id bigint not null references notify_channels on delete cascade,
  event text not null, payload jsonb not null, state text not null default 'queued' check (state in ('queued','sent','failed')),
  attempts int not null default 0, next_at timestamptz not null default now(), last_error text not null default '',
  created_at timestamptz not null default now());
create table recheck_runs (id bigserial primary key, reason text not null check (reason in ('trivydb','manual')),
  state text not null default 'running' check (state in ('running','done','failed','canceled')),
  total int not null default 0, done int not null default 0, new_findings int not null default 0,
  started_at timestamptz not null default now(), finished_at timestamptz, error text not null default '');
create table recheck_items (run_id bigint not null references recheck_runs on delete cascade,
  target_id bigint not null references targets on delete cascade,
  state text not null default 'queued' check (state in ('queued','done','failed','skipped')), primary key (run_id, target_id));
create table audit_log (id bigserial primary key, at timestamptz not null default now(),
  actor_user bigint references users on delete set null, actor_token bigint references api_tokens on delete set null,
  ip text not null default '', action text not null, project_id bigint references projects on delete set null,
  target text not null default '', details jsonb not null default '{}');
create index audit_at_idx on audit_log (at desc);
