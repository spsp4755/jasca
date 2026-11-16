-- Exploitation data carried in as files (관리 → Trivy DB → 악용 정보): CISA KEV and EPSS, one row per CVE.
-- A row exists while either source names the CVE. The data dates and counts are in settings['intel'].
create table vuln_intel (
  cve text primary key,
  kev boolean not null default false, kev_added date, kev_ransomware boolean not null default false,
  kev_action text not null default '',
  epss numeric(6,5), epss_pct numeric(6,5));
