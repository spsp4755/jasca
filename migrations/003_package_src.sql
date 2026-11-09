-- Debian/Ubuntu advisories are keyed by the source package; the recheck needs it to match OS packages again.
alter table packages add column src_name text not null default '', add column src_version text not null default '';
