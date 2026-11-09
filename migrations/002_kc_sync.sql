-- The Keycloak sync re-enables only users it disabled itself; an admin's deactivation stays.
alter table users add column disabled_by_sync boolean not null default false;
