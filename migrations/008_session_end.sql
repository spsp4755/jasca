-- A session ended by a newer login stays until it expires, so that browser can be told why it was signed out
-- (ended_reason 'replaced'). notice is what a new session tells its user once: how many other sessions the login
-- ended and how many are still open.
alter table sessions add column ended_reason text not null default '', add column notice jsonb;
