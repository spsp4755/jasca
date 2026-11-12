-- Personal MCP keys: a key speaks for its user, with whatever that user may do at the moment of the call
-- (system role and project memberships are read on every request). read_only keys get no tool that changes anything.
create table mcp_keys (
  id bigserial primary key, user_id bigint not null references users on delete cascade, name text not null,
  prefix text not null, key_hash bytea not null unique, read_only boolean not null default false,
  expires_at timestamptz not null, last_used_at timestamptz, created_at timestamptz not null default now(),
  revoked_at timestamptz);
create index mcp_keys_user_idx on mcp_keys (user_id);
