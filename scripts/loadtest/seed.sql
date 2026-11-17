-- Load-test data for an empty, migrated JASCA database (see docs/maintaining.md "부하 시험").
-- Run by `go run ./scripts/loadtest seed`; lt.targets / lt.projects / lt.users are set by it. Every statement is
-- set-based so that 2,000 targets take minutes. The shapes follow what the server writes (ingest.go): fingerprints,
-- scan links and changes, the retention rule, exceptions on their findings. Deadlines (due_at) are left to the
-- server, which applies its own rule when it starts.
-- A "step" line starts a part the tool times; a "chunked" step runs once per 100 targets with :lo and :hi.

-- step: helpers
create function pg_temp.r(k bigint, m int) returns int language sql immutable
  as $$ select ((hashint8(k)::bigint & 2147483647) % m)::int $$;
do $$ begin
  if (select count(*) from projects) > 0 then raise exception 'the database already has projects: seed an empty one'; end if;
end $$;

-- step: users and projects
insert into kc_groups(path) select '/jasca-users' union all select '/그룹' || g from generate_series(1, 40) g;
insert into users(username, email, name, source, oidc_sub, system_role, last_login_at, created_at)
select 'lt.user' || lpad(i::text, 5, '0'), 'lt.user' || i || '@example.internal',
  (array['김','이','박','최','정','강','조','윤','장','임'])[1 + pg_temp.r(i, 10)] ||
  (array['민준','서연','도윤','지우','하준','서현','예준','지민','시우','수아','주원','하은'])[1 + pg_temp.r(i * 7, 12)],
  'sso', 'lt-sub-' || i, case when i <= 2 then 'admin' when i <= 8 then 'security' else '' end,
  now() - make_interval(hours => pg_temp.r(i * 3, 2000)), now() - interval '400 days'
from generate_series(1, current_setting('lt.users')::int) i;
create temp table lt_user as select (row_number() over (order by id))::int n, id from users where username like 'lt.user%';
create unique index on lt_user (n);
insert into user_groups select id, '/jasca-users' from lt_user;
insert into user_groups select id, '/그룹' || (1 + pg_temp.r(n * 5, 40)) from lt_user;
insert into user_depts select id, '/본부' || (1 + (n % 25) % 5) || '/팀' || (1 + n % 25) from lt_user;

insert into projects(key, name, description, created_by, created_at)
select 'lt-' || lpad(i::text, 4, '0'),
  (array['결제','주문','회원','정산','배송','검색','추천','알림','인증','통계'])[1 + i % 10] || ' ' ||
  (array['API','웹','배치','게이트웨이','어드민','모바일 BFF'])[1 + pg_temp.r(i, 6)] || ' ' || i, '부하 시험용 프로젝트 ' || i,
  (select id from lt_user where n = 9 + pg_temp.r(i * 11, current_setting('lt.users')::int - 8)), now() - interval '400 days'
from generate_series(1, current_setting('lt.projects')::int) i;
create temp table lt_proj as select (row_number() over (order by id))::int n, id, created_by from projects;
create unique index on lt_proj (n);
-- the owner, 4 to 10 people, and for most projects a department or a group
insert into project_members select id, 'user', created_by::text, 'owner' from lt_proj;
insert into project_members
select p.id, 'user', u.id::text, case when k % 4 = 0 then 'viewer' else 'member' end
from lt_proj p cross join generate_series(1, 10) k
  join lt_user u on u.n = 9 + pg_temp.r(p.n * 1000 + k, current_setting('lt.users')::int - 8)
where k <= 4 + pg_temp.r(p.n, 7) on conflict do nothing;
insert into project_members
select id, 'group', '/본부' || (1 + (n % 25) % 5) || '/팀' || (1 + n % 25), 'member' from lt_proj where n % 5 < 3;
insert into project_members select id, 'group', '/그룹' || (1 + n % 40), 'viewer' from lt_proj where n % 5 = 3;
create temp table lt_pm as select project_id, (row_number() over (partition by project_id order by principal))::int - 1 k,
  principal::bigint user_id, (count(*) over (partition by project_id))::int cnt from project_members where principal_kind = 'user';
create index on lt_pm (project_id, k);
insert into api_tokens(project_id, name, prefix, token_hash, scopes, expires_at, last_used_at, created_by)
select id, 'ci', 'jsc_lt_' || n, sha256(convert_to('jsc_lt_' || n, 'UTF8')), '{upload,read}', now() + interval '200 days',
  now() - interval '1 hour', created_by from lt_proj;
create temp table lt_tok as select project_id, id from api_tokens;

-- step: package pool
-- Ids below 1000 are real packages at old versions (Trivy knows their vulnerabilities, none of which is seeded: the
-- first re-evaluation finds them). The rest are made up, in real ecosystems so that versions compare.
create temp table lt_pkg (id int primary key, eco text, name text, ver text, old_ver text, purl text, path text,
  src_name text default '', src_ver text default '', maj int, mnr int, pat int, pre text default '', suf text default '');
insert into lt_pkg(id, eco, name, ver, purl, path, src_name, src_ver)
select row_number() over (), eco, name, ver, purl || '@' || ver || q, path, src, case when src = '' then '' else ver end
from (values
  ('npm','lodash','4.17.15','pkg:npm/lodash','','package-lock.json',''), ('npm','minimist','1.2.0','pkg:npm/minimist','','package-lock.json',''),
  ('npm','axios','0.21.0','pkg:npm/axios','','package-lock.json',''), ('npm','express','4.16.0','pkg:npm/express','','package-lock.json',''),
  ('npm','moment','2.24.0','pkg:npm/moment','','package-lock.json',''), ('npm','jquery','3.4.1','pkg:npm/jquery','','package-lock.json',''),
  ('npm','handlebars','4.5.3','pkg:npm/handlebars','','package-lock.json',''), ('npm','node-fetch','2.6.0','pkg:npm/node-fetch','','package-lock.json',''),
  ('npm','ws','7.4.5','pkg:npm/ws','','package-lock.json',''), ('npm','underscore','1.12.0','pkg:npm/underscore','','package-lock.json',''),
  ('npm','qs','6.5.2','pkg:npm/qs','','package-lock.json',''), ('npm','tar','4.4.13','pkg:npm/tar','','package-lock.json',''),
  ('npm','y18n','4.0.0','pkg:npm/y18n','','package-lock.json',''), ('npm','ini','1.3.5','pkg:npm/ini','','package-lock.json',''),
  ('npm','json5','2.1.3','pkg:npm/json5','','package-lock.json',''), ('npm','glob-parent','5.1.1','pkg:npm/glob-parent','','package-lock.json',''),
  ('npm','path-parse','1.0.6','pkg:npm/path-parse','','package-lock.json',''), ('npm','ansi-regex','5.0.0','pkg:npm/ansi-regex','','package-lock.json',''),
  ('npm','semver','5.7.1','pkg:npm/semver','','package-lock.json',''), ('npm','follow-redirects','1.13.0','pkg:npm/follow-redirects','','package-lock.json',''),
  ('npm','jsonwebtoken','8.5.1','pkg:npm/jsonwebtoken','','package-lock.json',''), ('npm','serialize-javascript','3.0.0','pkg:npm/serialize-javascript','','package-lock.json',''),
  ('npm','async','2.6.3','pkg:npm/async','','package-lock.json',''), ('npm','debug','2.6.8','pkg:npm/debug','','package-lock.json',''),
  ('pip','django','2.2.0','pkg:pypi/django','','requirements.txt',''), ('pip','requests','2.19.0','pkg:pypi/requests','','requirements.txt',''),
  ('pip','urllib3','1.24.1','pkg:pypi/urllib3','','requirements.txt',''), ('pip','pyyaml','5.1','pkg:pypi/pyyaml','','requirements.txt',''),
  ('pip','flask','0.12.2','pkg:pypi/flask','','requirements.txt',''), ('pip','jinja2','2.10','pkg:pypi/jinja2','','requirements.txt',''),
  ('pip','pillow','6.2.0','pkg:pypi/pillow','','requirements.txt',''), ('pip','cryptography','2.8','pkg:pypi/cryptography','','requirements.txt',''),
  ('pip','numpy','1.16.0','pkg:pypi/numpy','','requirements.txt',''), ('pip','sqlalchemy','1.3.0','pkg:pypi/sqlalchemy','','requirements.txt',''),
  ('pip','werkzeug','0.15.3','pkg:pypi/werkzeug','','requirements.txt',''), ('pip','certifi','2019.3.9','pkg:pypi/certifi','','requirements.txt',''),
  ('maven','org.apache.logging.log4j:log4j-core','2.14.1','pkg:maven/org.apache.logging.log4j/log4j-core','','pom.xml',''),
  ('maven','com.fasterxml.jackson.core:jackson-databind','2.9.8','pkg:maven/com.fasterxml.jackson.core/jackson-databind','','pom.xml',''),
  ('maven','org.springframework:spring-core','5.2.0.RELEASE','pkg:maven/org.springframework/spring-core','','pom.xml',''),
  ('maven','org.springframework:spring-web','5.2.0.RELEASE','pkg:maven/org.springframework/spring-web','','pom.xml',''),
  ('maven','org.yaml:snakeyaml','1.26','pkg:maven/org.yaml/snakeyaml','','pom.xml',''),
  ('maven','commons-collections:commons-collections','3.2.1','pkg:maven/commons-collections/commons-collections','','pom.xml',''),
  ('maven','org.apache.commons:commons-text','1.9','pkg:maven/org.apache.commons/commons-text','','pom.xml',''),
  ('maven','com.google.guava:guava','28.0-jre','pkg:maven/com.google.guava/guava','','pom.xml',''),
  ('maven','org.apache.tomcat.embed:tomcat-embed-core','9.0.30','pkg:maven/org.apache.tomcat.embed/tomcat-embed-core','','pom.xml',''),
  ('maven','ch.qos.logback:logback-classic','1.2.3','pkg:maven/ch.qos.logback/logback-classic','','pom.xml',''),
  ('maven','com.h2database:h2','1.4.199','pkg:maven/com.h2database/h2','','pom.xml',''),
  ('maven','org.postgresql:postgresql','42.2.5','pkg:maven/org.postgresql/postgresql','','pom.xml',''),
  ('gomod','golang.org/x/crypto','v0.0.0-20200622213623-75b288015ac9','pkg:golang/golang.org/x/crypto','','go.mod',''),
  ('gomod','golang.org/x/net','v0.0.0-20200822124328-c89045814202','pkg:golang/golang.org/x/net','','go.mod',''),
  ('gomod','golang.org/x/text','v0.3.2','pkg:golang/golang.org/x/text','','go.mod',''),
  ('gomod','github.com/gin-gonic/gin','v1.6.3','pkg:golang/github.com/gin-gonic/gin','','go.mod',''),
  ('gomod','github.com/dgrijalva/jwt-go','v3.2.0+incompatible','pkg:golang/github.com/dgrijalva/jwt-go','','go.mod',''),
  ('gomod','gopkg.in/yaml.v2','v2.2.2','pkg:golang/gopkg.in/yaml.v2','','go.mod',''),
  ('gomod','github.com/gogo/protobuf','v1.3.1','pkg:golang/github.com/gogo/protobuf','','go.mod',''),
  ('alpine','openssl','1.1.1g-r0','pkg:apk/alpine/openssl','?arch=x86_64&distro=3.12.0','','openssl'),
  ('alpine','libcrypto1.1','1.1.1g-r0','pkg:apk/alpine/libcrypto1.1','?arch=x86_64&distro=3.12.0','','openssl'),
  ('alpine','libssl1.1','1.1.1g-r0','pkg:apk/alpine/libssl1.1','?arch=x86_64&distro=3.12.0','','openssl'),
  ('alpine','busybox','1.31.1-r16','pkg:apk/alpine/busybox','?arch=x86_64&distro=3.12.0','','busybox'),
  ('alpine','musl','1.1.24-r8','pkg:apk/alpine/musl','?arch=x86_64&distro=3.12.0','','musl'),
  ('alpine','zlib','1.2.11-r3','pkg:apk/alpine/zlib','?arch=x86_64&distro=3.12.0','','zlib'),
  ('alpine','apk-tools','2.10.5-r1','pkg:apk/alpine/apk-tools','?arch=x86_64&distro=3.12.0','','apk-tools'),
  ('debian','openssl','3.0.11-1~deb12u1','pkg:deb/debian/openssl','?arch=amd64&distro=debian-12.1','','openssl'),
  ('debian','libssl3','3.0.11-1~deb12u1','pkg:deb/debian/libssl3','?arch=amd64&distro=debian-12.1','','openssl'),
  ('debian','libc6','2.36-9+deb12u1','pkg:deb/debian/libc6','?arch=amd64&distro=debian-12.1','','glibc'),
  ('debian','curl','7.88.1-10+deb12u1','pkg:deb/debian/curl','?arch=amd64&distro=debian-12.1','','curl'),
  ('debian','libcurl4','7.88.1-10+deb12u1','pkg:deb/debian/libcurl4','?arch=amd64&distro=debian-12.1','','curl'),
  ('debian','libexpat1','2.5.0-1','pkg:deb/debian/libexpat1','?arch=amd64&distro=debian-12.1','','expat'),
  ('debian','libgnutls30','3.7.9-2','pkg:deb/debian/libgnutls30','?arch=amd64&distro=debian-12.1','','gnutls28')
) v(eco, name, ver, purl, q, path, src);
insert into lt_pkg(id, eco, maj, mnr, pat, name)
select i, (case when x < 45 then 'npm' when x < 60 then 'maven' when x < 72 then 'pip' when x < 82 then 'gomod' when x < 94 then 'debian' else 'alpine' end),
  1 + pg_temp.r(i * 3, 9), pg_temp.r(i * 5, 30), pg_temp.r(i * 7, 40), ''
from generate_series(1001, 31000) i cross join lateral (select pg_temp.r(i, 100) x) x;
update lt_pkg set
  name = case eco when 'npm' then (case when id % 5 = 0 then '@loadtest/' else '' end) || 'lt-module-' || id
    when 'maven' then 'io.loadtest.group' || (id % 300) || ':lt-artifact-' || id when 'pip' then 'lt-pylib-' || id
    when 'gomod' then 'example.internal/lt/mod' || id else 'liblt' || id end,
  pre = case when eco = 'gomod' then 'v' else '' end,
  suf = case eco when 'debian' then '-' || (1 + id % 5) || '+deb12u' || (1 + id % 4) when 'alpine' then '-r' || (id % 9) else '' end,
  path = case eco when 'npm' then 'package-lock.json' when 'maven' then 'pom.xml' when 'pip' then 'requirements.txt'
    when 'gomod' then 'go.mod' else '' end
where id > 1000;
update lt_pkg set ver = pre || maj || '.' || mnr || '.' || pat || suf, old_ver = pre || maj || '.' || greatest(mnr - 1, 0) || '.' || (pat + 3) || suf,
  src_name = case when eco in ('debian', 'alpine') then name else '' end where id > 1000;
update lt_pkg set src_ver = case when eco in ('debian', 'alpine') then ver else '' end,
  purl = case eco when 'npm' then 'pkg:npm/' || replace(name, '@', '%40') || '@' || ver
    when 'maven' then 'pkg:maven/' || replace(name, ':', '/') || '@' || ver when 'pip' then 'pkg:pypi/' || name || '@' || ver
    when 'gomod' then 'pkg:golang/' || name || '@' || ver
    when 'debian' then 'pkg:deb/debian/' || name || '@' || ver || '?arch=amd64&distro=debian-12.1'
    else 'pkg:apk/alpine/' || name || '@' || ver || '?arch=x86_64&distro=3.12.0' end
where id > 1000;

-- 40 stacks (a base image and one language); a target is one stack minus a few packages. Sizes: 60 to 2,000 packages.
create temp table lt_stack as select g tpl, (array[60,250,250,700,700,250,250,700,2000,60])[1 + g % 10] sz,
  (array['npm','maven','pip','gomod'])[1 + g % 4] lang, case when g % 3 = 0 then 'alpine' else 'debian' end os
from generate_series(1, 40) g;
create temp table lt_tpl as
select tpl, id pkg from (
  select s.tpl, p.id, p.eco = s.os is_os, least(s.sz * 35 / 100, case s.os when 'alpine' then 40 else 180 end) n_os, s.sz,
    row_number() over (partition by s.tpl, p.eco order by pg_temp.r(s.tpl * 7919 + p.id, 1000000) * (p.id - 1000)::float8 ^ 0.7) rn
  from lt_stack s join lt_pkg p on p.id > 1000 and p.eco in (s.lang, s.os)) x
where rn <= case when is_os then n_os else sz - n_os end
union all select s.tpl, p.id from lt_stack s join lt_pkg p on p.id < 1000 and p.eco in (s.lang, s.os);
create index on lt_tpl (tpl);

-- 22% of the made-up packages are vulnerable, with 1 to 9 CVEs each; 45% of those are of an older version and fixed by now
create temp table lt_vuln as
select distinct on (p.id, cve) p.id pkg, cve, pg_temp.r(p.id * 19 + k, 100) < 45 old,
  (case when x < 4 then 'CRITICAL' when x < 26 then 'HIGH' when x < 74 then 'MEDIUM' when x < 98 then 'LOW' else 'UNKNOWN' end) sev,
  case when pg_temp.r(p.id * 23 + k, 100) < 75 then p.pre || p.maj || '.' || p.mnr || '.' || (p.pat + 1 + pg_temp.r(p.id + k, 5)) || p.suf else '' end fixed
from lt_pkg p cross join generate_series(1, 9) k
  cross join lateral (select 'CVE-' || (2017 + pg_temp.r(p.id * 31 + k, 9)) || '-' || (1000 + pg_temp.r(p.id * 37 + k * 101, 45000)) cve,
    pg_temp.r(p.id * 41 + k, 100) x) c
where p.id > 1000 and pg_temp.r(p.id * 13, 100) < 22 and k <= 1 + (pg_temp.r(p.id * 17, 1000) / 1000.0) ^ 2 * 8;
create index on lt_vuln (pkg);
insert into vulns(id, title, description, cvss_score, cvss_vector, refs, cwe_ids, published_at, last_modified_at)
select cve, (array['Prototype Pollution','Denial of Service via crafted input','Improper Input Validation','Path Traversal',
    'Regular Expression Denial of Service','Use After Free','Out-of-bounds Read','Server-Side Request Forgery','Deserialization of Untrusted Data',
    'Improper Certificate Validation','Integer Overflow','Information Exposure'])[1 + h % 12] || ' (' || cve || ')',
  -- 60 to 150 words in no order: a description that compresses like text, not like a repeated sentence
  (select string_agg((array['flaw','attacker','remote','crafted','input','parser','buffer','memory','service','request','header','allows',
    'arbitrary','code','execution','denial','bypass','validation','improper','access','privilege','overflow','component','before','version',
    'affected','vulnerable','function','argument','untrusted','data','leads','information','disclosure','certificate','handling','when',
    'processing','malicious','payload'])[1 + pg_temp.r(h * 131 + w, 40)], ' ') from generate_series(1, 60 + h % 90) w),
  (30 + h % 70) / 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  array['https://nvd.nist.gov/vuln/detail/' || cve, 'https://github.com/advisories/GHSA-' || md5(cve), 'https://www.cve.org/CVERecord?id=' || cve],
  array['CWE-' || (20 + h % 900)], now() - make_interval(days => 30 + h % 2500), now() - make_interval(days => h % 30)
from (select distinct cve, pg_temp.r(hashtext(cve), 100000) h from lt_vuln) c;

-- step: raw reports (go)

-- step: targets and scans
-- A few projects are large: the first one has about 7% of all targets.
insert into targets(project_id, kind, name, created_at)
select p.id, kind, case kind when 'image' then 'registry.example.internal/team' || (p.n % 25) || '/svc-' || t
  when 'repo' then 'git.example.internal/team' || (p.n % 25) || '/svc-' || t else 'svc-' || t || '-src' end, now() - interval '400 days'
from generate_series(1, current_setting('lt.targets')::int) t
  cross join lateral (select (array['image','image','image','fs','repo'])[1 + pg_temp.r(t * 3, 5)] kind,
    1 + floor(current_setting('lt.projects')::int * (pg_temp.r(t * 29, 1000000) / 1000000.0) ^ 2)::int pn) x
  join lt_proj p on p.n = x.pn;
-- nscans / cadence: 15% are scanned now and then, 75% weekly, 10% daily (those keep 90 days of scans, not 20)
create temp table lt_tgt as
select (row_number() over (order by t.id))::int t, t.id, t.project_id, t.kind, 1 + pg_temp.r(t.id * 13, 40) tpl,
  case when c < 15 then 3 + pg_temp.r(t.id * 7, 15) when c < 90 then 20 + pg_temp.r(t.id * 7, 25) else 100 + pg_temp.r(t.id * 7, 100) end nscans,
  case when c < 15 then 240 when c < 90 then 168 else 24 end cadence_h
from targets t cross join lateral (select pg_temp.r(t.id * 17, 100) c) c;
create unique index on lt_tgt (id);
create index on lt_tgt (t);
create temp table lt_inv as
select t.id target_id, tp.pkg from lt_tgt t join lt_tpl tp on tp.tpl = t.tpl join lt_pkg p on p.id = tp.pkg
where (t.kind = 'image' or p.eco not in ('debian', 'alpine')) and (p.id < 1000 or pg_temp.r(t.id * 100003 + p.id, 100) < 92);
create index on lt_inv (target_id);
-- idx 0 is the newest scan; ids follow time, as they do in a live system
create temp table lt_scan as
select (row_number() over (order by ts, target_id))::bigint id, * from (
  select t.id target_id, t.project_id, t.tpl, t.kind, t.t, t.nscans, i idx,
    now() - make_interval(hours => i * t.cadence_h + pg_temp.r(t.id * 1000 + i, t.cadence_h / 2 + 1)) - interval '10 minutes' ts
  from lt_tgt t cross join lateral generate_series(0, t.nscans - 1) i) s;
alter table lt_scan add column kept boolean;
update lt_scan set kept = idx < 20 or ts > now() - interval '90 days';  -- the default retention
create unique index on lt_scan (target_id, idx);
create index on lt_scan (t);

-- step: findings
-- One row per finding with its life: first seen in scan s_idx, gone since scan j_idx (-1: still there).
create temp table lt_f0 as
select t.id target_id, t.project_id, t.nscans, 'vuln' kind, v.cve rule_id, v.sev, p.name pkg_name,
  case when v.old then p.old_ver else p.ver end pkg_version, v.fixed, p.path pkg_path, '' location, '{}'::jsonb details, v.old,
  'vuln|' || v.cve || '|' || p.name || '|' || p.path fp_src
from lt_tgt t join lt_inv i on i.target_id = t.id join lt_pkg p on p.id = i.pkg join lt_vuln v on v.pkg = p.id
union all
-- misconfigurations of a third of the source trees, a secret in a few
select t.id, t.project_id, t.nscans, 'misconfig', 'DS-' || lpad((1 + pg_temp.r(t.id * 53 + k, 40))::text, 4, '0'),
  (array['HIGH','MEDIUM','MEDIUM','LOW'])[1 + pg_temp.r(t.id + k, 4)], '', '', '', '', loc,
  jsonb_build_object('message', 'Specify at least 1 USER command in Dockerfile with non-root user as argument', 'description',
    'Running containers with root user can lead to a container escape situation.', 'resolution', 'Add USER to Dockerfile',
    'resource', '', 'namespace', 'builtin.dockerfile', 'start_line', k, 'end_line', k), pg_temp.r(t.id * 59 + k, 100) < 30,
  'misconfig|DS-' || lpad((1 + pg_temp.r(t.id * 53 + k, 40))::text, 4, '0') || '|' || loc || '|'
from lt_tgt t cross join generate_series(1, 25) k cross join lateral (select 'deploy/' || k || '/Dockerfile' loc) l
where t.kind in ('fs', 'repo') and t.id % 3 = 0 and k <= 5 + pg_temp.r(t.id * 61, 21);
create temp table lt_f1 as
select (row_number() over (order by target_id, fp_src))::bigint id, f.*, hk, s_idx, case when old then pg_temp.r(hk + 3, s_idx) else -1 end j_idx
from lt_f0 f cross join lateral (select hashtextextended(fp_src, target_id) hk) h
  cross join lateral (select greatest(case when pg_temp.r(hk + 1, 100) < 60 then nscans - 1 else pg_temp.r(hk + 2, nscans) end, old::int) s_idx) s;
-- exceptions: 1% of a project's CVEs are accepted for the whole project, 0.5% of the findings are false positives
create temp table lt_exc as
select (row_number() over (order by project_id, rule_id))::bigint id, project_id, rule_id, null::bigint finding_id from (
  select distinct project_id, rule_id from lt_f1 where kind = 'vuln' and not old
    and pg_temp.r(project_id * 1000003 + hashtext(rule_id), 1000) < 10) x;
create index on lt_exc (project_id, rule_id);
insert into lt_exc select (select count(*) from lt_exc) + row_number() over (order by id), project_id, rule_id, id from lt_f1 f
where not old and pg_temp.r(hk + 4, 1000) < 5
  and not exists (select 1 from lt_exc e where e.project_id = f.project_id and e.rule_id = f.rule_id);
create temp table lt_f as
select f.*, case when f.old then 'fixed' when e2.id is not null then 'accepted' when e1.id is not null then 'false_positive' else 'open' end status,
  case when not f.old then coalesce(e2.id, e1.id) end exception_id
from lt_f1 f left join lt_exc e1 on e1.finding_id = f.id
  left join lt_exc e2 on e2.finding_id is null and e2.project_id = f.project_id and e2.rule_id = f.rule_id and f.kind = 'vuln';
create index on lt_f (target_id);

-- What every scan saw: its counts, for the summary the lists show.
create temp table lt_sum as
select s.id, count(*) filter (where f.sev = 'CRITICAL') critical, count(*) filter (where f.sev = 'HIGH') high,
  count(*) filter (where f.sev = 'MEDIUM') medium, count(*) filter (where f.sev = 'LOW') low,
  count(*) filter (where f.sev = 'UNKNOWN') unknown, count(*) open
from lt_scan s join lt_f f on f.target_id = s.target_id and s.idx <= f.s_idx and s.idx > f.j_idx and f.status in ('open', 'fixed')
group by s.id;
create unique index on lt_sum (id);
create temp table lt_invc as select target_id, count(*) n from lt_inv group by target_id;
create unique index on lt_invc (target_id);

-- step: scans (chunked)
insert into scans(id, project_id, target_id, source, format, ref, report_sha256, status, created_by_user, created_by_token,
  summary, policy, raw, created_at, finished_at)
select s.id, s.project_id, s.target_id, case when up then 'upload' else 'server' end, 'trivy', 'build-' || (1000 + s.nscans - s.idx),
  sha256(convert_to(s.id::text, 'UTF8')), 'done', case when not up then pm.user_id end, case when up then tk.id end,
  jsonb_build_object('critical', coalesce(c.critical, 0), 'high', coalesce(c.high, 0), 'medium', coalesce(c.medium, 0),
    'low', coalesce(c.low, 0), 'unknown', coalesce(c.unknown, 0), 'open', coalesce(c.open, 0), 'packages', n.n) ||
    case when s.kind = 'image' then jsonb_build_object('os', jsonb_build_object('family', st.os, 'name', case st.os when 'alpine' then '3.12.0' else '12.1' end)) else '{}' end,
  jsonb_build_object('passed', coalesce(c.critical, 0) = 0, 'reasons',
    case when coalesce(c.critical, 0) > 0 then jsonb_build_array('CRITICAL 이상 열린 결과 ' || c.critical || '건 (허용 0건)') else '[]'::jsonb end),
  case when s.kept then r.raw end, s.ts, s.ts + interval '4 seconds'
from lt_scan s cross join lateral (select pg_temp.r(s.target_id * 71, 100) < 80 up) u
  join lt_stack st on st.tpl = s.tpl join lt_raw r on r.tpl = s.tpl join lt_invc n on n.target_id = s.target_id
  join lt_tok tk on tk.project_id = s.project_id join lt_pm pm on pm.project_id = s.project_id and pm.k = 0
  left join lt_sum c on c.id = s.id
where s.t between :lo and :hi order by s.id;

-- step: packages (chunked)
insert into packages(scan_id, purl, name, version, ecosystem, path, src_name, src_version)
select s.id, p.purl, p.name, p.ver, p.eco, p.path, p.src_name, p.src_ver
from lt_scan s join lt_inv i on i.target_id = s.target_id join lt_pkg p on p.id = i.pkg
where s.kept and s.t between :lo and :hi order by s.id;

-- step: finding rows
insert into findings(id, project_id, target_id, fingerprint, kind, tool, rule_id, title, severity, pkg_name, pkg_version,
  fixed_version, pkg_path, location, status, origin, first_seen_at, last_seen_at, fixed_at, exception_id, details, assignee_id, open_since)
select f.id, f.project_id, f.target_id, sha256(convert_to(f.fp_src, 'UTF8')), f.kind, 'trivy', f.rule_id,
  coalesce(v.title, 'Image user should not be ''root'''), f.sev, f.pkg_name, f.pkg_version, f.fixed, f.pkg_path, f.location, f.status,
  case when f.status = 'open' and f.s_idx = 0 and pg_temp.r(f.hk + 7, 100) < 30 then 'recheck' else 'scan' end,
  s1.ts + interval '4 seconds', s2.ts + interval '4 seconds', sj.ts + interval '4 seconds', f.exception_id, f.details,
  case when f.status = 'open' and pg_temp.r(f.hk + 5, 100) < 15 then pm.user_id end,
  -- as if deadlines were switched on 45 days ago: CRITICAL and HIGH of the backlog are overdue, the rest not yet
  greatest(s1.ts + interval '4 seconds', now() - interval '45 days')
from lt_f f join lt_scan s1 on s1.target_id = f.target_id and s1.idx = f.s_idx
  join lt_scan s2 on s2.target_id = f.target_id and s2.idx = f.j_idx + 1
  left join lt_scan sj on sj.target_id = f.target_id and sj.idx = f.j_idx
  left join vulns v on v.id = f.rule_id and f.kind = 'vuln'
  left join lt_pm pm on pm.project_id = f.project_id and pm.k = pg_temp.r(f.hk + 6, (select cnt from lt_pm c where c.project_id = f.project_id and c.k = 0))
order by f.id;
update targets t set last_scan_at = s.ts + interval '4 seconds' from lt_scan s where s.target_id = t.id and s.idx = 0;

-- step: scan links (chunked)
insert into scan_findings(scan_id, finding_id)
select s.id, f.id from lt_scan s join lt_f f on f.target_id = s.target_id and s.idx <= f.s_idx and s.idx > f.j_idx
where s.kept and s.t between :lo and :hi order by s.id, f.id;

-- step: scan changes, exceptions
insert into scan_changes(scan_id, finding_id, change)
select s.id, f.id, 'new' from lt_f f join lt_scan s on s.target_id = f.target_id and s.idx = f.s_idx and s.kept
union all select s.id, f.id, 'fixed' from lt_f f join lt_scan s on s.target_id = f.target_id and s.idx = f.j_idx and s.kept;
insert into exceptions(id, scope, project_id, finding_id, vuln_id, resolution, reason, status, requested_by, decided_by,
  decided_at, decision_note, expires_at, created_at)
select e.id, case when e.finding_id is null then 'project_vuln' else 'finding' end, e.project_id, e.finding_id,
  case when e.finding_id is null then e.rule_id end, case when e.finding_id is null then 'accepted' else 'false_positive' end,
  case when e.finding_id is null then '내부망 전용 서비스로 해당 기능을 사용하지 않습니다. 다음 정기 배포에서 올립니다.' else '이 경로는 배포 이미지에 들어가지 않습니다.' end,
  'approved', pm.user_id, (select id from lt_user where n = 3 + e.id % 6), now() - make_interval(days => 1 + (e.id % 60)::int), '확인했습니다.',
  now() + make_interval(days => 2 + pg_temp.r(e.id, 300)), now() - make_interval(days => 2 + (e.id % 60)::int)
from lt_exc e join lt_pm pm on pm.project_id = e.project_id and pm.k = 0;
select setval('exceptions_id_seq', (select max(id) from exceptions));
-- history: requests that ended, and some that wait
insert into exceptions(scope, project_id, vuln_id, resolution, reason, status, requested_by, decided_by, decided_at, decision_note, expires_at, created_at)
select 'project_vuln', p.id, 'CVE-2016-' || (1000 + g), 'accepted', '조치 일정 협의 중입니다.',
  (array['expired','expired','expired','rejected','revoked','pending'])[1 + g % 6], p.created_by,
  case when g % 6 < 5 then (select id from lt_user where n = 3 + g % 6) end, case when g % 6 < 5 then now() - make_interval(days => 100 + g % 200) end, '',
  case when g % 6 < 3 then now() - make_interval(days => 1 + g % 90) else now() + make_interval(days => 30 + g % 90) end, now() - make_interval(days => 120 + g % 200)
from generate_series(1, current_setting('lt.targets')::int) g join lt_proj p on p.n = 1 + g % current_setting('lt.projects')::int;

-- step: audit log and notifications
insert into audit_log(at, actor_user, actor_token, ip, action, project_id, target, details)
select at, actor_user, actor_token, ip, action, project_id, target, details from (
  select s.ts as at, null::bigint actor_user, tk.id actor_token, '10.20.' || (s.target_id % 250) || '.' || (s.id % 250) ip, 'scan.upload' action,
    s.project_id, s.kind || ':' || s.target_id target, jsonb_build_object('scan_id', s.id, 'format', 'trivy', 'ref', 'build-' || (1000 + s.nscans - s.idx),
      'duplicate', false, 'findings', 120, 'policy_passed', true) details
  from lt_scan s join lt_tok tk on tk.project_id = s.project_id where pg_temp.r(s.target_id * 71, 100) < 80
  union all
  select now() - make_interval(hours => g * 8 + u.n % 8), u.id, null, '10.10.' || (u.n % 250) || '.' || (g % 250), 'auth.login', null, '',
    '{"method": "sso"}' from lt_user u cross join generate_series(1, 60) g
  union all
  select now() - make_interval(mins => g * 37), u.id, null, '10.10.1.' || (g % 250),
    (array['finding.assign','exception.request','exception.approve','project.members','token.create','policy.update'])[1 + g % 6],
    p.id, '', jsonb_build_object('count', 1 + g % 9)
  from generate_series(1, current_setting('lt.targets')::int * 4) g join lt_proj p on p.n = 1 + g % current_setting('lt.projects')::int
    join lt_user u on u.n = 1 + g % current_setting('lt.users')::int) a
order by at;
insert into notify_channels(kind, name, config, enabled)
select 'mattermost', '부하 시험 채널 ' || g, '{"url": "http://127.0.0.1:9/hooks/loadtest"}', false from generate_series(1, 3) g;
insert into notify_subs select p.id, (select min(id) from notify_channels) + p.n % 3, '{new_critical,policy_failed,overdue,due_soon}'
from lt_proj p where p.n % 3 = 0;
insert into deliveries(channel_id, event, payload, state, attempts, next_at, last_error, created_at)
select (select min(id) from notify_channels) + g % 3, (array['new_critical','policy_failed','overdue','due_soon'])[1 + g % 4],
  jsonb_build_object('project_id', (select id from lt_proj where n = 1 + g % current_setting('lt.projects')::int), 'count', 1 + g % 20),
  case when g % 150 = 0 then 'failed' else 'sent' end, case when g % 150 = 0 then 4 else 1 end, now(), case when g % 150 = 0 then 'dial tcp: connection refused' else '' end,
  now() - make_interval(mins => g * 17)
from generate_series(1, current_setting('lt.targets')::int * 15) g;
insert into mcp_keys(user_id, name, prefix, key_hash, read_only, expires_at)
select id, 'agent', 'jsu_lt_' || n, sha256(convert_to('jsu_lt_' || n, 'UTF8')), n % 2 = 0, now() + interval '90 days' from lt_user where n % 3 = 0;

-- step: sequences
select setval('scans_id_seq', (select max(id) from scans)), setval('findings_id_seq', (select max(id) from findings));
