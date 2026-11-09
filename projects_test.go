package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return v
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, code int, what string) {
	t.Helper()
	if rec.Code != code {
		t.Errorf("%s: %d %s, want %d", what, rec.Code, rec.Body.String(), code)
	}
}

func auditCount(t *testing.T, s *server, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(), `select count(*) from audit_log where action=$1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestProjectCRUD(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	alice, bob := mkUser(t, s, "alice", ""), mkUser(t, s, "bob", "")
	ca, cb := loginAs(t, s, alice), loginAs(t, s, bob)

	rec := do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "웹 서비스", "description": "설명"}, ca)
	wantCode(t, rec, 201, "create")
	if p := decode[map[string]any](t, rec); p["key"] != "web" || p["my_role"] != "owner" {
		t.Errorf("create response: %v", p)
	}
	var role string
	s.db.QueryRow(ctx, `select role from project_members m join projects p on p.id=m.project_id
		where p.key='web' and principal_kind='user' and principal=$1`, itoa(alice.ID)).Scan(&role)
	if role != "owner" {
		t.Errorf("creator role %q", role)
	}
	if auditCount(t, s, "project.create") != 1 {
		t.Error("create not audited")
	}
	for _, bad := range []map[string]string{
		{"key": "A B", "name": "x"}, {"key": "a", "name": "x"}, {"key": "-ab", "name": "x"}, {"key": "Web", "name": "x"},
		{"key": "okay", "name": " "}, {"key": "okay", "name": strings.Repeat("가", 101)},
	} {
		rec := do(t, s, "POST", "/api/v1/projects", bad, ca)
		if rec.Code != 400 || errCode(t, rec) != "bad_request" {
			t.Errorf("bad %v: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	rec = do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "again"}, cb)
	if rec.Code != 409 || errCode(t, rec) != "conflict" {
		t.Errorf("duplicate: %d %s", rec.Code, rec.Body.String())
	}

	// listing shows only visible projects, with counts; an empty list is [], not null
	if rec := do(t, s, "GET", "/api/v1/projects", nil, cb); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("bob's list: %d %s", rec.Code, rec.Body.String())
	}
	var pid int64
	s.db.QueryRow(ctx, `select id from projects where key='web'`).Scan(&pid)
	var tid int64
	s.db.QueryRow(ctx, `insert into targets(project_id, kind, name, last_scan_at) values($1, 'image', 'app:1', now()) returning id`, pid).Scan(&tid)
	sqlExec(t, s, `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity, status) values
		($1, $2, 'a', 'vuln', 'trivy', 'CVE-1', 'CRITICAL', 'open'), ($1, $2, 'b', 'vuln', 'trivy', 'CVE-2', 'LOW', 'open'),
		($1, $2, 'c', 'vuln', 'trivy', 'CVE-3', 'HIGH', 'fixed')`, pid, tid)
	list := decode[[]struct {
		Key        string         `json:"key"`
		MyRole     string         `json:"my_role"`
		Counts     map[string]int `json:"counts"`
		LastScanAt *time.Time     `json:"last_scan_at"`
	}](t, do(t, s, "GET", "/api/v1/projects", nil, ca))
	if len(list) != 1 || list[0].Key != "web" || list[0].MyRole != "owner" || list[0].LastScanAt == nil ||
		list[0].Counts["critical"] != 1 || list[0].Counts["low"] != 1 || list[0].Counts["high"] != 0 || list[0].Counts["open"] != 2 {
		t.Errorf("alice's list: %+v", list)
	}

	wantCode(t, do(t, s, "GET", "/api/v1/projects/web", nil, cb), 404, "non-member get")
	wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/members", []map[string]string{
		{"principal_kind": "user", "principal": itoa(alice.ID), "role": "owner"},
		{"principal_kind": "user", "principal": itoa(bob.ID), "role": "viewer"},
	}, ca), 204, "add bob")
	if p := decode[map[string]any](t, do(t, s, "GET", "/api/v1/projects/web", nil, cb)); p["my_role"] != "viewer" || p["name"] != "웹 서비스" {
		t.Errorf("viewer get: %v", p)
	}
	wantCode(t, do(t, s, "PATCH", "/api/v1/projects/web", map[string]string{"name": "x"}, cb), 403, "viewer patch")
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/web", nil, cb), 403, "viewer delete")

	rec = do(t, s, "PATCH", "/api/v1/projects/web", map[string]string{"name": "새 이름"}, ca)
	wantCode(t, rec, 200, "owner patch")
	if p := decode[map[string]any](t, rec); p["name"] != "새 이름" || p["description"] != "설명" {
		t.Errorf("patch kept description? %v", p)
	}
	wantCode(t, do(t, s, "PATCH", "/api/v1/projects/web", map[string]string{"name": ""}, ca), 400, "empty name")
	wantCode(t, do(t, s, "PATCH", "/api/v1/projects/web", map[string]string{"key": "other"}, ca), 400, "key is immutable")
	if auditCount(t, s, "project.update") != 1 {
		t.Error("patch not audited")
	}
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/web", nil, ca), 204, "owner delete")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web", nil, ca), 404, "after delete")
	if auditCount(t, s, "project.delete") != 1 {
		t.Error("delete not audited")
	}
}

func TestMembersKeepOneOwner(t *testing.T) {
	s := testServer(t)
	alice, bob := mkUser(t, s, "alice", ""), mkUser(t, s, "bob", "")
	ca := loginAs(t, s, alice)
	wantCode(t, do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "web"}, ca), 201, "create")
	m := func(kind, principal, role string) map[string]string {
		return map[string]string{"principal_kind": kind, "principal": principal, "role": role}
	}
	owner := m("user", itoa(alice.ID), "owner")
	for name, body := range map[string]any{
		"no owner":        []any{m("user", itoa(alice.ID), "member"), m("user", itoa(bob.ID), "viewer")},
		"empty":           []any{},
		"unknown user":    []any{owner, m("user", "999999", "viewer")},
		"non-numeric":     []any{owner, m("user", "bob", "viewer")},
		"bad kind":        []any{owner, m("team", "/dev", "viewer")},
		"bad role":        []any{owner, m("group", "/dev", "admin")},
		"relative path":   []any{owner, m("group", "dev", "viewer")},
		"duplicate":       []any{owner, m("user", itoa(alice.ID), "viewer")},
		"not a list":      map[string]string{"x": "y"},
		"too long a path": []any{owner, m("group", "/"+strings.Repeat("a", 600), "viewer")},
	} {
		rec := do(t, s, "PUT", "/api/v1/projects/web/members", body, ca)
		if rec.Code != 400 || errCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// a group can be the only owner
	wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/members", []any{m("group", "/dev", "owner"), m("user", itoa(bob.ID), "viewer")}, ca), 204, "group owner")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/members", nil, ca), 404, "alice removed herself")
	ca2 := loginAs(t, s, mkUser(t, s, "carol", ""))
	sqlExec(t, s, `insert into user_groups(user_id, path) select id, '/dev/x' from users where username='carol'`)
	rec := do(t, s, "GET", "/api/v1/projects/web/members", nil, ca2)
	wantCode(t, rec, 200, "members get")
	got := decode[[]map[string]string](t, rec)
	if len(got) != 2 || got[0]["principal"] != "/dev" || got[0]["display"] != "/dev" || got[1]["display"] != "bob" || got[1]["role"] != "viewer" {
		t.Errorf("members: %v", got)
	}
	if auditCount(t, s, "project.members") != 1 {
		t.Error("members not audited")
	}
}

func TestTokenLifecycle(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", "")
	ca := loginAs(t, s, alice)
	for _, k := range []string{"alpha", "beta"} {
		wantCode(t, do(t, s, "POST", "/api/v1/projects", map[string]string{"key": k, "name": k}, ca), 201, "create "+k)
	}
	ok := func(w http.ResponseWriter, r *http.Request, c *reqCtx) { w.WriteHeader(204) }
	s.handle("POST /api/v1/projects/{key}/t-upload", permUpload, ok)
	s.handle("GET /api/v1/projects/{key}/t-view", permProj("viewer"), ok)

	mk := func(scopes ...string) string {
		t.Helper()
		rec := do(t, s, "POST", "/api/v1/projects/alpha/tokens",
			map[string]any{"name": "ci", "scopes": scopes, "expires_at": time.Now().Add(30 * 24 * time.Hour)}, ca)
		wantCode(t, rec, 201, "token create")
		r := decode[struct {
			ID    int64  `json:"id"`
			Token string `json:"token"`
		}](t, rec)
		if !strings.HasPrefix(r.Token, "jsc_") || len(r.Token) < 40 || r.ID == 0 {
			t.Fatalf("token: %+v", r)
		}
		return r.Token
	}
	up, rd := mk("upload"), mk("read")

	rec := do(t, s, "GET", "/api/v1/projects/alpha/tokens", nil, ca)
	wantCode(t, rec, 200, "list")
	if b := rec.Body.String(); strings.Contains(b, up) || strings.Contains(b, rd) || strings.Contains(b, "hash") || !strings.Contains(b, `"prefix":"jsc_`) {
		t.Errorf("list leaks or lacks fields: %s", b)
	}
	var details string
	s.db.QueryRow(ctx, `select string_agg(details::text, ' ') from audit_log where action='token.create'`).Scan(&details)
	if auditCount(t, s, "token.create") != 2 || strings.Contains(details, up) {
		t.Errorf("token.create audit: %s", details)
	}

	for name, body := range map[string]any{
		"over a year": map[string]any{"name": "x", "scopes": []string{"upload"}, "expires_at": time.Now().Add(366 * 24 * time.Hour)},
		"past":        map[string]any{"name": "x", "scopes": []string{"upload"}, "expires_at": time.Now().Add(-time.Hour)},
		"no expiry":   map[string]any{"name": "x", "scopes": []string{"upload"}},
		"bad scope":   map[string]any{"name": "x", "scopes": []string{"admin"}, "expires_at": time.Now().Add(time.Hour)},
		"no scopes":   map[string]any{"name": "x", "scopes": []string{}, "expires_at": time.Now().Add(time.Hour)},
		"no name":     map[string]any{"name": " ", "scopes": []string{"read"}, "expires_at": time.Now().Add(time.Hour)},
	} {
		if rec := do(t, s, "POST", "/api/v1/projects/alpha/tokens", body, ca); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}

	wantCode(t, do(t, s, "POST", "/api/v1/projects/alpha/t-upload", nil, up), 204, "upload token uploads")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/alpha/t-view", nil, rd), 204, "read token reads")
	wantCode(t, do(t, s, "POST", "/api/v1/projects/alpha/t-upload", nil, rd), 403, "read token on upload route")
	wantCode(t, do(t, s, "POST", "/api/v1/projects/beta/t-upload", nil, up), 404, "alpha token on beta")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/alpha/tokens", nil, rd), 403, "token cannot manage tokens")

	var id int64
	s.db.QueryRow(ctx, `select id from api_tokens where token_hash=$1`, tokenHash(up)).Scan(&id)
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/beta/tokens/"+itoa(id), nil, ca), 404, "revoke via another project")
	wantCode(t, do(t, s, "POST", "/api/v1/projects/alpha/t-upload", nil, up), 204, "still live")
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/alpha/tokens/"+itoa(id), nil, ca), 204, "revoke")
	wantCode(t, do(t, s, "POST", "/api/v1/projects/alpha/t-upload", nil, up), 401, "revoked token")
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/alpha/tokens/nope", nil, ca), 404, "bad id")
	if auditCount(t, s, "token.revoke") != 1 {
		t.Error("revoke not audited")
	}

	// only owners manage tokens
	bob := mkUser(t, s, "bob", "")
	addMember(t, s, func() int64 { p, _ := s.projectByKey(ctx, "alpha"); return p.ID }(), "user", itoa(bob.ID), "member")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/alpha/tokens", nil, loginAs(t, s, bob)), 403, "member lists tokens")
}

func TestPolicy(t *testing.T) {
	s := testServer(t)
	ca := loginAs(t, s, mkUser(t, s, "alice", ""))
	wantCode(t, do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "web"}, ca), 201, "create")
	if p := decode[policy](t, do(t, s, "GET", "/api/v1/projects/web/policy", nil, ca)); p != (policy{Enabled: true, MinSeverity: "CRITICAL"}) {
		t.Errorf("default: %+v", p)
	}
	// the system default applies to a project with no policy row
	if err := s.putSetting(context.Background(), "default_policy", policy{Enabled: true, MinSeverity: "HIGH", MaxCount: 5}); err != nil {
		t.Fatal(err)
	}
	if p := decode[policy](t, do(t, s, "GET", "/api/v1/projects/web/policy", nil, ca)); p.MinSeverity != "HIGH" || p.MaxCount != 5 {
		t.Errorf("setting default: %+v", p)
	}
	rec := do(t, s, "PUT", "/api/v1/projects/web/policy", map[string]any{"min_severity": "MEDIUM", "max_count": 2, "fixable_only": true}, ca)
	wantCode(t, rec, 200, "put")
	want := policy{Enabled: true, MinSeverity: "MEDIUM", MaxCount: 2, FixableOnly: true}
	if p := decode[policy](t, do(t, s, "GET", "/api/v1/projects/web/policy", nil, ca)); p != want {
		t.Errorf("after put: %+v", p)
	}
	for name, body := range map[string]any{
		"bad severity":   map[string]any{"min_severity": "SEVERE"},
		"lower case":     map[string]any{"min_severity": "high"},
		"negative count": map[string]any{"max_count": -1},
		"unknown field":  map[string]any{"maxcount": 1},
	} {
		wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/policy", body, ca), 400, name)
	}
	if auditCount(t, s, "policy.update") != 1 {
		t.Error("policy not audited")
	}
}

func TestNotifySubs(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	ca := loginAs(t, s, mkUser(t, s, "alice", ""))
	wantCode(t, do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "web"}, ca), 201, "create")
	var ch int64
	s.db.QueryRow(ctx, `insert into notify_channels(kind, name, config) values('mattermost', 'mm', '{}') returning id`).Scan(&ch)
	if rec := do(t, s, "GET", "/api/v1/projects/web/notify", nil, ca); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty: %s", rec.Body.String())
	}
	sub := func(id int64, ev ...string) map[string]any { return map[string]any{"channel_id": id, "events": ev} }
	wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/notify", []any{sub(ch, "policy_failed", "new_critical", "new_critical")}, ca), 204, "put")
	got := decode[[]struct {
		ChannelID int64    `json:"channel_id"`
		Events    []string `json:"events"`
	}](t, do(t, s, "GET", "/api/v1/projects/web/notify", nil, ca))
	if len(got) != 1 || got[0].ChannelID != ch || strings.Join(got[0].Events, ",") != "new_critical,policy_failed" {
		t.Errorf("get: %+v", got)
	}
	for name, body := range map[string]any{
		"unknown channel": []any{sub(ch+100, "new_critical")},
		"bad event":       []any{sub(ch, "everything")},
		"no events":       []any{sub(ch)},
		"duplicate":       []any{sub(ch, "new_critical"), sub(ch, "scan_failed")},
	} {
		wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/notify", body, ca), 400, name)
	}
	wantCode(t, do(t, s, "PUT", "/api/v1/projects/web/notify", []any{}, ca), 204, "clear")
	if auditCount(t, s, "notify.update") != 2 {
		t.Error("notify not audited")
	}
}

func TestTargetsList(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	ca := loginAs(t, s, mkUser(t, s, "alice", ""))
	wantCode(t, do(t, s, "POST", "/api/v1/projects", map[string]string{"key": "web", "name": "web"}, ca), 201, "create")
	p, _ := s.projectByKey(ctx, "web")
	var tid int64
	s.db.QueryRow(ctx, `insert into targets(project_id, kind, name) values($1, 'repo', 'git.example.internal/app') returning id`, p.ID).Scan(&tid)
	sqlExec(t, s, `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity) values
		($1, $2, 'a', 'vuln', 'trivy', 'CVE-1', 'HIGH'), ($1, $2, 'b', 'secret', 'trivy', 'aws', 'HIGH')`, p.ID, tid)
	got := decode[[]struct {
		ID              int64          `json:"id"`
		Counts          map[string]int `json:"counts"`
		RecheckExcluded *bool          `json:"recheck_excluded"`
	}](t, do(t, s, "GET", "/api/v1/projects/web/targets", nil, ca))
	if len(got) != 1 || got[0].ID != tid || got[0].Counts["high"] != 2 || got[0].Counts["open"] != 2 || got[0].RecheckExcluded == nil {
		t.Errorf("targets: %+v", got)
	}
}

func TestPrincipals(t *testing.T) {
	s := testServer(t)
	u := mkUser(t, s, "kim.security", "")
	mkUser(t, s, "gone", "")
	sqlExec(t, s, `update users set active=false where username='gone'`)
	sqlExec(t, s, `insert into kc_groups(path) values('/보안실'), ('/dev')`)
	sqlExec(t, s, `insert into kc_groups(path, deleted) values('/보안실-폐지', true)`)
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/보안실/취약점팀')`, u.ID)
	ck := loginAs(t, s, u)
	type principal struct{ Kind, Principal, Display string }
	get := func(q string) []principal {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/principals?q="+q, nil, ck)
		wantCode(t, rec, 200, "principals "+q)
		return decode[[]principal](t, rec)
	}
	if got := get("%EB%B3%B4%EC%95%88"); len(got) != 2 || got[0] != (principal{"group", "/보안실", "/보안실"}) || got[1].Principal != "/보안실/취약점팀" {
		t.Errorf("보안: %+v", got)
	}
	if got := get("kim"); len(got) != 1 || got[0].Kind != "user" || got[0].Principal != itoa(u.ID) || !strings.Contains(got[0].Display, "kim.security") {
		t.Errorf("kim: %+v", got)
	}
	if got := get("gone"); len(got) != 0 {
		t.Errorf("inactive user listed: %+v", got)
	}
	if got := get("%25"); len(got) != 0 { // a literal %, not a wildcard
		t.Errorf("wildcard: %+v", got)
	}
	for i := range 30 {
		mkUser(t, s, "bulk"+itoa(int64(i)), "")
	}
	if got := get("bulk"); len(got) != 20 {
		t.Errorf("limit: %d", len(got))
	}
}
