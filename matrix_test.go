package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The cross-project matrix: a user who owns project A sends project B's key and B's object ids to every
// project-scoped route and must get 404 (never 403, never data). Later tasks extend it from an init() in their
// own _test.go:
//
//	func init() {
//		matrixRoutes = append(matrixRoutes,
//			matrixCase{Method: "GET", Path: "/api/v1/scans/{scan}"},
//			matrixCase{Method: "GET", Path: "/api/v1/findings?project={key}", List: "items"})
//		matrixFixtures = append(matrixFixtures, func(t *testing.T, s *server, projB *project) map[string]string {
//			return map[string]string{"{advisory}": "..."} // extra B-side objects, only if the base set lacks them
//		})
//	}
//
// Placeholders (all of project B unless noted): {key}, {akey} (project A's key, to send B's ids through A's
// routes), {me} (the caller's user id), {target}, {scan}, {finding}, {exception}, {ai_run}, {token}, {channel}.
// They are replaced in Path and in the JSON of Body.
type matrixCase struct {
	Method, Path string
	Body         any
	// List marks a list endpoint, which may also answer 200 with nothing in it: "[]" means the body itself is an
	// empty array, any other value names a top-level field that must be an empty array. "" means only 404 passes.
	List string
}

var matrixRoutes = []matrixCase{
	{Method: "GET", Path: "/api/v1/projects/{key}"},
	{Method: "PATCH", Path: "/api/v1/projects/{key}", Body: map[string]string{"name": "taken"}},
	{Method: "DELETE", Path: "/api/v1/projects/{key}"},
	{Method: "GET", Path: "/api/v1/projects/{key}/members"},
	{Method: "PUT", Path: "/api/v1/projects/{key}/members", Body: []map[string]string{{"principal_kind": "user", "principal": "{me}", "role": "owner"}}},
	{Method: "GET", Path: "/api/v1/projects/{key}/tokens"},
	{Method: "POST", Path: "/api/v1/projects/{key}/tokens", Body: map[string]any{"name": "x", "scopes": []string{"upload"}, "expires_at": "2099-01-01T00:00:00Z"}},
	{Method: "DELETE", Path: "/api/v1/projects/{key}/tokens/{token}"},
	{Method: "DELETE", Path: "/api/v1/projects/{akey}/tokens/{token}"},
	{Method: "GET", Path: "/api/v1/projects/{key}/policy"},
	{Method: "PUT", Path: "/api/v1/projects/{key}/policy", Body: map[string]any{"enabled": false}},
	{Method: "GET", Path: "/api/v1/projects/{key}/notify"},
	{Method: "PUT", Path: "/api/v1/projects/{key}/notify", Body: []any{}},
	{Method: "GET", Path: "/api/v1/projects/{key}/targets"},
	{Method: "PATCH", Path: "/api/v1/projects/{key}/targets/{target}", Body: map[string]string{"name": "taken"}},
	{Method: "DELETE", Path: "/api/v1/projects/{key}/targets/{target}"},
	// B's target through the caller's own project
	{Method: "PATCH", Path: "/api/v1/projects/{akey}/targets/{target}", Body: map[string]string{"name": "taken"}},
	{Method: "DELETE", Path: "/api/v1/projects/{akey}/targets/{target}"},
}

// matrixFixtures add placeholder values for objects of project B that the base fixture does not create.
var matrixFixtures []func(t *testing.T, s *server, projB *project) map[string]string

// matrixExempt lists route patterns with path values that are deliberately not project-scoped, with the reason
// (for example a shared catalog). Every other non-public, non-admin, non-security route with a path value must
// have a matrix case.
var matrixExempt = map[string]string{}

// matrixBase creates the base fixture: project B with one object of each kind, owned by someone else.
func matrixBase(t *testing.T, s *server, projB *project) map[string]string {
	t.Helper()
	ctx := context.Background()
	id := func(q string, args ...any) string {
		t.Helper()
		var v int64
		if err := s.db.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return itoa(v)
	}
	b := projB.ID
	ph := map[string]string{}
	ph["{target}"] = id(`insert into targets(project_id, kind, name) values($1, 'image', 'b/app:1') returning id`, b)
	ph["{scan}"] = id(`insert into scans(project_id, target_id, source, format, status) values($1, $2, 'upload', 'trivy', 'done') returning id`, b, ph["{target}"])
	ph["{finding}"] = id(`insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity) values($1, $2, 'fp', 'vuln', 'trivy', 'CVE-2024-0001', 'HIGH') returning id`, b, ph["{target}"])
	sqlExec(t, s, `insert into scan_findings(scan_id, finding_id) values($1, $2)`, ph["{scan}"], ph["{finding}"])
	ph["{exception}"] = id(`insert into exceptions(scope, project_id, finding_id, resolution, reason, expires_at)
		values('finding', $1, $2, 'accepted', 'b only', now() + interval '30 days') returning id`, b, ph["{finding}"])
	ph["{ai_run}"] = id(`insert into ai_runs(kind, project_id, state, output) values('project_report', $1, 'done', 'b report') returning id`, b)
	ph["{token}"] = id(`insert into api_tokens(project_id, name, prefix, token_hash, scopes, expires_at)
		values($1, 'b-ci', 'jsc_b', $2, '{upload}', now() + interval '1 day') returning id`, b, tokenHash("jsc_matrix_b"))
	ph["{channel}"] = id(`insert into notify_channels(kind, name, config) values('mattermost', 'b-mm', '{}') returning id`)
	sqlExec(t, s, `insert into notify_subs(project_id, channel_id, events) values($1, $2, '{new_critical}')`, b, ph["{channel}"])
	sqlExec(t, s, `insert into policies(project_id, min_severity) values($1, 'LOW')`, b)
	return ph
}

var unfilled = regexp.MustCompile(`\{[a-z_]+\}`)

func TestCrossProjectMatrix(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	me, bOwner := mkUser(t, s, "a-owner", ""), mkUser(t, s, "b-owner", "")
	a, b := mkProject(t, s, "proj-a"), mkProject(t, s, "proj-b")
	addMember(t, s, a, "user", itoa(me.ID), "owner")
	addMember(t, s, b, "user", itoa(bOwner.ID), "owner")
	addMember(t, s, b, "group", "/b-team", "member")
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/a-team')`, me.ID) // memberships elsewhere grant nothing
	projB, err := s.projectByID(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	ph := matrixBase(t, s, projB)
	ph["{key}"], ph["{akey}"], ph["{me}"] = "proj-b", "proj-a", itoa(me.ID)
	for _, f := range matrixFixtures {
		for k, v := range f(t, s, projB) {
			ph[k] = v
		}
	}
	fill := func(x string) string {
		for k, v := range ph {
			x = strings.ReplaceAll(x, k, v)
		}
		return x
	}
	ck := loginAs(t, s, me)
	covered := map[string]bool{}
	for _, mc := range matrixRoutes {
		name := mc.Method + " " + mc.Path
		path := fill(mc.Path)
		var body any
		if mc.Body != nil {
			j, err := json.Marshal(mc.Body)
			if err != nil {
				t.Fatal(err)
			}
			body = []byte(fill(string(j)))
		}
		if unfilled.MatchString(path) || body != nil && unfilled.Match(body.([]byte)) {
			t.Errorf("%s: unknown placeholder (add it with matrixFixtures)", name)
			continue
		}
		_, pattern := s.mux.Handler(httptest.NewRequest(mc.Method, path, nil))
		covered[pattern] = true
		rec := do(t, s, mc.Method, path, body, ck)
		if rec.Code == 404 && errCode(t, rec) == "not_found" || mc.List != "" && rec.Code == 200 && emptyList(rec.Body.Bytes(), mc.List) {
			continue
		}
		t.Errorf("%s (%s): %d %s", name, path, rec.Code, rec.Body.String())
	}

	// nothing of B's changed
	var name string
	var revoked, members, subs int
	var sev string
	s.db.QueryRow(ctx, `select name, (select count(*) from api_tokens where project_id=p.id and revoked_at is not null),
		(select count(*) from project_members where project_id=p.id), (select count(*) from notify_subs where project_id=p.id),
		(select min_severity from policies where project_id=p.id) from projects p where id=$1`, b).Scan(&name, &revoked, &members, &subs, &sev)
	if name != "proj-b" || revoked != 0 || members != 2 || subs != 1 || sev != "LOW" {
		t.Errorf("project B changed: name=%q revoked=%d members=%d subs=%d sev=%q", name, revoked, members, subs, sev)
	}

	for _, ri := range s.routes {
		method, path, _ := strings.Cut(ri.pattern, " ")
		switch {
		case !strings.Contains(path, "{"), ri.perm.kind == "public", ri.perm.kind == "admin", ri.perm.kind == "security":
		case covered[ri.pattern], matrixExempt[ri.pattern] != "":
		default:
			t.Errorf("%s %s has no matrix case: append one to matrixRoutes (or a reason to matrixExempt)", method, path)
		}
	}
}

func emptyList(b []byte, field string) bool {
	if field == "[]" {
		var l []any
		return json.Unmarshal(b, &l) == nil && l != nil && len(l) == 0
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return emptyList(m[field], "[]")
}
