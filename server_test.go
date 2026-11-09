package main

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
)

func TestHandlePanicsWithoutPerm(t *testing.T) {
	s := &server{mux: http.NewServeMux()}
	for _, p := range []perm{{}, {kind: "bogus"}, {kind: "proj", role: "boss"}, {kind: "obj", role: "viewer"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("handle with %+v did not panic", p)
				}
			}()
			s.handle("GET /x", p, func(http.ResponseWriter, *http.Request, *reqCtx) {})
		}()
	}
}

func TestEveryRouteDeclaresPerm(t *testing.T) {
	s := testServer(t)
	if len(s.routes) == 0 {
		t.Fatal("no routes")
	}
	known := map[string]bool{"public": true, "user": true, "admin": true, "security": true, "proj": true, "upload": true, "obj": true}
	for _, ri := range s.routes {
		if !known[ri.perm.kind] {
			t.Errorf("%s: unknown perm kind %q", ri.pattern, ri.perm.kind)
		}
		if ri.perm.kind == "obj" && s.objs[ri.perm.obj] == nil {
			t.Errorf("%s: no resolver registered for obj kind %q", ri.pattern, ri.perm.obj)
		}
	}
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

func TestUnauthenticatedGets401(t *testing.T) {
	s := testServer(t)
	for _, ri := range s.routes {
		if ri.perm.kind == "public" {
			continue
		}
		method, path, ok := strings.Cut(ri.pattern, " ")
		if !ok {
			method, path = "GET", ri.pattern
		}
		rec := do(t, s, method, pathParam.ReplaceAllString(path, "1"), nil)
		if rec.Code != 401 || errCode(t, rec) != "unauthorized" {
			t.Errorf("%s: %d %s", ri.pattern, rec.Code, rec.Body.String())
		}
	}
}

func TestHealthz(t *testing.T) {
	s := testServer(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		rec := do(t, s, "GET", p, nil)
		if rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: security headers missing: %v", p, rec.Header())
		}
	}
	if rec := do(t, s, "GET", "/healthz", nil, http.Header{"X-Forwarded-Proto": {"https"}}); rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS over https")
	}
}

func TestCSRF(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "alice", ""))
	s.handle("POST /api/v1/test/echo", permUser, func(w http.ResponseWriter, r *http.Request, c *reqCtx) { w.WriteHeader(204) })
	evil := http.Header{"Origin": {"http://evil.example"}}
	cases := []struct {
		name string
		h    http.Header
		want int
	}{
		{"foreign origin", evil, 403},
		{"cross-site fetch", http.Header{"Sec-Fetch-Site": {"cross-site"}}, 403},
		{"no origin markers", http.Header{}, 403},
		{"same origin", http.Header{"Origin": {"http://example.com"}}, 204}, // httptest requests use Host example.com
		{"sec-fetch-site same-origin", http.Header{"Sec-Fetch-Site": {"same-origin"}}, 204},
	}
	for _, tc := range cases {
		rec := do(t, s, "POST", "/api/v1/test/echo", nil, ck, tc.h)
		if rec.Code != tc.want {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body.String())
		}
		if tc.want == 403 && errCode(t, rec) != "csrf" {
			t.Errorf("%s: %s", tc.name, rec.Body.String())
		}
	}
	// a bearer token carries no ambient credential, so the check is skipped
	_, plain := mkToken(t, s, "demo", "upload")
	s.handle("POST /api/v1/projects/{key}/test-upload", permUpload, func(w http.ResponseWriter, r *http.Request, c *reqCtx) { w.WriteHeader(204) })
	if rec := do(t, s, "POST", "/api/v1/projects/demo/test-upload", nil, plain, evil); rec.Code != 204 {
		t.Errorf("bearer with foreign origin: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBodyLimit(t *testing.T) {
	s := testServer(t)
	big := map[string]string{"username": "admin", "password": strings.Repeat("x", 64<<10)}
	rec := do(t, s, "POST", "/api/v1/auth/local", big)
	if rec.Code != 413 || errCode(t, rec) != "too_large" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, s, "POST", "/api/v1/auth/local", `{"username":"admin","password":"x","extra":1}`); rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
}

// mkToken creates project key (if missing) and an API token for it with the given scopes; returns the project id and plaintext.
func mkToken(t *testing.T, s *server, key string, scopes ...string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	var pid int64
	err := s.db.QueryRow(ctx, `insert into projects(key, name) values($1, $1) on conflict (key) do update set name=excluded.name returning id`, key).Scan(&pid)
	if err != nil {
		t.Fatal(err)
	}
	plain := "jsc_" + key + "_" + strings.Join(scopes, "_")
	_, err = s.db.Exec(ctx, `insert into api_tokens(project_id, name, prefix, token_hash, scopes, expires_at)
		values($1, 'ci', left($2, 8), $3, $4, now() + interval '1 day')`, pid, plain, tokenHash(plain), append([]string{}, scopes...))
	if err != nil {
		t.Fatal(err)
	}
	return pid, plain
}

func TestTokenAuth(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	ok := func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		if c.User != nil || c.Token == nil || c.Project == nil || c.Project.ID != c.Token.ProjectID {
			t.Errorf("reqCtx: %+v", c)
		}
		w.WriteHeader(204)
	}
	s.handle("POST /api/v1/projects/{key}/t-upload", permUpload, ok)
	s.handle("GET /api/v1/projects/{key}/t-view", permProj("viewer"), ok)
	s.handle("GET /api/v1/projects/{key}/t-member", permProj("member"), ok)
	s.handle("GET /api/v1/t-user", permUser, ok)
	_, up := mkToken(t, s, "alpha", "upload")
	_, rd := mkToken(t, s, "alpha", "read")
	mkToken(t, s, "beta", "upload")
	cases := []struct {
		method, path, tok string
		want              int
	}{
		{"POST", "/api/v1/projects/alpha/t-upload", up, 204},
		{"GET", "/api/v1/projects/alpha/t-view", rd, 204},
		{"POST", "/api/v1/projects/alpha/t-upload", rd, 403},  // read scope cannot upload
		{"GET", "/api/v1/projects/alpha/t-view", up, 403},     // upload scope cannot read
		{"GET", "/api/v1/projects/alpha/t-member", rd, 403},   // only proj:viewer routes
		{"GET", "/api/v1/t-user", up, 403},                    // tokens never act as a user
		{"POST", "/api/v1/projects/beta/t-upload", up, 404},   // another project's token
		{"POST", "/api/v1/projects/nosuch/t-upload", up, 404}, // unknown project
		{"POST", "/api/v1/projects/alpha/t-upload", "jsc_unknown", 401},
		{"POST", "/api/v1/projects/alpha/t-upload", "not-a-token", 401},
	}
	for _, tc := range cases {
		if rec := do(t, s, tc.method, tc.path, nil, tc.tok); rec.Code != tc.want {
			t.Errorf("%s %s (%s): %d %s", tc.method, tc.path, tc.tok, rec.Code, rec.Body.String())
		}
	}
	var used bool
	s.db.QueryRow(ctx, `select last_used_at is not null from api_tokens where token_hash=$1`, tokenHash(up)).Scan(&used)
	if !used {
		t.Error("last_used_at not set")
	}
	s.db.Exec(ctx, `update api_tokens set revoked_at=now() where token_hash=$1`, tokenHash(up))
	if rec := do(t, s, "POST", "/api/v1/projects/alpha/t-upload", nil, up); rec.Code != 401 {
		t.Errorf("revoked: %d", rec.Code)
	}
	s.db.Exec(ctx, `update api_tokens set expires_at=now() - interval '1 second' where token_hash=$1`, tokenHash(rd))
	if rec := do(t, s, "GET", "/api/v1/projects/alpha/t-view", nil, rd); rec.Code != 401 {
		t.Errorf("expired: %d", rec.Code)
	}
}

func TestPermChecks(t *testing.T) {
	s := testServer(t)
	ok := func(w http.ResponseWriter, r *http.Request, c *reqCtx) { w.WriteHeader(204) }
	s.handle("GET /api/v1/t-admin", permAdmin, ok)
	s.handle("GET /api/v1/t-security", permSecurity, ok)
	s.handle("GET /api/v1/projects/{key}/t-view", permProj("viewer"), ok)
	s.handle("GET /api/v1/projects/{key}/t-owner", permProj("owner"), ok)
	s.handle("GET /api/v1/things/{id}", permObj("thing", "viewer"), func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		writeJSON(w, 200, c.Project)
	})
	pid, _ := mkToken(t, s, "alpha")
	s.registerObj("thing", func(ctx context.Context, id string) (int64, error) {
		if id == "7" {
			return pid, nil
		}
		return 0, pgx.ErrNoRows
	})
	plain := loginAs(t, s, mkUser(t, s, "plain", ""))
	sec := loginAs(t, s, mkUser(t, s, "sec", "security"))
	adm := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	check := func(name, path string, ck *http.Cookie, want int) {
		t.Helper()
		if rec := do(t, s, "GET", path, nil, ck); rec.Code != want {
			t.Errorf("%s %s: %d %s", name, path, rec.Code, rec.Body.String())
		}
	}
	check("plain", "/api/v1/t-admin", plain, 403)
	check("sec", "/api/v1/t-admin", sec, 403)
	check("adm", "/api/v1/t-admin", adm, 204)
	check("plain", "/api/v1/t-security", plain, 403)
	check("sec", "/api/v1/t-security", sec, 204)
	check("adm", "/api/v1/t-security", adm, 204)
	check("adm", "/api/v1/projects/alpha/t-owner", adm, 204)
	check("adm", "/api/v1/things/7", adm, 200)
	check("sec", "/api/v1/projects/alpha/t-view", sec, 204)
	check("sec", "/api/v1/projects/alpha/t-owner", sec, 403)
	check("plain", "/api/v1/projects/alpha/t-view", plain, 404)

	old := projectRole
	t.Cleanup(func() { projectRole = old })
	projectRole = func(s *server, ctx context.Context, u *user, projectID int64) (string, error) {
		if u.Username == "plain" && projectID == pid {
			return "viewer", nil
		}
		return "", nil
	}
	check("plain viewer", "/api/v1/projects/alpha/t-view", plain, 204)
	check("plain viewer", "/api/v1/projects/alpha/t-owner", plain, 403)
	check("plain viewer", "/api/v1/projects/nosuch/t-view", plain, 404)
	check("no role", "/api/v1/projects/alpha/t-view", sec, 404)
	check("obj", "/api/v1/things/7", plain, 200)
	check("unknown obj", "/api/v1/things/8", plain, 404)
}

func TestWebFallback(t *testing.T) {
	s := testServer(t)
	old := webFiles
	t.Cleanup(func() { webFiles = old })
	webFiles = fstest.MapFS{
		"index.html":    {Data: []byte("<html>jasca app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	rec := do(t, s, "GET", "/projects/demo/findings", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "jasca app") {
		t.Errorf("spa fallback: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, s, "GET", "/assets/app.js", nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("asset: %d %v", rec.Code, rec.Header())
	}
	rec = do(t, s, "GET", "/api/v1/nosuch", nil)
	if rec.Code != 404 || errCode(t, rec) != "not_found" {
		t.Errorf("unknown api: %d %s", rec.Code, rec.Body.String())
	}
}
