package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBootstrapAdmin(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, pw := range []string{"", "short-pw-11", strings.Repeat("x", 73)} {
		cfg := s.cfg
		cfg.BootstrapPassword = pw
		if _, err := newServer(ctx, cfg, s.db); err == nil {
			t.Errorf("password of %d chars accepted", len(pw))
		}
	}
	var source, role, hash string
	if err := s.db.QueryRow(ctx, `select source, system_role, password_hash from users where username='admin'`).Scan(&source, &role, &hash); err != nil {
		t.Fatal(err)
	}
	if source != "local" || role != "admin" || hash == "" || strings.Contains(hash, testBootstrapPassword) {
		t.Fatalf("admin: %s %s %q", source, role, hash)
	}
	cfg := s.cfg
	cfg.BootstrapPassword = "another-password-456"
	if _, err := newServer(ctx, cfg, s.db); err != nil {
		t.Fatal(err)
	}
	var again string
	s.db.QueryRow(ctx, `select password_hash from users where username='admin'`).Scan(&again)
	if again != hash {
		t.Error("second start changed the admin password")
	}
}

func TestSessionIdle(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "alice", ""))
	if rec := do(t, s, "GET", "/api/v1/me", nil, ck); rec.Code != 200 {
		t.Fatalf("fresh session: %d", rec.Code)
	}
	s.db.Exec(context.Background(), `update sessions set last_seen_at = now() - interval '31 minutes'`)
	if rec := do(t, s, "GET", "/api/v1/me", nil, ck); rec.Code != 401 {
		t.Fatalf("idle session: %d", rec.Code)
	}
}

func TestSessionTouch(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "alice", ""))
	ctx := context.Background()
	s.db.Exec(ctx, `update sessions set last_seen_at = now() - interval '29 minutes'`)
	do(t, s, "GET", "/api/v1/me", nil, ck)
	var recent bool
	s.db.QueryRow(ctx, `select last_seen_at > now() - interval '1 minute' from sessions`).Scan(&recent)
	if !recent {
		t.Error("last_seen_at not refreshed")
	}
}

func TestMaxSessions(t *testing.T) {
	s := testServer(t)
	s.cfg.MaxSessions = 2
	u := mkUser(t, s, "alice", "")
	first, second, third := loginAs(t, s, u), loginAs(t, s, u), loginAs(t, s, u)
	if rec := do(t, s, "GET", "/api/v1/me", nil, first); rec.Code != 401 {
		t.Errorf("oldest session still works: %d", rec.Code)
	}
	for _, ck := range []any{second, third} {
		if rec := do(t, s, "GET", "/api/v1/me", nil, ck); rec.Code != 200 {
			t.Errorf("newer session: %d", rec.Code)
		}
	}
}

// The checklist case: one session per account. The older browser is signed out and told why on the login page; the
// newer one is told, once, that it ended another session; the event is in the audit log.
func TestSessionReplaced(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if def, _ := configFrom(func(string) string { return "" }); def.MaxSessions != 1 {
		t.Fatalf("default max sessions: %d", def.MaxSessions)
	}
	s.cfg.MaxSessions = 1
	u := mkUser(t, s, "alice", "")
	first := loginAs(t, s, u)
	if rec := do(t, s, "GET", "/api/v1/me", nil, first); rec.Code != 200 || strings.Contains(rec.Body.String(), "session_notice") {
		t.Fatalf("a first login has nothing to warn about: %d %s", rec.Code, rec.Body.String())
	}
	second := loginAs(t, s, u)
	if rec := do(t, s, "GET", "/api/v1/me", nil, first); rec.Code != 401 {
		t.Fatalf("replaced session still works: %d", rec.Code)
	}
	s.db.Exec(ctx, `update sessions set last_seen_at = now() - interval '2 hours'`) // the reason outlives the idle limit
	if rec := do(t, s, "GET", "/api/v1/auth/config", nil, first); !strings.Contains(rec.Body.String(), `"session_ended":"replaced"`) {
		t.Errorf("login page of the replaced browser: %s", rec.Body.String())
	}
	s.db.Exec(ctx, `update sessions set last_seen_at = now()`)
	if rec := do(t, s, "GET", "/api/v1/auth/config", nil, second); strings.Contains(rec.Body.String(), "session_ended") {
		t.Errorf("live session reported as ended: %s", rec.Body.String())
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, second); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"session_notice":{"ended":1,"active":0}`) {
		t.Errorf("notice of the new session: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, second); rec.Code != 200 || strings.Contains(rec.Body.String(), "session_notice") {
		t.Errorf("notice shown twice: %s", rec.Body.String())
	}
	var n int
	s.db.QueryRow(ctx, `select count(*) from audit_log where action='auth.session_end' and actor_user=$1 and details->>'count'='1'`, u.ID).Scan(&n)
	if n != 1 {
		t.Errorf("audit rows for the ended session: %d", n)
	}
	// signing in again from the replaced browser clears its old row and ends the other one in turn
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(first)
	if _, err := s.startSession(ctx, u.ID, req); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(ctx, `select count(*) from sessions where user_id=$1`, u.ID).Scan(&n)
	if rec := do(t, s, "GET", "/api/v1/me", nil, second); rec.Code != 401 || n != 2 {
		t.Errorf("after signing in again: other session %d, rows %d", rec.Code, n)
	}
}

// Without a limit nobody is signed out, but the new session is told the account is open elsewhere.
func TestSessionNoticeUnlimited(t *testing.T) {
	s := testServer(t)
	u := mkUser(t, s, "alice", "")
	first, second := loginAs(t, s, u), loginAs(t, s, u)
	if rec := do(t, s, "GET", "/api/v1/me", nil, first); rec.Code != 200 {
		t.Errorf("first session: %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, second); !strings.Contains(rec.Body.String(), `"session_notice":{"ended":0,"active":1}`) {
		t.Errorf("notice: %s", rec.Body.String())
	}
}

// Another administrator switches the shared local admin off in the users screen: its login and sessions stop and the
// login page is told. It comes back the same way, or with the server command when nobody can sign in.
func TestLocalAdminSwitch(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, adminCk, _ := login(t, s, "admin", testBootstrapPassword)
	local := qint64(t, s, `select id from users where source='local'`)
	path := "/api/v1/admin/users/" + itoa(local)
	if rec := do(t, s, "PATCH", path, map[string]any{"active": false}, adminCk); rec.Code != 400 {
		t.Fatalf("admin switched itself off: %d %s", rec.Code, rec.Body.String())
	}
	park := loginAs(t, s, mkUser(t, s, "park", "admin"))
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"active": false}, park), 200, "another administrator switches it off")
	if rec := do(t, s, "GET", "/api/v1/me", nil, adminCk); rec.Code != 401 {
		t.Errorf("admin session after switching off: %d", rec.Code)
	}
	rec := do(t, s, "POST", "/api/v1/auth/local", map[string]string{"username": "admin", "password": testBootstrapPassword})
	if rec.Code != 403 || errCode(t, rec) != "local_disabled" {
		t.Errorf("local login while off: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, s, "GET", "/api/v1/auth/config", nil); !strings.Contains(rec.Body.String(), `"local_login":false`) {
		t.Errorf("config: %s", rec.Body.String())
	}
	if n := qInt(t, s, `select count(*) from audit_log where action='auth.login_failed' and details->>'reason'='local_disabled'`); n != 1 {
		t.Errorf("audit rows for the refused login: %d", n)
	}
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"active": true}, park), 200, "switching it on again")
	if code, _, body := login(t, s, "admin", testBootstrapPassword); code != 200 {
		t.Errorf("local login after switching on: %d %s", code, body)
	}
	// the server command, for when Keycloak is down
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"active": false}, park), 200, "off again")
	if err := enableLocalAdmin(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if code, _, body := login(t, s, "admin", testBootstrapPassword); code != 200 {
		t.Errorf("local login after the server command: %d %s", code, body)
	}
	if n := qInt(t, s, `select count(*) from audit_log where action='user.update' and target='admin' and details->>'op'='server_command'`); n != 1 {
		t.Errorf("audit rows for the server command: %d", n)
	}
}

func TestLogout(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "alice", ""))
	rec := do(t, s, "POST", "/api/v1/auth/logout", nil, ck)
	if rec.Code != 204 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Name != sessionCookie || c[0].MaxAge >= 0 {
		t.Errorf("cookie not cleared: %v", c)
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, ck); rec.Code != 401 {
		t.Errorf("after logout: %d", rec.Code)
	}
}

func TestSignedValues(t *testing.T) {
	s := testServer(t)
	type state struct{ Next string }
	raw := s.signed(state{"/projects"})
	var got state
	if !s.unsigned(raw, &got) || got.Next != "/projects" {
		t.Fatalf("round trip: %v %+v", raw, got)
	}
	if s.unsigned(raw[:len(raw)-2]+"xx", &got) || s.unsigned("garbage", &got) {
		t.Error("tampered value accepted")
	}
}
