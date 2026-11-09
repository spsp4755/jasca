package main

import (
	"context"
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
