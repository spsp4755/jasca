package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func login(t *testing.T, s *server, username, password string, h ...any) (int, *http.Cookie, string) {
	t.Helper()
	rec := do(t, s, "POST", "/api/v1/auth/local", map[string]string{"username": username, "password": password}, h...)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return rec.Code, c, rec.Body.String()
		}
	}
	return rec.Code, nil, rec.Body.String()
}

func TestLocalLogin(t *testing.T) {
	s := testServer(t)
	code, ck, body := login(t, s, "admin", testBootstrapPassword)
	if code != 200 || ck == nil {
		t.Fatalf("login: %d %s", code, body)
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Secure {
		t.Errorf("cookie flags: %+v", ck)
	}
	rec := do(t, s, "GET", "/api/v1/me", nil, ck)
	var me map[string]any
	json.Unmarshal(rec.Body.Bytes(), &me)
	if rec.Code != 200 || me["username"] != "admin" || me["system_role"] != "admin" {
		t.Fatalf("me: %d %s", rec.Code, rec.Body.String())
	}
	if d, ok := me["depts"].([]any); !ok || len(d) != 0 {
		t.Errorf("depts should be an empty array: %s", rec.Body.String())
	}
	_, ck, _ = login(t, s, "admin", testBootstrapPassword, http.Header{"X-Forwarded-Proto": {"https"}})
	if ck == nil || !ck.Secure {
		t.Errorf("https cookie not Secure: %+v", ck)
	}
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log a join users u on u.id=a.actor_user where a.action='auth.login' and u.username='admin'`).Scan(&n)
	if n != 2 {
		t.Errorf("auth.login audit rows: %d", n)
	}
}

func TestLocalLoginLockout(t *testing.T) {
	s := testServer(t)
	_, _, unknown := login(t, s, "nobody", "wrong-password")
	for i := 0; i < 5; i++ {
		code, _, body := login(t, s, "admin", "wrong-password")
		if code != 401 || body != unknown {
			t.Fatalf("attempt %d: %d %s (unknown user got %s)", i+1, code, body, unknown)
		}
	}
	code, ck, body := login(t, s, "admin", testBootstrapPassword)
	if code != 423 || ck != nil {
		t.Fatalf("6th attempt: %d %s", code, body)
	}
	var e struct{ Error string }
	json.Unmarshal([]byte(body), &e)
	if e.Error != "locked" {
		t.Errorf("code: %s", body)
	}
	var until time.Duration
	s.db.QueryRow(context.Background(), `select extract(epoch from locked_until - now())::bigint * 1000000000 from users where username='admin'`).Scan(&until)
	if until < 14*time.Minute || until > 15*time.Minute {
		t.Errorf("locked for %v", until)
	}
	var fails int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action='auth.login_failed'`).Scan(&fails)
	if fails != 7 {
		t.Errorf("auth.login_failed audit rows: %d", fails)
	}
	// once the lock ends, the right password works and the counter starts over
	s.db.Exec(context.Background(), `update users set locked_until = now() - interval '1 second' where username='admin'`)
	if code, _, body := login(t, s, "admin", "wrong-password"); code != 401 {
		t.Fatalf("after lock, wrong: %d %s", code, body)
	}
	if code, _, body := login(t, s, "admin", testBootstrapPassword); code != 200 {
		t.Fatalf("after lock, right: %d %s", code, body)
	}
}

func TestSSOUserCannotLocalLogin(t *testing.T) {
	s := testServer(t)
	mkUser(t, s, "bob", "")
	hash, _ := bcrypt.GenerateFromPassword([]byte("bob-password-123"), bcrypt.MinCost)
	s.db.Exec(context.Background(), `update users set password_hash=$1 where username='bob'`, string(hash))
	if code, ck, body := login(t, s, "bob", "bob-password-123"); code != 401 || ck != nil {
		t.Fatalf("sso user local login: %d %s", code, body)
	}
}

func TestLoginRateLimiter(t *testing.T) {
	l := newLimiter(20, time.Minute)
	now := time.Now()
	for i := 0; i < 20; i++ {
		if !l.allow("10.0.0.1", now) {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if l.allow("10.0.0.1", now) {
		t.Error("21st attempt in the same minute allowed")
	}
	if !l.allow("10.0.0.2", now) {
		t.Error("another IP refused")
	}
	if !l.allow("10.0.0.1", now.Add(3*time.Second)) {
		t.Error("not refilled after 3s")
	}
}

func TestMePassword(t *testing.T) {
	s := testServer(t)
	_, ck, _ := login(t, s, "admin", testBootstrapPassword)
	_, other, _ := login(t, s, "admin", testBootstrapPassword)
	pw := func(ck *http.Cookie, cur, nw string) int {
		return do(t, s, "POST", "/api/v1/me/password", map[string]string{"current_password": cur, "new_password": nw}, ck).Code
	}
	if c := pw(ck, "wrong-password", "new-password-123"); c != 400 {
		t.Fatalf("wrong current: %d", c)
	}
	if c := pw(ck, testBootstrapPassword, "short"); c != 400 {
		t.Fatalf("short: %d", c)
	}
	if c := pw(ck, testBootstrapPassword, "new-password-123"); c != 204 {
		t.Fatalf("change: %d", c)
	}
	if c := do(t, s, "GET", "/api/v1/me", nil, ck).Code; c != 200 {
		t.Fatalf("this session ended: %d", c)
	}
	if c := do(t, s, "GET", "/api/v1/me", nil, other).Code; c != 401 {
		t.Fatalf("other session kept: %d", c)
	}
	if code, _, _ := login(t, s, "admin", testBootstrapPassword); code != 401 {
		t.Fatal("old password still works")
	}
	if code, _, _ := login(t, s, "admin", "new-password-123"); code != 200 {
		t.Fatal("new password refused")
	}
	if n := auditCount(t, s, "auth.password_change"); n != 1 {
		t.Fatalf("audit %d", n)
	}
	// a restart with the bootstrap password set never resets the changed password
	if _, err := newServer(context.Background(), s.cfg, s.db); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := login(t, s, "admin", "new-password-123"); code != 200 {
		t.Fatal("restart reset the admin password")
	}
	// SSO users have no local password
	if c := pw(loginAs(t, s, mkUser(t, s, "bob", "")), "x", "new-password-123"); c != 403 {
		t.Fatalf("sso user: %d", c)
	}
}
