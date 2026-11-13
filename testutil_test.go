package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testBootstrapPassword = "bootstrap-pw-123"

// testServer wipes the schema of JASCA_TEST_DATABASE_URL and returns a fresh server with the bootstrap admin.
// Tests share one database, so they must not call t.Parallel.
func testServer(t *testing.T) *server {
	t.Helper()
	url := os.Getenv("JASCA_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JASCA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	// JASCA_TEST_SCHEMA runs the suite inside another schema, the way a database handed out by a DBA is used
	schema := os.Getenv("JASCA_TEST_SCHEMA")
	q := pgx.Identifier{cmp.Or(schema, "public")}.Sanitize()
	if _, err := db.Exec(ctx, `drop schema if exists `+q+` cascade; create schema `+q); err != nil {
		t.Fatal(err)
	}
	if schema != "" {
		if db, err = openDB(ctx, url, schema); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
	}
	cfg, err := configFrom(func(string) string { return "" }) // defaults only, whatever the shell has set
	if err != nil {
		t.Fatal(err)
	}
	cfg.BootstrapPassword = testBootstrapPassword
	cfg.MaxSessions = 0 // tests sign the same user in many times; sessions_test.go sets the limit it checks
	cfg.DataDir = t.TempDir()
	s, err := newServer(ctx, cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mkUser inserts an SSO user with the given system role ("", "admin" or "security").
func mkUser(t *testing.T, s *server, username, systemRole string) *user {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := s.db.QueryRow(ctx, `insert into users(username, name, email, source, oidc_sub, system_role)
		values($1, $1, $1 || '@example.internal', 'sso', $1, $2) returning id`, username, systemRole).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.loadUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// loginAs starts a session for u directly, without a password, and returns its cookie.
func loginAs(t *testing.T, s *server, u *user) *http.Cookie {
	t.Helper()
	tok, err := s.startSession(context.Background(), u.ID, httptest.NewRequest("POST", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: tok}
}

// do sends a request through the full middleware chain.
// body: nil, []byte or string (sent raw), or anything else (sent as JSON).
// auth: *http.Cookie, string (an API token, sent as Bearer), or http.Header (merged into the request headers).
// Without an http.Header argument the request carries Sec-Fetch-Site: same-origin, as a browser on the site would.
func do(t *testing.T, s *server, method, path string, body any, auth ...any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	isJSON := false
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd, isJSON = bytes.NewReader(j), true
	}
	req := httptest.NewRequest(method, path, rd)
	if isJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	headers := false
	for _, a := range auth {
		switch v := a.(type) {
		case *http.Cookie:
			req.AddCookie(v)
		case string:
			req.Header.Set("Authorization", "Bearer "+v)
		case http.Header:
			headers = true
			for k, vs := range v {
				req.Header[http.CanonicalHeaderKey(k)] = vs
			}
		default:
			t.Fatalf("do: unsupported auth argument %T", a)
		}
	}
	if !headers {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// errCode returns the "error" field of a JSON error response.
func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct{ Error, Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("not a JSON error (%d): %s", rec.Code, rec.Body.String())
	}
	return e.Error
}
