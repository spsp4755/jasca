package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecretKey = "0123456789abcdef0123456789abcdef-test"

func TestSecretKeyConfig(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string { return map[string]string{"JASCA_SECRET_KEY": v}[k] }
	}
	for _, bad := range []string{"CHANGE_ME", "short", strings.Repeat("k", 31)} {
		if _, err := configFrom(get(bad)); err == nil || !strings.Contains(err.Error(), "JASCA_SECRET_KEY") {
			t.Errorf("key %q accepted: %v", bad, err)
		}
	}
	if c, err := configFrom(get(strings.Repeat("k", 32))); err != nil || c.SecretKey == "" {
		t.Errorf("32 characters refused: %v", err)
	}
	if c, err := configFrom(get("")); err != nil || c.SecretKey != "" {
		t.Errorf("no key must stay allowed: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	s := &server{aead: newAEAD(testSecretKey)}
	a, b := s.seal("p@ss word"), s.seal("p@ss word")
	if a == b || !strings.HasPrefix(a, encPrefix) || strings.Contains(a, "p@ss") {
		t.Fatalf("seal: %q %q", a, b)
	}
	if p, ok := s.open(a); !ok || p != "p@ss word" {
		t.Errorf("open: %q %v", p, ok)
	}
	if s.seal(a) != a || s.seal("") != "" {
		t.Error("sealing twice or sealing nothing changed the value")
	}
	if p, ok := s.open("plain"); !ok || p != "plain" {
		t.Errorf("a plain stored value: %q %v", p, ok)
	}
	for name, other := range map[string]*server{"another key": {aead: newAEAD(testSecretKey + "x")}, "no key": {}} {
		if p, ok := other.open(a); ok || p != "" {
			t.Errorf("%s opened it: %q", name, p)
		}
	}
	if p, ok := s.open(encPrefix + "!!"); ok || p != "" {
		t.Errorf("garbage opened: %q", p)
	}
	if (&server{}).seal("x") != "x" {
		t.Error("without a key values must stay as they are")
	}
}

// storedSecretsText is everything in the database that may hold a secret, as text.
func storedSecretsText(t *testing.T, s *server) string {
	t.Helper()
	var out string
	if err := s.db.QueryRow(context.Background(), `select coalesce((select string_agg(value::text, ' ' order by key) from settings), '') || ' ' ||
		coalesce((select string_agg(config::text, ' ' order by id) from notify_channels), '')`).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// setAllSecrets saves one secret through every admin route that takes one and returns them by name.
func setAllSecrets(t *testing.T, s *server, admin *http.Cookie, hook string) map[string]string {
	t.Helper()
	sec := map[string]string{"sso": "SSO-CLIENT-S3CRET", "sync": "SYNC-CLIENT-S3CRET", "smtp": "SMTP-PASSW0RD", "ai": "sk-AI-KEY-S3CRET", "channel": hook}
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/sso", map[string]any{"issuer": "https://sso.example.internal/realms/x", "client_id": "jasca", "client_secret": sec["sso"]}, admin), 200, "put sso")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"client_id": "jasca-sync", "client_secret": sec["sync"]}, admin), 200, "put sync")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/smtp", map[string]any{"host": "smtp.example.internal", "port": 587, "username": "u", "password": sec["smtp"], "from": "j@example.internal", "tls": "starttls"}, admin), 204, "put smtp")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/ai", map[string]any{"base_url": "http://llm.example.internal/v1", "model": "m", "api_key": sec["ai"]}, admin), 200, "put ai")
	wantCode(t, do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "mattermost", "name": "mm", "enabled": true, "config": map[string]any{"webhook_url": hook}}, admin), 201, "create channel")
	return sec
}

// readSecrets is what each consumer gets from its settings.
func readSecrets(t *testing.T, s *server) map[string]string {
	t.Helper()
	ctx := context.Background()
	sso, err1 := s.ssoConf(ctx)
	sy, err2 := s.syncConf(ctx)
	smtp, err3 := s.smtpConf(ctx)
	ai, err4 := s.aiConf(ctx)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		t.Fatal(err1, err2, err3, err4)
	}
	if sso.ClientID != "jasca" || sy.ClientID != "jasca-sync" || smtp.Host != "smtp.example.internal" || ai.Model != "m" {
		t.Errorf("the other fields did not survive: %+v %+v %+v %+v", sso.ClientID, sy.ClientID, smtp.Host, ai.Model)
	}
	return map[string]string{"sso": sso.ClientSecret, "sync": sy.ClientSecret, "smtp": smtp.Password, "ai": ai.APIKey}
}

func setFlags(t *testing.T, s *server, admin *http.Cookie) string {
	t.Helper()
	var b strings.Builder
	for _, p := range []string{"sso", "sync", "smtp", "ai", "channels"} {
		rec := do(t, s, "GET", "/api/v1/admin/"+p, nil, admin)
		wantCode(t, rec, 200, "get "+p)
		b.WriteString(rec.Body.String())
	}
	return b.String()
}

// With a key every secret is stored encrypted, each consumer still gets the plain value, a form saved without
// retyping the secret keeps it, and nothing comes back through the API.
func TestSecretsEncryptedAtRest(t *testing.T) {
	s := testServer(t)
	s.aead = newAEAD(testSecretKey)
	admin := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	sec := setAllSecrets(t, s, admin, srv.URL+"/hooks/t0ken-xyz")

	stored := storedSecretsText(t, s)
	for name, v := range sec {
		if strings.Contains(stored, v) || strings.Contains(stored, "t0ken-xyz") {
			t.Errorf("%s is stored as plain text", name)
		}
	}
	if n := strings.Count(stored, encPrefix); n != 5 {
		t.Errorf("%d encrypted values stored, want 5: %s", n, stored)
	}
	got := readSecrets(t, s)
	for _, name := range []string{"sso", "sync", "smtp", "ai"} {
		if got[name] != sec[name] {
			t.Errorf("%s reads %q", name, got[name])
		}
	}
	// the webhook is decrypted where it is used
	rec := do(t, s, "POST", "/api/v1/admin/channels/1/test", nil, admin)
	if wantCode(t, rec, 200, "channel test"); hits != 1 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("test message did not reach the webhook: %d %s", hits, rec.Body.String())
	}

	// saving each form again without the secret keeps the stored one
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/sso", map[string]any{"admin_role": "jasca-admin"}, admin), 200, "put sso again")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"interval_min": 30, "client_secret": ""}, admin), 200, "put sync again")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/smtp", map[string]any{"host": "smtp.example.internal", "port": 25, "username": "u", "from": "j@example.internal", "tls": "none"}, admin), 204, "put smtp again")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/ai", map[string]any{"model": "m", "api_key": ""}, admin), 200, "put ai again")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/channels/1", map[string]any{"kind": "mattermost", "name": "mm2", "enabled": true}, admin), 204, "put channel again")
	got = readSecrets(t, s)
	for _, name := range []string{"sso", "sync", "smtp", "ai"} {
		if got[name] != sec[name] {
			t.Errorf("%s after saving the form without it: %q", name, got[name])
		}
	}
	if do(t, s, "POST", "/api/v1/admin/channels/1/test", nil, admin); hits != 2 {
		t.Error("the webhook was lost by a save without it")
	}
	flags := setFlags(t, s, admin)
	if strings.Count(flags, `_set":true`) != 5 || strings.Contains(flags, encPrefix) {
		t.Errorf("the screens must say every secret is set and never show it: %s", flags)
	}
	for name, v := range sec {
		if strings.Contains(flags, v) {
			t.Errorf("%s came back through the API", name)
		}
	}
	if mode, total, bad, err := s.secretsState(context.Background()); err != nil || mode != "encrypted" || total != 5 || bad != 0 {
		t.Errorf("secretsState = %s %d %d %v", mode, total, bad, err)
	}
}

// An upgrade: values saved without a key are encrypted by the first start with one, once.
func TestSecretsEncryptedAtStart(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	admin := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	sec := setAllSecrets(t, s, admin, "http://mm.example.internal/hooks/t0ken-xyz")
	plain := storedSecretsText(t, s)
	if strings.Contains(plain, encPrefix) || !strings.Contains(plain, sec["smtp"]) {
		t.Fatalf("without a key the values must be stored as before: %s", plain)
	}
	if mode, total, bad, _ := s.secretsState(ctx); mode != "plain" || total != 5 || bad != 0 {
		t.Errorf("secretsState without a key = %s %d %d", mode, total, bad)
	}
	var hmacBefore string
	s.db.QueryRow(ctx, `select value::text from settings where key = 'hmac_secret'`).Scan(&hmacBefore)

	s.aead = newAEAD(testSecretKey)
	if err := s.encryptStored(ctx); err != nil {
		t.Fatal(err)
	}
	first := storedSecretsText(t, s)
	for name, v := range sec {
		if strings.Contains(first, v) || strings.Contains(first, "t0ken-xyz") {
			t.Errorf("%s is still plain after the start: %s", name, first)
		}
	}
	if got := readSecrets(t, s); fmt.Sprint(got) != fmt.Sprint(map[string]string{"sso": sec["sso"], "sync": sec["sync"], "smtp": sec["smtp"], "ai": sec["ai"]}) {
		t.Errorf("after the start the consumers read %v", got)
	}
	var hmacAfter, to string
	s.db.QueryRow(ctx, `select value::text from settings where key = 'hmac_secret'`).Scan(&hmacAfter)
	if hmacAfter != hmacBefore {
		t.Error("hmac_secret was touched")
	}
	// a second start changes nothing, and a channel without a secret is left alone
	wantCode(t, do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "email", "name": "mail", "enabled": true, "config": map[string]any{"to": []string{"a@example.internal"}}}, admin), 201, "email channel")
	before := storedSecretsText(t, s)
	if err := s.encryptStored(ctx); err != nil {
		t.Fatal(err)
	}
	if again := storedSecretsText(t, s); again != before || !strings.HasPrefix(again, first) {
		t.Error("a second start changed values that were already encrypted")
	}
	s.db.QueryRow(ctx, `select config->'to'->>0 from notify_channels where kind = 'email'`).Scan(&to)
	if to != "a@example.internal" {
		t.Errorf("email channel config = %q", to)
	}
}

// The key is lost or wrong: the server starts, the secrets read as not set, the local admin still signs in and
// entering a secret again makes it work.
func TestSecretsWrongKey(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.aead = newAEAD(testSecretKey)
	admin := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	sec := setAllSecrets(t, s, admin, "http://mm.example.internal/hooks/t0ken-xyz")

	for name, aead := range map[string]*server{"another key": {aead: newAEAD(strings.Repeat("z", 40))}, "no key": {}} {
		s.aead = aead.aead
		if err := s.encryptStored(ctx); err != nil {
			t.Fatalf("%s: the start failed: %v", name, err)
		}
		for k, v := range readSecrets(t, s) {
			if v != "" {
				t.Errorf("%s: %s reads %q", name, k, v)
			}
		}
		if flags := setFlags(t, s, admin); strings.Contains(flags, `_set":true`) {
			t.Errorf("%s: a screen says a secret is set: %s", name, flags)
		}
		rec := do(t, s, "POST", "/api/v1/admin/channels/1/test", nil, admin)
		if !strings.Contains(rec.Body.String(), "Webhook URL이 설정되지 않았습니다") {
			t.Errorf("%s: channel test: %s", name, rec.Body.String())
		}
		if _, total, bad, _ := s.secretsState(ctx); total != 5 || bad != 5 {
			t.Errorf("%s: secretsState = %d %d", name, total, bad)
		}
		if code, _, body := login(t, s, "admin", testBootstrapPassword); code != 200 {
			t.Errorf("%s: the local admin cannot sign in: %d %s", name, code, body)
		}
	}
	if n := strings.Count(storedSecretsText(t, s), encPrefix); n != 5 {
		t.Errorf("unreadable values were rewritten: %d left", n)
	}

	// with another key: entered again, it is stored under that key and read back; the others stay unreadable
	s.aead = newAEAD(strings.Repeat("z", 40))
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/sso", map[string]any{"client_secret": "NEW-S3CRET"}, admin), 200, "enter again")
	if got := readSecrets(t, s); got["sso"] != "NEW-S3CRET" || got["ai"] != "" {
		t.Errorf("after entering it again: %v", got)
	}
	if _, total, bad, _ := s.secretsState(ctx); total != 5 || bad != 4 {
		t.Errorf("secretsState after one was entered again = %d %d", total, bad)
	}
	// the right key back: what was not overwritten is readable again
	s.aead = newAEAD(testSecretKey)
	if got := readSecrets(t, s); got["ai"] != sec["ai"] || got["sso"] != "" {
		t.Errorf("with the first key back: %v", got)
	}
}

// The 시스템 상태 row: nothing stored is fine, plain storage is a warning, an unreadable secret is a problem that alerts.
func TestSecretsStatusRow(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	row := func() sysCheck {
		for _, c := range s.systemChecks(ctx, &sysInfo{}, time.Now()) {
			if c.Key == "secrets" {
				return c
			}
		}
		t.Fatal("no secrets row")
		return sysCheck{}
	}
	if c := row(); c.State != "ok" || c.Action != "" {
		t.Errorf("nothing stored: %+v", c)
	}
	if err := s.mergeSetting(ctx, "smtp", map[string]string{"password": "pw-plain"}); err != nil {
		t.Fatal(err)
	}
	if c := row(); c.State != "warn" || c.Action == "" || c.alert {
		t.Errorf("stored plain: %+v", c)
	}
	s.aead = newAEAD(testSecretKey)
	if err := s.encryptStored(ctx); err != nil {
		t.Fatal(err)
	}
	if c := row(); c.State != "ok" || c.Action != "" {
		t.Errorf("encrypted: %+v", c)
	}
	s.aead = newAEAD(strings.Repeat("z", 40))
	if c := row(); c.State != "bad" || c.Action == "" || !c.alert {
		t.Errorf("another key: %+v", c)
	}
}
