package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeKC is one httptest server acting as the OIDC provider and the Keycloak Admin API for one realm.
type fakeKC struct {
	*httptest.Server
	key              *rsa.PrivateKey
	iss              string
	nonce, challenge string         // from the last /sso/start redirect
	user, sub        string         // who logs in next
	claims           map[string]any // more ID token claims (groups, department, ...)
	access           map[string]any // more access token claims (realm_access, resource_access)
	tree             []map[string]any
	member           map[string][]map[string]any // group id -> members
	users            []map[string]any
	userLookups      int
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newFakeKC serves the realm at prefix, e.g. "/realms/jasca" or the old "/auth/realms/master".
func newFakeKC(t *testing.T, prefix string) *fakeKC {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeKC{key: key, member: map[string][]map[string]any{}}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	f.iss = f.URL + prefix
	admin, err := adminBase(f.iss)
	if err != nil {
		t.Fatal(err)
	}
	admin = strings.TrimPrefix(admin, f.URL)
	js := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	jwt := func(claims map[string]any) string {
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
		c, _ := json.Marshal(claims)
		in := b64(h) + "." + b64(c)
		sum := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		return in + "." + b64(sig)
	}
	mux.HandleFunc(prefix+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"issuer": f.iss, "authorization_endpoint": f.iss + "/protocol/openid-connect/auth",
			"token_endpoint": f.iss + "/protocol/openid-connect/token", "jwks_uri": f.iss + "/certs",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc(prefix+"/certs", func(w http.ResponseWriter, r *http.Request) {
		js(w, map[string]any{"keys": []map[string]any{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1})}}})
	})
	mux.HandleFunc(prefix+"/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if r.Form.Get("grant_type") == "client_credentials" {
			if id != "jasca-sync" || secret != "sync-secret" {
				http.Error(w, "bad client", 401)
				return
			}
			js(w, map[string]any{"access_token": "admin-tok", "token_type": "Bearer", "expires_in": 60})
			return
		}
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if id != "jasca" || secret != "sso-secret" || r.Form.Get("code") != "c" || b64(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := time.Now()
		sub := f.sub
		if sub == "" {
			sub = f.user
		}
		idc := map[string]any{"iss": f.iss, "sub": sub, "aud": "jasca", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
			"nonce": f.nonce, "preferred_username": f.user, "email": f.user + "@example.internal"}
		for k, v := range f.claims {
			idc[k] = v
		}
		atc := map[string]any{"iss": f.iss, "sub": sub, "aud": "account", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}
		for k, v := range f.access {
			atc[k] = v
		}
		js(w, map[string]any{"access_token": jwt(atc), "token_type": "Bearer", "expires_in": 300, "id_token": jwt(idc)})
	})
	adm := func(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer admin-tok" {
				http.Error(w, "unauthorized", 401)
				return
			}
			h(w, r)
		}
	}
	page := func(r *http.Request, all []map[string]any) []map[string]any {
		var first, max int
		fmt.Sscan(r.URL.Query().Get("first"), &first)
		if fmt.Sscan(r.URL.Query().Get("max"), &max); max == 0 {
			max = 100
		}
		first = min(first, len(all))
		return all[first:min(first+max, len(all))]
	}
	mux.HandleFunc(admin+"/groups", adm(func(w http.ResponseWriter, r *http.Request) { js(w, page(r, f.tree)) }))
	mux.HandleFunc(admin+"/groups/{id}/members", adm(func(w http.ResponseWriter, r *http.Request) {
		js(w, page(r, f.member[r.PathValue("id")]))
	}))
	mux.HandleFunc(admin+"/users", adm(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("username")
		if q != "" {
			f.userLookups++
		}
		out := []map[string]any{}
		for _, u := range f.users {
			if q == "" || u["username"] == q {
				out = append(out, u)
			}
		}
		js(w, page(r, out))
	}))
	return f
}

// configureSSO points s at kc (login client "jasca", sync client "jasca-sync").
func configureSSO(t *testing.T, s *server, kc *fakeKC) {
	t.Helper()
	ctx := context.Background()
	if err := s.putSetting(ctx, "sso", ssoSettings{Enabled: true, Issuer: kc.iss, ClientID: "jasca", ClientSecret: "sso-secret",
		AdminRole: "jasca-admin", SecurityRole: "jasca-security"}); err != nil {
		t.Fatal(err)
	}
	if err := s.putSetting(ctx, "sync", syncSettings{ClientID: "jasca-sync", ClientSecret: "sync-secret"}); err != nil {
		t.Fatal(err)
	}
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ssoStart begins a login and returns the state cookie and the Keycloak redirect, remembering nonce and challenge in kc.
func ssoStart(t *testing.T, s *server, kc *fakeKC, next string) (*http.Cookie, *url.URL) {
	t.Helper()
	rec := do(t, s, "GET", "/api/v1/auth/sso/start?next="+url.QueryEscape(next), nil)
	if rec.Code != 302 {
		t.Fatalf("sso start: %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), kc.iss+"/protocol/openid-connect/auth") {
		t.Fatalf("sso start redirect: %v", loc)
	}
	kc.nonce, kc.challenge = loc.Query().Get("nonce"), loc.Query().Get("code_challenge")
	st := cookieNamed(rec, ssoCookie)
	if st == nil || !st.HttpOnly {
		t.Fatalf("no httpOnly state cookie: %v", rec.Result().Cookies())
	}
	return st, loc
}

// The login returns to the page it started from, with its #section.
func TestSSOCallbackKeepsHash(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	st, loc := ssoStart(t, s, kc, "/projects/a/settings#tokens")
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/projects/a/settings#tokens" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// ssoLogin runs the whole login as kc.user and returns the session cookie.
func ssoLogin(t *testing.T, s *server, kc *fakeKC) *http.Cookie {
	t.Helper()
	st, loc := ssoStart(t, s, kc, "/projects")
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/projects" {
		t.Fatalf("callback: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	sc := cookieNamed(rec, sessionCookie)
	if sc == nil {
		t.Fatal("no session cookie")
	}
	return sc
}

func userID(t *testing.T, s *server, username string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(context.Background(), `select id from users where username=$1`, username).Scan(&id); err != nil {
		t.Fatalf("user %s: %v", username, err)
	}
	return id
}

func memberships(t *testing.T, s *server, username string) (groups, depts []string) {
	t.Helper()
	g, d, err := s.groupsFor(context.Background(), userID(t, s, username))
	if err != nil {
		t.Fatal(err)
	}
	return g, d
}

func TestAuthConfig(t *testing.T) {
	s := testServer(t)
	var out struct {
		SSOEnabled bool   `json:"sso_enabled"`
		TZ         string `json:"tz"`
		Version    string `json:"version"`
	}
	rec := do(t, s, "GET", "/api/v1/auth/config", nil)
	if json.Unmarshal(rec.Body.Bytes(), &out); rec.Code != 200 || out.SSOEnabled || out.TZ != "Asia/Seoul" || out.Version != version {
		t.Fatalf("unconfigured: %d %s", rec.Code, rec.Body.String())
	}
	configureSSO(t, s, newFakeKC(t, "/realms/jasca"))
	rec = do(t, s, "GET", "/api/v1/auth/config", nil)
	if json.Unmarshal(rec.Body.Bytes(), &out); !out.SSOEnabled {
		t.Fatalf("configured: %s", rec.Body.String())
	}
	// the web asks here (a public 200) whether to load /me, so a signed-out visit logs no 401
	var si struct {
		SignedIn *bool `json:"signed_in"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &si); si.SignedIn == nil || *si.SignedIn {
		t.Fatalf("signed out: %s", rec.Body.String())
	}
	rec = do(t, s, "GET", "/api/v1/auth/config", nil, loginAs(t, s, mkUser(t, s, "kim", "")))
	if json.Unmarshal(rec.Body.Bytes(), &si); si.SignedIn == nil || !*si.SignedIn {
		t.Fatalf("signed in: %s", rec.Body.String())
	}
}

// Signed-in users learn whether AI is on and the scan upload limit, nothing else about the AI settings; signed-out callers
// neither (they are told the version only).
func TestAuthConfigInstanceFields(t *testing.T) {
	s := testServer(t)
	get := func(opts ...any) map[string]any {
		t.Helper()
		rec, out := do(t, s, "GET", "/api/v1/auth/config", nil, opts...), map[string]any{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	if err := s.putSetting(context.Background(), "ai", aiSettings{BaseURL: "http://ai.example.test/v1", Model: "m", APIKey: "sk-secret-key", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if out := get(); out["ai_enabled"] != nil || out["max_scan_upload_mb"] != nil {
		t.Fatalf("signed out sees instance fields: %v", out)
	}
	kim := loginAs(t, s, mkUser(t, s, "kim", ""))
	out := get(kim)
	if out["ai_enabled"] != true || out["max_scan_upload_mb"] != float64(s.cfg.MaxScanUploadMB) || len(out) != 7 {
		t.Fatalf("signed in, AI on: %v", out)
	}
	if err := s.putSetting(context.Background(), "ai", aiSettings{BaseURL: "http://ai.example.test/v1", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if out := get(kim); out["ai_enabled"] != false {
		t.Fatalf("signed in, AI off: %v", out)
	}
}

func TestSSOStartRejectsExternalNext(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	for next, want := range map[string]string{"//evil.example": "/", "https://evil.example": "/", `/\evil`: "/",
		"/x/../\\evil": "/", "": "/", "/projects/a?tab=1": "/projects/a?tab=1", "/\t/evil.example": "/",
		"/projects/a/settings#tokens": "/projects/a/settings#tokens"} { // the page the session ended on, section included
		st, loc := ssoStart(t, s, kc, next)
		var o ssoState
		if !s.unsigned(st.Value, &o) || o.Next != want {
			t.Errorf("next %q: stored %q, want %q", next, o.Next, want)
		}
		if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("state") != o.State || o.Nonce == "" {
			t.Errorf("redirect lacks PKCE/state/nonce: %v", loc)
		}
		if want := "http://example.com/api/v1/auth/sso/callback"; loc.Query().Get("redirect_uri") != want {
			t.Errorf("redirect_uri %q", loc.Query().Get("redirect_uri"))
		}
	}
}

func TestSSOStartDisabled(t *testing.T) {
	s := testServer(t)
	rec := do(t, s, "GET", "/api/v1/auth/sso/start", nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=sso" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSSOCallbackCreatesUser(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user, kc.sub = "kim", "kc-id-kim"
	kc.claims = map[string]any{"department": "보안실/취약점팀", "groups": []string{"/dev"}, "given_name": "민수", "family_name": "김"}
	sc := ssoLogin(t, s, kc)
	var source, name, email string
	var sub *string
	var fromSSO bool
	if err := s.db.QueryRow(context.Background(), `select source, name, email, oidc_sub, role_from_sso from users where username='kim'`).
		Scan(&source, &name, &email, &sub, &fromSSO); err != nil {
		t.Fatal(err)
	}
	if source != "sso" || name != "김민수" || email != "kim@example.internal" || sub == nil || *sub != "kc-id-kim" || !fromSSO {
		t.Fatalf("user row: %s %s %s %v %v", source, name, email, sub, fromSSO)
	}
	g, d := memberships(t, s, "kim")
	if !reflect.DeepEqual(g, []string{"/dev"}) || !reflect.DeepEqual(d, []string{"/보안실", "/보안실/취약점팀"}) {
		t.Fatalf("groups %v depts %v", g, d)
	}
	var me user
	rec := do(t, s, "GET", "/api/v1/me", nil, sc)
	if json.Unmarshal(rec.Body.Bytes(), &me); rec.Code != 200 || !reflect.DeepEqual(me.Depts, d) || !reflect.DeepEqual(me.Groups, g) {
		t.Fatalf("/me: %d %s", rec.Code, rec.Body.String())
	}

	// a second login matches the same row by sub; a groups claim without full paths keeps the stored groups
	kc.claims = map[string]any{"groups": []string{"dev"}, "department": []string{"보안실/취약점팀", "기획실"}}
	ssoLogin(t, s, kc)
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from users where source='sso'`).Scan(&n)
	g, d = memberships(t, s, "kim")
	if n != 1 || !reflect.DeepEqual(g, []string{"/dev"}) || !reflect.DeepEqual(d, []string{"/기획실", "/보안실", "/보안실/취약점팀"}) {
		t.Fatalf("second login: users %d groups %v depts %v", n, g, d)
	}

	// the diagnostics table shows both logins, newest first
	admin := loginAs(t, s, mkUser(t, s, "boss", "admin"))
	var logins []loginDept
	rec = do(t, s, "GET", "/api/v1/admin/sync/logins", nil, admin)
	if json.Unmarshal(rec.Body.Bytes(), &logins); len(logins) != 2 || logins[0].Source != "claim" || len(logins[0].Depts) != 2 {
		t.Fatalf("logins: %s", rec.Body.String())
	}
}

func TestSSOStateMismatch(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "kim"
	st, loc := ssoStart(t, s, kc, "/")
	state := loc.Query().Get("state")
	forged := *st
	forged.Value = st.Value[:len(st.Value)-3] + "AAA"
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"wrong state":     do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state=nope", nil, st),
		"missing cookie":  do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(state), nil),
		"forged cookie":   do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(state), nil, &forged),
		"missing state":   do(t, s, "GET", "/api/v1/auth/sso/callback?code=c", nil, st),
		"other site's ck": do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(state), nil, &http.Cookie{Name: ssoCookie, Value: "x.y"}),
	} {
		if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=state" || cookieNamed(rec, sessionCookie) != nil {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from users where source='sso'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d sso users created", n)
	}
}

// The state cookie's expiry is inside the signed payload, so an old cookie fails even if the browser kept it.
func TestSSOStateExpires(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "kim"
	st, loc := ssoStart(t, s, kc, "/")
	var o ssoState
	if !s.unsigned(st.Value, &o) || o.Exp < time.Now().Add(9*time.Minute).Unix() || o.Exp > time.Now().Add(11*time.Minute).Unix() {
		t.Fatalf("exp %d is not about 10 minutes away", o.Exp)
	}
	o.Exp = time.Now().Add(-time.Second).Unix()
	old := &http.Cookie{Name: ssoCookie, Value: s.signed(o)}
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, old)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=state" || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("expired state: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSSOWrongNonceOrVerifier(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "kim"
	st, loc := ssoStart(t, s, kc, "/")
	kc.nonce = "replayed"
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=sso" || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("wrong nonce: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	st, loc = ssoStart(t, s, kc, "/")
	kc.challenge = "other"
	rec = do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=sso" {
		t.Fatalf("wrong verifier: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSSOLocalUsernameConflict(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "admin"
	st, loc := ssoStart(t, s, kc, "/")
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=conflict" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSSORoleMapping(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "kim"
	role := func() string {
		t.Helper()
		var r string
		s.db.QueryRow(context.Background(), `select system_role from users where username='kim'`).Scan(&r)
		return r
	}
	kc.access = map[string]any{"resource_access": map[string]any{"jasca": map[string]any{"roles": []string{"jasca-admin"}}}}
	ssoLogin(t, s, kc)
	if r := role(); r != "admin" {
		t.Fatalf("client role: %q", r)
	}
	kc.access = nil
	ssoLogin(t, s, kc)
	if r := role(); r != "" {
		t.Fatalf("after removal: %q", r)
	}
	kc.access = map[string]any{"realm_access": map[string]any{"roles": []string{"jasca-security"}}}
	ssoLogin(t, s, kc)
	if r := role(); r != "security" {
		t.Fatalf("realm role: %q", r)
	}
	// a client role of another client does not count
	kc.access = map[string]any{"resource_access": map[string]any{"other": map[string]any{"roles": []string{"jasca-admin"}}}}
	ssoLogin(t, s, kc)
	if r := role(); r != "" {
		t.Fatalf("other client: %q", r)
	}
	// an admin's override (role_from_sso=false) survives logins
	s.db.Exec(context.Background(), `update users set system_role='security', role_from_sso=false where username='kim'`)
	ssoLogin(t, s, kc)
	if r := role(); r != "security" {
		t.Fatalf("override: %q", r)
	}

	// old Keycloak: /auth path, master realm, master-realm client roles
	s2 := testServer(t)
	old := newFakeKC(t, "/auth/realms/master")
	configureSSO(t, s2, old)
	old.user = "lee"
	old.access = map[string]any{"resource_access": map[string]any{"master-realm": map[string]any{"roles": []string{"jasca-admin"}}}}
	ssoLogin(t, s2, old)
	var r string
	s2.db.QueryRow(context.Background(), `select system_role from users where username='lee'`).Scan(&r)
	if r != "admin" {
		t.Fatalf("master-realm role: %q", r)
	}
}

// R4a: a department path that is also a known Keycloak group path never grants that group, nor does a parent.
func TestDeptCannotGrantGroup(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user, kc.claims = "lee", map[string]any{"groups": []string{"/보안실"}}
	ssoLogin(t, s, kc) // makes /보안실 a known Keycloak group
	kc.user, kc.claims = "kim", map[string]any{"groups": []string{}, "department": []string{"보안실/취약점팀", "보안실", "기획실"}}
	ssoLogin(t, s, kc)
	g, d := memberships(t, s, "kim")
	if len(g) != 0 || !reflect.DeepEqual(d, []string{"/기획실", "/보안실/취약점팀"}) {
		t.Fatalf("groups %v depts %v", g, d)
	}
	// a group the sync later marks deleted still blocks the department
	s.db.Exec(context.Background(), `update kc_groups set deleted=true where path='/보안실'`)
	if _, d = memberships(t, s, "kim"); !reflect.DeepEqual(d, []string{"/기획실", "/보안실/취약점팀"}) {
		t.Fatalf("deleted group: depts %v", d)
	}
}

func TestDeptValueLimits(t *testing.T) {
	var many []string
	for i := range 12 {
		many = append(many, fmt.Sprintf("부서%d", i))
	}
	if got := deptPaths(many); len(got) != maxDepts {
		t.Errorf("kept %d values", len(got))
	}
	deep := strings.Repeat("a/", 12) + "z"
	if got := deptPaths([]string{deep}); len(got) != 1 || strings.Count(got[0], "/") != maxDeptLevels {
		t.Errorf("levels: %v", got)
	}
	if got := deptPaths([]string{"a\nb", strings.Repeat("x", 151), " / ", " 보안실 / 팀 "}); !reflect.DeepEqual(got, []string{"/보안실/팀"}) {
		t.Errorf("validation: %v", got)
	}
}

func TestDeptFromAdminAPIAndOff(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	kc.user = "kim"
	kc.users = []map[string]any{{"id": "kim", "username": "kim", "enabled": true, "attributes": map[string][]string{"department": {"보안실"}}}}
	ssoLogin(t, s, kc) // no department claim: read this user from the Admin API
	if _, d := memberships(t, s, "kim"); !reflect.DeepEqual(d, []string{"/보안실"}) || kc.userLookups != 1 {
		t.Fatalf("admin api depts %v lookups %d", d, kc.userLookups)
	}
	admin := loginAs(t, s, mkUser(t, s, "boss", "admin"))
	var logins []loginDept
	rec := do(t, s, "GET", "/api/v1/admin/sync/logins", nil, admin)
	if json.Unmarshal(rec.Body.Bytes(), &logins); len(logins) != 1 || logins[0].Source != "admin_api" || logins[0].User != "kim" {
		t.Fatalf("logins: %s", rec.Body.String())
	}
	// a renamed attribute is read from the claim of that name
	if rec := do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"dept_attribute": "org"}, admin); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	kc.claims = map[string]any{"org": "기획실", "department": "무시"}
	ssoLogin(t, s, kc)
	if _, d := memberships(t, s, "kim"); !reflect.DeepEqual(d, []string{"/기획실"}) {
		t.Fatalf("renamed attribute: %v", d)
	}
	// turning departments off clears them at once, and logins store none
	if rec := do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"dept_off": true}, admin); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if _, d := memberships(t, s, "kim"); len(d) != 0 {
		t.Fatalf("after off: %v", d)
	}
	ssoLogin(t, s, kc)
	if _, d := memberships(t, s, "kim"); len(d) != 0 {
		t.Fatalf("login while off: %v", d)
	}
}

func TestAdminSSONeverReturnsSecret(t *testing.T) {
	s := testServer(t)
	admin := loginAs(t, s, mkUser(t, s, "boss", "admin"))
	body := map[string]any{"enabled": true, "issuer": "https://sso.example.internal/auth/realms/master/", "client_id": "jasca",
		"client_secret": "s3cret", "admin_role": "jasca-admin", "security_role": "jasca-security", "public_url": "https://jasca.example.internal/"}
	if rec := do(t, s, "PUT", "/api/v1/admin/sso", body, admin); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	get := func(path string) map[string]any {
		t.Helper()
		rec := do(t, s, "GET", path, nil, admin)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
			t.Fatalf("get %s: %d %s", path, rec.Code, rec.Body.String())
		}
		if _, ok := out["client_secret"]; ok || strings.Contains(rec.Body.String(), "s3cret") {
			t.Fatalf("%s leaks the secret: %s", path, rec.Body.String())
		}
		return out
	}
	out := get("/api/v1/admin/sso")
	if out["client_secret_set"] != true || out["issuer"] != "https://sso.example.internal/auth/realms/master" ||
		out["public_url"] != "https://jasca.example.internal" || out["admin_role"] != "jasca-admin" {
		t.Fatalf("get: %v", out)
	}
	// the UI sends the form back with an empty secret: the stored one stays
	out["client_secret"], out["client_id"] = "", "jasca2"
	if rec := do(t, s, "PUT", "/api/v1/admin/sso", out, admin); rec.Code != 200 {
		t.Fatalf("put empty secret: %d %s", rec.Code, rec.Body.String())
	}
	var st ssoSettings
	s.getSetting(context.Background(), "sso", &st)
	if st.ClientSecret != "s3cret" || st.ClientID != "jasca2" {
		t.Fatalf("stored: %+v", st)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/sso", map[string]any{"issuer": "ftp://x"}, admin); rec.Code != 400 {
		t.Fatalf("bad issuer: %d", rec.Code)
	}

	if rec := do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"client_id": "jasca-sync", "client_secret": "s3cret", "interval_min": 5}, admin); rec.Code != 200 {
		t.Fatalf("put sync: %d %s", rec.Code, rec.Body.String())
	}
	sy := get("/api/v1/admin/sync")
	if sy["client_secret_set"] != true || sy["interval_min"] != 5.0 || sy["dept_off"] != false {
		t.Fatalf("sync: %v", sy)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/sync", map[string]any{"client_secret": "", "interval_min": 0}, admin); rec.Code != 400 {
		t.Fatalf("interval 0: %d", rec.Code)
	}
	user := loginAs(t, s, mkUser(t, s, "kim", ""))
	for _, p := range []string{"/api/v1/admin/sso", "/api/v1/admin/sync", "/api/v1/admin/sync/logins"} {
		if rec := do(t, s, "GET", p, nil, user); rec.Code != 403 {
			t.Errorf("%s as user: %d", p, rec.Code)
		}
	}
}

// A different Keycloak identity with a reused username never inherits the old row (memberships, admin role).
func TestSSOUsernameReuseRefused(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	ctx := context.Background()
	old := mkUser(t, s, "alice", "") // oidc_sub = "alice"
	sqlExec(t, s, `update users set system_role='security', role_from_sso=false where id=$1`, old.ID)
	if _, _, _, _, err := s.ssoUpsert(ctx, "a-different-keycloak-user", "alice", "New Alice", "new@example.internal", ""); !errors.Is(err, errIdentityConflict) {
		t.Fatalf("upsert with another sub: %v", err)
	}
	kc.user, kc.sub = "alice", "a-different-keycloak-user"
	st, loc := ssoStart(t, s, kc, "/")
	rec := do(t, s, "GET", "/api/v1/auth/sso/callback?code=c&state="+url.QueryEscape(loc.Query().Get("state")), nil, st)
	if rec.Code != 302 || rec.Header().Get("Location") != "/login?error=identity" || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var sub, role string
	s.db.QueryRow(ctx, `select oidc_sub, system_role from users where id=$1`, old.ID).Scan(&sub, &role)
	if sub != "alice" || role != "security" {
		t.Fatalf("old row changed: sub %q role %q", sub, role)
	}

	// once an admin deactivates the old account, the new person gets a fresh row and the old one is renamed
	sqlExec(t, s, `update users set active=false where id=$1`, old.ID)
	ssoLogin(t, s, kc)
	var id int64
	s.db.QueryRow(ctx, `select id, system_role from users where username='alice'`).Scan(&id, &role)
	var oldName string
	s.db.QueryRow(ctx, `select username from users where id=$1`, old.ID).Scan(&oldName)
	if id == old.ID || role != "" || oldName == "alice" {
		t.Fatalf("new row %d (old %d) role %q, old name %q", id, old.ID, role, oldName)
	}

	// a row without a stored sub (made before subs were recorded) is still found by username
	sqlExec(t, s, `insert into users(username, name, source) values('bob', 'bob', 'sso')`)
	bob := userID(t, s, "bob")
	kc.user, kc.sub = "bob", "kc-bob"
	ssoLogin(t, s, kc)
	if userID(t, s, "bob") != bob {
		t.Fatal("null-sub row not adopted")
	}
}
