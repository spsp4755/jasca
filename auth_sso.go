package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// Keycloak login: OIDC authorization code + PKCE. Keycloak 10 (the old "/auth" path,
// master realm) and current versions both work; a private CA is trusted through SSL_CERT_FILE.

// ssoSettings is settings['sso'].
type ssoSettings struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AdminRole    string `json:"admin_role"`    // Keycloak role that makes a user system admin
	SecurityRole string `json:"security_role"` // Keycloak role that makes a user security
	PublicURL    string `json:"public_url"`    // site address; "" = the one the browser used
}

func (s *server) ssoConf(ctx context.Context) (ssoSettings, error) {
	var sso ssoSettings
	_, err := s.getSetting(ctx, "sso", &sso)
	return sso, err
}

const (
	ssoCookie     = "jasca_sso"
	ssoCookiePath = "/api/v1/auth/sso"
	ssoStateTTL   = 10 * time.Minute
)

// ssoState travels in the signed state cookie. Exp is inside the signature, so an old cookie is refused even if
// the browser kept it.
type ssoState struct {
	State, Verifier, Nonce, Next string
	Exp                          int64
}

var errLocalAccount = errors.New("a local account already uses this username")

// errIdentityConflict: an active Keycloak row with another sub holds the username (a reused username).
var errIdentityConflict = errors.New("another Keycloak identity already uses this username")

func (s *server) ssoRoutes() {
	s.handle("GET /api/v1/auth/config", permPublic, func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		sso, err := s.ssoConf(r.Context())
		if err != nil {
			writeInternal(w, "auth config", err)
			return
		}
		out := map[string]any{"sso_enabled": sso.Enabled && sso.Issuer != "" && sso.ClientID != "", "tz": s.cfg.Loc.String(),
			"signed_in": c.User != nil} // lets the web skip a /me that would only 401 (a console error) when signed out
		if c.User != nil { // what the screens need to know up front; a signed-out caller learns nothing about the instance
			ai, err := s.aiConf(r.Context())
			if err != nil {
				writeInternal(w, "auth config", err)
				return
			}
			out["ai_enabled"], out["max_scan_upload_mb"] = ai.on(), s.cfg.MaxScanUploadMB
		}
		writeJSON(w, 200, out)
	})
	s.handle("GET /api/v1/auth/sso/start", permPublic, s.handleSSOStart)
	s.handle("GET /api/v1/auth/sso/callback", permPublic, s.handleSSOCallback)
	s.handle("GET /api/v1/admin/sso", permAdmin, s.handleGetSSO)
	s.handle("PUT /api/v1/admin/sso", permAdmin, s.handlePutSSO)
}

func (s *server) publicURL(r *http.Request, sso ssoSettings) string {
	if sso.PublicURL != "" {
		return sso.PublicURL
	}
	scheme := "http"
	if secure(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// oidcClient discovers the provider for the current settings (cached per issuer) and builds the login client.
func (s *server) oidcClient(r *http.Request, sso ssoSettings) (*oidc.Provider, *oauth2.Config, error) {
	if !sso.Enabled || sso.Issuer == "" || sso.ClientID == "" {
		return nil, nil, errors.New("keycloak login is off")
	}
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	p := s.providers[sso.Issuer]
	if p == nil {
		var err error
		if p, err = oidc.NewProvider(oidc.ClientContext(r.Context(), &http.Client{Timeout: 10 * time.Second}), sso.Issuer); err != nil {
			return nil, nil, err
		}
		if s.providers == nil {
			s.providers = map[string]*oidc.Provider{}
		}
		s.providers[sso.Issuer] = p
	}
	return p, &oauth2.Config{ClientID: sso.ClientID, ClientSecret: sso.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: s.publicURL(r, sso) + ssoCookiePath + "/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, nil
}

// safeNext keeps post-login redirects on this site: a local absolute path only ("\" is read as "/" by browsers).
func safeNext(next string) string {
	u, err := url.Parse(next)
	if err != nil || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}

func (s *server) handleSSOStart(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	sso, err := s.ssoConf(r.Context())
	var oc *oauth2.Config
	if err == nil {
		_, oc, err = s.oidcClient(r, sso)
	}
	if err != nil {
		log.Printf("sso start: %v", err)
		s.audit(r.Context(), c, "auth.login_failed", nil, "", map[string]any{"method": "sso", "reason": "sso", "step": "start"})
		http.Redirect(w, r, "/login?error=sso", http.StatusFound)
		return
	}
	o := ssoState{State: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(),
		Next: safeNext(r.URL.Query().Get("next")), Exp: time.Now().Add(ssoStateTTL).Unix()}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: s.signed(o), Path: ssoCookiePath, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure(r), MaxAge: int(ssoStateTTL.Seconds())})
	http.Redirect(w, r, oc.AuthCodeURL(o.State, oauth2.S256ChallengeOption(o.Verifier), oidc.Nonce(o.Nonce)), http.StatusFound)
}

// roleClaims are Keycloak's role claims, in the access token (and the ID token when a mapper adds them).
type roleClaims struct {
	Realm    struct{ Roles []string }            `json:"realm_access"`
	Resource map[string]struct{ Roles []string } `json:"resource_access"`
}

// roles lists realm roles and this client's roles; in the master realm (old Keycloak) also master-realm client roles.
func (rc roleClaims) roles(sso ssoSettings) []string {
	out := append(rc.Realm.Roles, rc.Resource[sso.ClientID].Roles...)
	if strings.HasSuffix(sso.Issuer, "/realms/master") {
		out = append(out, rc.Resource["master-realm"].Roles...)
	}
	return out
}

// mapRole is the system role the Keycloak roles give: admin_role wins over security_role.
func mapRole(sso ssoSettings, roles []string) string {
	switch {
	case sso.AdminRole != "" && slices.Contains(roles, sso.AdminRole):
		return "admin"
	case sso.SecurityRole != "" && slices.Contains(roles, sso.SecurityRole):
		return "security"
	}
	return ""
}

func (s *server) handleSSOCallback(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	actor := "" // known only after the ID token is verified
	audit := func(reason, step string) {
		s.audit(ctx, c, "auth.login_failed", nil, actor, map[string]any{"method": "sso", "reason": reason, "step": step})
	}
	bad := func(code, step string, err error) {
		log.Printf("sso callback %s: %v", step, err)
		audit(code, step)
		http.Redirect(w, r, "/login?error="+code, http.StatusFound)
	}
	var o ssoState
	ck, err := r.Cookie(ssoCookie)
	if err != nil || !s.unsigned(ck.Value, &o) || time.Now().Unix() > o.Exp || o.State == "" ||
		subtle.ConstantTimeCompare([]byte(o.State), []byte(r.URL.Query().Get("state"))) != 1 {
		audit("state", "state")
		http.Redirect(w, r, "/login?error=state", http.StatusFound) // a browser lands here, so show the login page's message
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Path: ssoCookiePath, MaxAge: -1, HttpOnly: true, Secure: secure(r)})
	sso, err := s.ssoConf(ctx)
	if err != nil {
		bad("sso", "settings", err)
		return
	}
	p, oc, err := s.oidcClient(r, sso)
	if err != nil {
		bad("sso", "discovery", err)
		return
	}
	hctx := context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: 10 * time.Second})
	tok, err := oc.Exchange(hctx, r.URL.Query().Get("code"), oauth2.VerifierOption(o.Verifier))
	if err != nil {
		bad("sso", "exchange", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	id, err := p.Verifier(&oidc.Config{ClientID: sso.ClientID}).Verify(hctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(o.Nonce)) != 1 {
		bad("sso", "verify", err)
		return
	}
	var claims struct {
		Username string   `json:"preferred_username"`
		Name     string   `json:"name"`
		Email    string   `json:"email"`
		Given    string   `json:"given_name"`
		Family   string   `json:"family_name"`
		Groups   []string `json:"groups"` // nil when the mapper is missing: keep the stored memberships
		roleClaims
	}
	if err := id.Claims(&claims); err != nil {
		bad("sso", "claims", err)
		return
	}
	// Keycloak builds "name" as "given family"; Korean names read family-first without a space.
	if hangul(claims.Family) && hangul(claims.Given) {
		claims.Name = claims.Family + claims.Given
	}
	if claims.Username == "" {
		claims.Username = id.Subject
	}
	actor = claims.Username
	if claims.Name == "" {
		claims.Name = claims.Username
	}
	roles := claims.roles(sso)
	if at, err := p.Verifier(&oidc.Config{SkipClientIDCheck: true}).Verify(hctx, tok.AccessToken); err == nil {
		var rc roleClaims
		if at.Claims(&rc) == nil {
			roles = append(roles, rc.roles(sso)...)
		}
	}
	uid, active, before, after, err := s.ssoUpsert(ctx, id.Subject, claims.Username, claims.Name, claims.Email, mapRole(sso, roles))
	if errors.Is(err, errLocalAccount) {
		bad("conflict", "username", err)
		return
	}
	if errors.Is(err, errIdentityConflict) {
		bad("identity", "username", err)
		return
	}
	if err != nil {
		bad("sso", "save user", err)
		return
	}
	c.User = &user{ID: uid, Username: claims.Username}
	if before != after { // the Keycloak role decides the system role at each login
		s.audit(ctx, c, "user.update", nil, claims.Username, map[string]any{"op": "sso_role", "before": before, "after": after})
	}
	if !active {
		bad("disabled", "disabled", nil)
		return
	}

	var groups []string // nil keeps the stored group memberships
	if claims.Groups != nil {
		// Only full paths count: a short name ("팀") could collide with an unrelated top-level group.
		paths := []string{}
		for _, g := range claims.Groups {
			if g = strings.TrimSpace(g); strings.HasPrefix(g, "/") && normalizePath(g) != "" {
				paths = append(paths, normalizePath(g))
			}
		}
		if n := len(claims.Groups) - len(paths); n > 0 {
			log.Printf("sso login %s: ignored %d group claim value(s) without a leading \"/\"; turn on \"Full group path\" in the Keycloak groups mapper", claims.Username, n)
		}
		if len(paths) > 0 || len(claims.Groups) == 0 { // all-invalid claims keep the stored memberships, like a missing claim
			groups = paths
		}
	}
	depts := s.loginDeptsFor(ctx, id, sso, claims.Username)
	if groups != nil || depts != nil {
		if err := s.setLoginMemberships(ctx, uid, groups, depts); err != nil {
			log.Printf("sso callback memberships: %v", err) // login still succeeds
		}
	}
	token, err := s.startSession(ctx, uid, r)
	if err != nil {
		bad("sso", "session", err)
		return
	}
	setSessionCookie(w, r, token)
	s.audit(ctx, c, "auth.login", nil, claims.Username, map[string]any{"method": "sso"})
	http.Redirect(w, r, safeNext(o.Next), http.StatusFound)
}

// read decides a login's department paths and records the outcome; nil keeps the stored departments.
func (s *server) loginDeptsFor(ctx context.Context, id *oidc.IDToken, sso ssoSettings, username string) []string {
	sy, err := s.syncConf(ctx)
	if err != nil {
		log.Printf("sso login %s: sync settings: %v", username, err)
		return nil
	}
	name, on := sy.deptAttr()
	if !on {
		return []string{} // off: no department counts, even one stored earlier
	}
	var depts []string
	var all map[string]json.RawMessage
	id.Claims(&all)
	val, claimed := all[name]
	if claimed {
		var one string
		var many []string
		if json.Unmarshal(val, &one) == nil {
			many = []string{one}
		} else if json.Unmarshal(val, &many) != nil {
			log.Printf("sso login %s: department claim %q is neither a string nor a string list", username, name)
		}
		if many != nil {
			depts = deptPaths(many)
		}
	}
	d := loginDept{User: username, At: time.Now().UTC(), Source: "claim", Depts: depts}
	switch {
	case claimed && len(depts) == 0:
		d.Source = "claim_empty" // empty clears the departments, a malformed value keeps them; no Admin API either way
	case !claimed:
		d.Source = "missing"
		if sy.ClientID != "" && sy.ClientSecret != "" { // no mapper yet: read this one person from the Admin API
			got, err := kcUserDept(ctx, sso.Issuer, sy, username)
			switch {
			case err != nil:
				log.Printf("sso login %s: department from the Keycloak Admin API: %v", username, err) // login still succeeds
				d.Source = "error"
			case got != nil:
				depts, d.Source, d.Depts = got, "admin_api", got
			}
		}
	}
	s.loginDepts.add(d)
	return depts
}

// freeUsernameSQL renames an inactive Keycloak row that holds username $1 under another sub ($2), so a new person
// who got a departed person's username gets a fresh row instead of the old memberships and role.
const freeUsernameSQL = `update users set username = username || '#' || id
	where username = $1 and source = 'sso' and not active and oidc_sub is not null and oidc_sub <> $2`

// ssoUpsert finds the user by OIDC sub (then by username, only for rows without a stored sub) or creates it.
// A username held by an active row with another sub is refused (errIdentityConflict). With role_from_sso the
// Keycloak role replaces the system role; an admin's override is kept.
func (s *server) ssoUpsert(ctx context.Context, sub, username, name, email, role string) (id int64, active bool, before, after string, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, freeUsernameSQL, username, sub); e != nil {
			return e
		}
		var hsource string
		var hsub *string
		e := tx.QueryRow(ctx, `select source, oidc_sub from users where username=$1 for update`, username).Scan(&hsource, &hsub)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
		case e != nil:
			return e
		case hsource != "sso":
			return errLocalAccount
		case hsub != nil && *hsub != sub:
			return errIdentityConflict
		}
		var fromSSO, bySync bool
		const cols = `select id, active, system_role, role_from_sso, disabled_by_sync from users `
		e = tx.QueryRow(ctx, cols+`where oidc_sub=$1 and source='sso' for update`, sub).Scan(&id, &active, &before, &fromSSO, &bySync)
		if errors.Is(e, pgx.ErrNoRows) {
			e = tx.QueryRow(ctx, cols+`where username=$1 and source='sso' and oidc_sub is null for update`, username).Scan(&id, &active, &before, &fromSSO, &bySync)
		}
		if errors.Is(e, pgx.ErrNoRows) {
			before, after, active = "", role, true
			return tx.QueryRow(ctx, `insert into users(username, name, email, source, oidc_sub, system_role, role_from_sso, last_login_at)
				values($1, $2, $3, 'sso', $4, $5, true, now()) returning id`, username, name, email, sub, role).Scan(&id)
		}
		if e != nil {
			return e
		}
		after = before
		if fromSSO {
			after = role
		}
		if bySync && !active { // the sync disabled it, and this Keycloak login proves Keycloak enabled it again
			active = true
		}
		_, e = tx.Exec(ctx, `update users set username=$2, name=$3, email=$4, oidc_sub=$5, system_role=$6, last_login_at=now(),
			active = active or disabled_by_sync, disabled_by_sync = false where id=$1`,
			id, username, name, email, sub, after)
		return e
	})
	return
}

// setLoginMemberships stores a login's group-claim memberships and department paths; nil keeps that side.
// Claimed groups and their parents become known Keycloak groups, so a department can never grant them (R4a)
// even on sites without the sync.
func (s *server) setLoginMemberships(ctx context.Context, userID int64, groups, depts []string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		for table, paths := range map[string][]string{"user_groups": groups, "user_depts": depts} {
			if paths == nil {
				continue
			}
			if table == "user_groups" {
				if _, err := tx.Exec(ctx, `insert into kc_groups(path) select unnest($1::text[])
					on conflict (path) do update set deleted=false, seen_at=now()`, expandGroups(paths)); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `delete from `+table+` where user_id=$1`, userID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `insert into `+table+`(user_id, path) select $1, unnest($2::text[]) on conflict do nothing`, userID, paths); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *server) handleGetSSO(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	sso, err := s.ssoConf(r.Context())
	if err != nil {
		writeInternal(w, "get sso", err)
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": sso.Enabled, "issuer": sso.Issuer, "client_id": sso.ClientID,
		"client_secret_set": sso.ClientSecret != "", "admin_role": sso.AdminRole, "security_role": sso.SecurityRole, "public_url": sso.PublicURL})
}

func (s *server) handlePutSSO(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	// nil fields keep the stored value; client_secret_set is accepted so the UI can send its form back
	var req struct {
		Enabled         *bool   `json:"enabled,omitempty"`
		Issuer          *string `json:"issuer,omitempty"`
		ClientID        *string `json:"client_id,omitempty"`
		ClientSecret    *string `json:"client_secret,omitempty"`
		AdminRole       *string `json:"admin_role,omitempty"`
		SecurityRole    *string `json:"security_role,omitempty"`
		PublicURL       *string `json:"public_url,omitempty"`
		ClientSecretSet *bool   `json:"client_secret_set,omitempty"`
	}
	if err := readJSON(r, 4<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	req.ClientSecretSet = nil
	trim(req.Issuer, req.ClientID, req.ClientSecret, req.AdminRole, req.SecurityRole, req.PublicURL)
	for _, p := range []*string{req.Issuer, req.PublicURL} {
		if p == nil {
			continue
		}
		*p = strings.TrimRight(*p, "/")
		if u, err := url.Parse(*p); *p != "" && (err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https") {
			writeErr(w, 400, "bad_request", "Issuer URL과 사이트 주소는 http:// 또는 https:// 로 시작해야 합니다.")
			return
		}
	}
	if req.ClientSecret != nil && *req.ClientSecret == "" {
		req.ClientSecret = nil
	}
	if err := s.mergeSetting(r.Context(), "sso", req); err != nil {
		writeInternal(w, "put sso", err)
		return
	}
	s.audit(r.Context(), c, "settings.update", nil, "sso", map[string]any{"credential_changed": req.ClientSecret != nil})
	s.handleGetSSO(w, r, c)
}
