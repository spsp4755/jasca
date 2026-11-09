package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// syncSettings is settings['sync']: the Keycloak service account (view-users, query-groups) and the last result.
type syncSettings struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IntervalMin  int    `json:"interval_min"` // 0 = 15
	// DeptAttribute names the Keycloak user attribute (and ID token claim) holding departments; "" = "department".
	DeptAttribute string     `json:"dept_attribute"`
	DeptOff       bool       `json:"dept_off"` // neither login nor sync reads departments
	LastRun       *time.Time `json:"last_run"`
	LastError     string     `json:"last_error"`
	Groups        int        `json:"groups"`
	Users         int        `json:"users"`
}

func (s *server) syncConf(ctx context.Context) (syncSettings, error) {
	var sy syncSettings
	_, err := s.getSetting(ctx, "sync", &sy)
	if sy.IntervalMin <= 0 {
		sy.IntervalMin = 15
	}
	return sy, err
}

// deptAttr is the department attribute in use: "department" unless renamed, none when turned off.
func (sy syncSettings) deptAttr() (name string, on bool) {
	if sy.DeptOff {
		return "", false
	}
	if sy.DeptAttribute == "" {
		return "department", true
	}
	return sy.DeptAttribute, true
}

// normalizePath makes a Keycloak group path canonical: leading "/", no trailing "/". "/" alone becomes "".
func normalizePath(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

const maxDepts, maxDeptLevels = 10, 10

// deptPath turns a department value ("보안실/취약점팀") into a path ("/보안실/취약점팀"); cut reports dropped levels.
func deptPath(v string) (path string, cut bool) {
	if v = strings.TrimSpace(v); len(v) > 150 || strings.ContainsFunc(v, unicode.IsControl) {
		return "", false
	}
	var parts []string
	for _, p := range strings.Split(v, "/") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return "/" + strings.Join(parts[:min(len(parts), maxDeptLevels)], "/"), len(parts) > maxDeptLevels
}

// deptPaths keeps at most maxDepts distinct paths of at most maxDeptLevels levels each.
func deptPaths(vals []string) []string {
	out, capped := []string{}, false
	for _, v := range vals {
		p, cut := deptPath(v)
		if p == "" || slices.Contains(out, p) {
			continue
		}
		capped = capped || cut
		if len(out) == maxDepts {
			capped = true
			break
		}
		out = append(out, p)
	}
	if capped {
		log.Printf("department values: kept the first %d values and %d levels per value", maxDepts, maxDeptLevels)
	}
	return out
}

// ancestors returns every prefix path: "/a/b" -> ["/a", "/a/b"].
func ancestors(path string) []string {
	var out []string
	for i := 1; i < len(path); i++ {
		if path[i] == '/' {
			out = append(out, path[:i])
		}
	}
	return append(out, path)
}

// expandGroups adds every parent path, sorted, without duplicates.
func expandGroups(own []string) []string {
	out := []string{}
	for _, p := range own {
		for _, a := range ancestors(p) {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.Sort(out)
	return out
}

// groupsFor is the user's Keycloak groups and departments, parents included, split for display. The rule itself
// (R4a: a department path or parent that a Keycloak group has, live or deleted, grants nothing) lives only in
// memberPathsSQL; the dept side is repeated here only to keep groups and depts separate, and
// TestMembershipRuleSingleSource pins both to memberPaths.
func (s *server) groupsFor(ctx context.Context, userID int64) (groups, depts []string, err error) {
	var gs, ds []string
	err = s.db.QueryRow(ctx, `select array(select path from user_groups where user_id=$1), array(select path from user_depts where user_id=$1)`,
		userID).Scan(&gs, &ds)
	if err != nil {
		return nil, nil, err
	}
	// dept side of the rule: parents of user_depts minus every kc_groups path (same as memberPathsSQL's dept branch)
	all := expandGroups(ds)
	var known []string
	if len(all) > 0 {
		if err = s.db.QueryRow(ctx, `select array(select path from kc_groups where path = any($1))`, all).Scan(&known); err != nil {
			return nil, nil, err
		}
	}
	depts = []string{}
	for _, p := range all {
		if !slices.Contains(known, p) {
			depts = append(depts, p)
		}
	}
	return expandGroups(gs), depts, nil
}

// adminBase maps an issuer to the Keycloak Admin REST base for the same realm (old "/auth" servers included).
func adminBase(issuer string) (string, error) {
	i := strings.Index(issuer, "/realms/")
	if i < 0 {
		return "", errors.New("Issuer URL에 /realms/ 경로가 없습니다")
	}
	return issuer[:i] + "/admin" + issuer[i:], nil
}

type kcGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	SubGroups []kcGroup `json:"subGroups"`
	// SubGroupCount is set by Keycloak >= 23, whose listings no longer nest children.
	SubGroupCount int `json:"subGroupCount"`
}

type kcUser struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Enabled    bool                `json:"enabled"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

func kcGet(ctx context.Context, hc *http.Client, token, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Keycloak %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// kcPages reads a first/max paged list until a short page.
func kcPages[T any](ctx context.Context, hc *http.Client, token, base, path, query string) ([]T, error) {
	const page = 200
	var all []T
	for first := 0; ; first += page {
		var got []T
		if err := kcGet(ctx, hc, token, fmt.Sprintf("%s%s?%sfirst=%d&max=%d", base, path, query, first, page), &got); err != nil {
			return nil, err
		}
		all = append(all, got...)
		if len(got) < page {
			return all, nil
		}
	}
}

// fillChildren fetches /groups/{id}/children for groups that report children but carry none (Keycloak >= 23).
// Older servers nest subGroups already and are left alone. seen keeps any group from being fetched twice.
func fillChildren(ctx context.Context, hc *http.Client, token, base string, gs []kcGroup, seen map[string]bool) error {
	for i := range gs {
		g := &gs[i]
		if len(g.SubGroups) == 0 && g.SubGroupCount > 0 && !seen[g.ID] {
			seen[g.ID] = true
			kids, err := kcPages[kcGroup](ctx, hc, token, base, "/groups/"+url.PathEscape(g.ID)+"/children", "briefRepresentation=false&")
			if err != nil {
				return err
			}
			g.SubGroups = kids
		}
		if err := fillChildren(ctx, hc, token, base, g.SubGroups, seen); err != nil {
			return err
		}
	}
	return nil
}

func flattenGroups(gs []kcGroup, parent string, out *[]kcGroup) {
	for _, g := range gs {
		if g.Path == "" {
			g.Path = parent + "/" + g.Name
		}
		g.Path = normalizePath(g.Path)
		*out = append(*out, g)
		flattenGroups(g.SubGroups, g.Path, out)
	}
}

// kcToken gets a service-account access token with client_credentials.
func kcToken(ctx context.Context, hc *http.Client, issuer string, sy syncSettings) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", issuer+"/protocol/openid-connect/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"}, "client_id": {sy.ClientID}, "client_secret": {sy.ClientSecret}}.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok)
	if resp.StatusCode != 200 || err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("서비스 계정 토큰을 받지 못했습니다 (HTTP %d)", resp.StatusCode)
	}
	return tok.AccessToken, nil
}

// kcUserDept reads one user's department paths through the Admin API (the login fallback when the ID token has
// no department claim), within 3 seconds. nil, nil = the user has no department value.
func kcUserDept(ctx context.Context, issuer string, sy syncSettings, username string) ([]string, error) {
	attr, on := sy.deptAttr()
	if !on || sy.ClientID == "" || sy.ClientSecret == "" {
		return nil, errors.New("서비스 계정이 설정되지 않았습니다")
	}
	base, err := adminBase(issuer)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	hc := &http.Client{Timeout: 3 * time.Second}
	token, err := kcToken(ctx, hc, issuer, sy)
	if err != nil {
		return nil, err
	}
	var users []kcUser
	if err := kcGet(ctx, hc, token, base+"/users?exact=true&briefRepresentation=false&username="+url.QueryEscape(username), &users); err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Username == strings.ToLower(username) { // Keycloak stores usernames lower-cased; some versions ignore exact=true
			if d := deptPaths(u.Attributes[attr]); len(d) > 0 {
				return d, nil
			}
			return nil, nil
		}
	}
	return nil, fmt.Errorf("Keycloak에 사용자 %s가 없습니다", username)
}

// loginDept is one SSO login's department outcome, kept in memory for the admin sync page (not audited).
type loginDept struct {
	User   string    `json:"user"`
	At     time.Time `json:"at"`
	Source string    `json:"source"` // claim | claim_empty | admin_api | missing | error
	Depts  []string  `json:"depts"`
}

// deptLog keeps the latest 20 login outcomes, newest first; a restart empties it.
type deptLog struct {
	mu   sync.Mutex
	rows []loginDept
}

func (l *deptLog) add(d loginDept) {
	if d.Depts == nil {
		d.Depts = []string{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows = append([]loginDept{d}, l.rows[:min(len(l.rows), 19)]...)
}

// syncKeycloak pulls groups, users, emails, memberships and departments with the service account and records
// the outcome in settings['sync'].
func (s *server) syncKeycloak(ctx context.Context) error {
	if !s.syncMu.TryLock() {
		return errors.New("동기화가 이미 실행 중입니다")
	}
	defer s.syncMu.Unlock()
	groups, users, err := s.doSync(ctx)
	res := map[string]any{"last_run": time.Now().UTC(), "last_error": ""}
	if err != nil {
		res["last_error"] = err.Error()
	} else {
		res["groups"], res["users"] = groups, users
	}
	if e := s.mergeSetting(ctx, "sync", res); e != nil {
		log.Printf("keycloak sync result: %v", e)
	}
	return err
}

func (s *server) doSync(ctx context.Context) (nGroups, nUsers int, err error) {
	sso, err := s.ssoConf(ctx)
	if err != nil {
		return 0, 0, err
	}
	sy, err := s.syncConf(ctx)
	if err != nil {
		return 0, 0, err
	}
	if sy.ClientID == "" || sy.ClientSecret == "" || sso.Issuer == "" {
		return 0, 0, errors.New("동기화에 필요한 Issuer URL, Client ID, Client Secret이 설정되지 않았습니다")
	}
	base, err := adminBase(sso.Issuer)
	if err != nil {
		return 0, 0, err
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	token, err := kcToken(ctx, hc, sso.Issuer, sy)
	if err != nil {
		return 0, 0, err
	}
	tree, err := kcPages[kcGroup](ctx, hc, token, base, "/groups", "briefRepresentation=false&")
	if err != nil {
		return 0, 0, err
	}
	if err := fillChildren(ctx, hc, token, base, tree, map[string]bool{}); err != nil {
		return 0, 0, err
	}
	var groups []kcGroup
	flattenGroups(tree, "", &groups)
	members := map[string][]kcUser{} // group id -> members
	for _, g := range groups {
		if members[g.ID], err = kcPages[kcUser](ctx, hc, token, base, "/groups/"+url.PathEscape(g.ID)+"/members", ""); err != nil {
			return 0, 0, err
		}
	}
	all, err := kcPages[kcUser](ctx, hc, token, base, "/users", "briefRepresentation=false&")
	if err != nil {
		return 0, 0, err
	}
	if len(all) == 0 {
		return 0, 0, errors.New("Keycloak 사용자 목록이 비어 있어 동기화를 중단합니다") // would disable everyone
	}
	attr, deptOn := sy.deptAttr()
	paths := []string{}
	for _, g := range groups {
		paths = append(paths, g.Path)
	}
	var known, off, on []string
	for _, u := range all {
		known = append(known, u.Username)
		if u.Enabled {
			on = append(on, u.Username)
		} else {
			off = append(off, u.Username)
		}
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		// shortcut: groups are keyed by path, so a group renamed in Keycloak is a new group and its old project
		// memberships stop working; store the Keycloak group id if renames turn out to matter.
		if _, e := tx.Exec(ctx, `insert into kc_groups(path) select unnest($1::text[])
			on conflict (path) do update set deleted=false, seen_at=now()`, paths); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `update kc_groups set deleted=true where not deleted and path <> all($1)`, paths); e != nil {
			return e
		}
		for _, u := range all {
			// the Keycloak user id is the OIDC sub; a sub match also follows a username rename
			tag, e := tx.Exec(ctx, `update users set username=$1, name=$2, email=$3 where oidc_sub=$4 and source='sso'`,
				u.Username, displayName(u), u.Email, u.ID)
			if e != nil {
				return e
			}
			if tag.RowsAffected() == 0 && u.Enabled {
				if _, e := tx.Exec(ctx, `insert into users(username, name, email, source, oidc_sub, role_from_sso) values($1, $2, $3, 'sso', $4, true)
					on conflict (username) do update set name=excluded.name, email=excluded.email where users.source='sso'`,
					u.Username, displayName(u), u.Email, u.ID); e != nil {
					return e
				}
			}
		}
		// memberships of Keycloak users are rebuilt from the sync; local accounts are left alone
		for _, t := range []string{"user_groups", "user_depts"} {
			if _, e := tx.Exec(ctx, `delete from `+t+` where user_id in (select id from users where source='sso')`); e != nil {
				return e
			}
		}
		add := func(table, username, path string) error {
			_, e := tx.Exec(ctx, `insert into `+table+`(user_id, path) select id, $2 from users where username=$1 and source='sso'
				on conflict do nothing`, username, path)
			return e
		}
		for _, g := range groups {
			for _, u := range members[g.ID] {
				if e := add("user_groups", u.Username, g.Path); e != nil {
					return e
				}
			}
		}
		if deptOn {
			for _, u := range all {
				for _, p := range deptPaths(u.Attributes[attr]) {
					if e := add("user_depts", u.Username, p); e != nil {
						return e
					}
				}
			}
		}
		// disabled or deleted in Keycloak: inactive now, and their sessions end
		if _, e := tx.Exec(ctx, `with gone as (update users set active=false, disabled_by_sync=true
				where source='sso' and active and (username = any($1) or username <> all($2)) returning id)
			delete from sessions where user_id in (select id from gone)`, off, known); e != nil {
			return e
		}
		// only users this sync disabled come back; an admin's deactivation stays
		_, e := tx.Exec(ctx, `update users set active=true, disabled_by_sync=false where source='sso' and disabled_by_sync and username = any($1)`, on)
		return e
	})
	return len(groups), len(on), err
}

func displayName(u kcUser) string {
	switch {
	case hangul(u.LastName) && hangul(u.FirstName):
		return u.LastName + u.FirstName
	case strings.TrimSpace(u.FirstName+" "+u.LastName) != "":
		return strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
	return u.Username
}

func hangul(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.Is(unicode.Hangul, r) })
}

// syncLoop runs the sync every interval_min minutes while a service account is configured.
func (s *server) syncLoop(ctx context.Context) {
	for {
		wait := 15 * time.Minute
		if sy, err := s.syncConf(ctx); err == nil {
			wait = time.Duration(sy.IntervalMin) * time.Minute
			if sy.ClientID != "" {
				if err := s.syncKeycloak(ctx); err != nil {
					log.Printf("keycloak sync: %v", err)
					s.audit(ctx, nil, "sync.run", nil, "", map[string]any{"error": err.Error()}) // only failures, to keep the log quiet
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// --- admin routes ---

func (s *server) syncRoutes() {
	s.handle("GET /api/v1/admin/sync", permAdmin, s.handleGetSync)
	s.handle("PUT /api/v1/admin/sync", permAdmin, s.handlePutSync)
	s.handle("POST /api/v1/admin/sync/run", permAdmin, s.handleRunSync)
	s.handle("GET /api/v1/admin/sync/logins", permAdmin, func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		s.loginDepts.mu.Lock()
		defer s.loginDepts.mu.Unlock()
		writeJSON(w, 200, append([]loginDept{}, s.loginDepts.rows...))
	})
}

func (s *server) handleGetSync(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	sy, err := s.syncConf(r.Context())
	if err != nil {
		writeInternal(w, "get sync", err)
		return
	}
	writeJSON(w, 200, map[string]any{"client_id": sy.ClientID, "client_secret_set": sy.ClientSecret != "", "interval_min": sy.IntervalMin,
		"dept_attribute": sy.DeptAttribute, "dept_off": sy.DeptOff, "last_run": sy.LastRun, "last_error": sy.LastError,
		"groups": sy.Groups, "users": sy.Users})
}

func (s *server) handlePutSync(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	// nil fields keep the stored value; the read-only fields are accepted so the UI can send its form back
	var req struct {
		ClientID        *string    `json:"client_id,omitempty"`
		ClientSecret    *string    `json:"client_secret,omitempty"`
		IntervalMin     *int       `json:"interval_min,omitempty"`
		DeptAttribute   *string    `json:"dept_attribute,omitempty"`
		DeptOff         *bool      `json:"dept_off,omitempty"`
		ClientSecretSet *bool      `json:"client_secret_set,omitempty"`
		LastRun         *time.Time `json:"last_run,omitempty"`
		LastError       *string    `json:"last_error,omitempty"`
		Groups          *int       `json:"groups,omitempty"`
		Users           *int       `json:"users,omitempty"`
	}
	if err := readJSON(r, 4<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if req.IntervalMin != nil && (*req.IntervalMin < 1 || *req.IntervalMin > 1440) {
		writeErr(w, 400, "bad_request", "동기화 주기는 1~1440분이어야 합니다.")
		return
	}
	req.ClientSecretSet, req.LastRun, req.LastError, req.Groups, req.Users = nil, nil, nil, nil, nil
	trim(req.ClientID, req.ClientSecret, req.DeptAttribute)
	if req.ClientSecret != nil && *req.ClientSecret == "" {
		req.ClientSecret = nil
	}
	if err := s.mergeSetting(r.Context(), "sync", req); err != nil {
		writeInternal(w, "put sync", err)
		return
	}
	if req.DeptOff != nil && *req.DeptOff { // off takes every department's access away now, not at next login
		if _, err := s.db.Exec(r.Context(), `delete from user_depts`); err != nil {
			writeInternal(w, "clear departments", err)
			return
		}
	}
	s.audit(r.Context(), c, "settings.update", nil, "sync", map[string]any{"credential_changed": req.ClientSecret != nil})
	s.handleGetSync(w, r, c)
}

func (s *server) handleRunSync(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	err := s.syncKeycloak(r.Context())
	sy, _ := s.syncConf(r.Context())
	out := map[string]any{"groups": sy.Groups, "users": sy.Users, "error": ""}
	if err != nil {
		log.Printf("keycloak sync: %v", err)
		out["error"] = err.Error()
	}
	s.audit(r.Context(), c, "sync.run", nil, "", out)
	writeJSON(w, 200, out)
}

// trim trims each non-nil string in place.
func trim(ps ...*string) {
	for _, p := range ps {
		if p != nil {
			*p = strings.TrimSpace(*p)
		}
	}
}
