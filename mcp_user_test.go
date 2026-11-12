package main

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"testing"
	"time"
)

func init() {
	// another person's MCP key is not there for the caller
	matrixRoutes = append(matrixRoutes, matrixCase{Method: "DELETE", Path: "/api/v1/me/mcp-keys/{mcp_key}"})
	matrixFixtures = append(matrixFixtures, func(t *testing.T, s *server, projB *project) map[string]string {
		return map[string]string{"{mcp_key}": itoa(qint64(t, s, `insert into mcp_keys(user_id, name, prefix, key_hash, expires_at)
			select id, 'b', 'jsu_b', $1, now() + interval '1 day' from users where username = 'b-owner' returning id`, tokenHash("jsu_matrix_b")))}
	})
}

// mkKey gives u a personal MCP key directly and returns the key.
func mkKey(t *testing.T, s *server, u *user, readOnly bool) string {
	t.Helper()
	plain := mcpKeyPrefix + u.Username + map[bool]string{true: "_ro", false: "_rw"}[readOnly]
	sqlExec(t, s, `insert into mcp_keys(user_id, name, prefix, key_hash, read_only, expires_at)
		values($1, 'agent', left($2, 12), $3, $4, now() + interval '1 day')`, u.ID, plain, tokenHash(plain), readOnly)
	return plain
}

func toolNames(t *testing.T, s *server, key string) []string {
	t.Helper()
	rec, rp := mcpNew(t, s, key, "tools/list", nil)
	if rec.Code != 200 || rp.Error != nil {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	var names []string
	for _, tl := range rp.Result["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	return names
}

func TestMCPKeyLifecycle(t *testing.T) {
	s := testServer(t)
	kim, lee := mkUser(t, s, "kim", ""), mkUser(t, s, "lee", "")
	ck := loginAs(t, s, kim)
	exp := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	for name, body := range map[string]map[string]any{
		"no name":     {"name": " ", "expires_at": exp},
		"long name":   {"name": strings.Repeat("가", 101), "expires_at": exp},
		"past expiry": {"name": "x", "expires_at": "2020-01-01T00:00:00Z"},
		"far expiry":  {"name": "x", "expires_at": time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)},
	} {
		if rec := do(t, s, "POST", "/api/v1/me/mcp-keys", body, ck); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	rec := do(t, s, "POST", "/api/v1/me/mcp-keys", map[string]any{"name": "노트북 에이전트", "expires_at": exp}, ck)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	made := decode[struct {
		ID  int64  `json:"id"`
		Key string `json:"key"`
	}](t, rec)
	if !strings.HasPrefix(made.Key, "jsu_") || len(made.Key) < 40 {
		t.Fatalf("key %q", made.Key)
	}
	// the list never carries the key or its hash
	rec = do(t, s, "GET", "/api/v1/me/mcp-keys", nil, ck)
	if body := rec.Body.String(); rec.Code != 200 || strings.Contains(body, made.Key) || strings.Contains(body, "hash") ||
		!strings.Contains(body, `"prefix":"`+made.Key[:12]+`"`) {
		t.Fatalf("list: %d %s", rec.Code, body)
	}
	if rec := do(t, s, "GET", "/api/v1/me/mcp-keys", nil, loginAs(t, s, lee)); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("lee sees kim's keys: %s", rec.Body.String())
	}
	if n := qInt(t, s, `select count(*) from audit_log where action = 'mcpkey.create' and actor_user = $1 and target = '노트북 에이전트'`, kim.ID); n != 1 {
		t.Errorf("audit rows for the new key: %d", n)
	}

	// the key is the person at /mcp …
	who := callTool[struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Key      string `json:"key_name"`
	}](t, s, made.Key, "whoami", nil)
	if who.Username != "kim" || who.Role != "user" || who.Key != "노트북 에이전트" {
		t.Errorf("whoami: %+v", who)
	}
	// … and nobody in the REST API, except on the upload routes
	for _, path := range []string{"/api/v1/projects", "/api/v1/me", "/api/v1/me/mcp-keys", "/api/v1/findings"} {
		if rec := do(t, s, "GET", path, nil, made.Key); rec.Code != 403 || errCode(t, rec) != "forbidden" {
			t.Errorf("GET %s with a key: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := do(t, s, "POST", "/api/v1/me/mcp-keys", map[string]any{"name": "more", "expires_at": exp}, made.Key); rec.Code != 403 {
		t.Errorf("a key minted a key: %d", rec.Code)
	}
	pid := mkProject(t, s, "shop")
	doc := trivyDoc("x", []tv{{ID: "CVE-2024-1111", Pkg: "openssl", Sev: "HIGH"}}, nil)
	if rec := upload(t, s, "shop", "target=api&kind=image", doc, made.Key); rec.Code != 404 { // not a member: the project is not there
		t.Errorf("upload without membership: %d %s", rec.Code, rec.Body.String())
	}
	addMember(t, s, pid, "user", itoa(kim.ID), "viewer")
	if rec := upload(t, s, "shop", "target=api&kind=image", doc, made.Key); rec.Code != 403 {
		t.Errorf("upload as viewer: %d %s", rec.Code, rec.Body.String())
	}
	sqlExec(t, s, `update project_members set role = 'member' where project_id = $1`, pid)
	if rec := upload(t, s, "shop", "target=api&kind=image", doc, made.Key); rec.Code != 201 {
		t.Fatalf("upload as member: %d %s", rec.Code, rec.Body.String())
	}
	if n := qInt(t, s, `select count(*) from scans where created_by_user = $1`, kim.ID); n != 1 {
		t.Errorf("the scan is not kim's: %d", n)
	}
	if n := qInt(t, s, `select count(*) from audit_log where action = 'scan.upload' and actor_user = $1 and details->>'mcp_key' = '노트북 에이전트'`, kim.ID); n != 1 {
		t.Errorf("the upload's audit row does not name the key: %d", n)
	}
	ro := mkKey(t, s, kim, true)
	if rec := upload(t, s, "shop", "target=api&kind=image", doc, ro); rec.Code != 403 || !strings.Contains(rec.Body.String(), "읽기 전용") {
		t.Errorf("upload with a read-only key: %d %s", rec.Code, rec.Body.String())
	}

	// revoking: not another person's, then one's own; a revoked key is nobody
	if rec := do(t, s, "DELETE", "/api/v1/me/mcp-keys/"+itoa(made.ID), nil, loginAs(t, s, lee)); rec.Code != 404 {
		t.Errorf("lee revoked kim's key: %d", rec.Code)
	}
	if rec, _ := mcpNew(t, s, made.Key, "tools/list", nil); rec.Code != 200 {
		t.Fatalf("the key stopped working: %d", rec.Code)
	}
	for range 2 { // twice is fine
		if rec := do(t, s, "DELETE", "/api/v1/me/mcp-keys/"+itoa(made.ID), nil, ck); rec.Code != 204 {
			t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec, _ := mcpNew(t, s, made.Key, "tools/list", nil); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("a revoked key: %d", rec.Code)
	}

	// an expired key and a deactivated person's key are nobody; reactivating brings the key back
	sqlExec(t, s, `update mcp_keys set expires_at = now() - interval '1 second' where key_hash = $1`, tokenHash(ro))
	if rec, _ := mcpNew(t, s, ro, "tools/list", nil); rec.Code != 401 {
		t.Errorf("an expired key: %d", rec.Code)
	}
	leeKey := mkKey(t, s, lee, false)
	sqlExec(t, s, `update users set active = false where id = $1`, lee.ID)
	if rec, _ := mcpNew(t, s, leeKey, "tools/list", nil); rec.Code != 401 {
		t.Errorf("a deactivated user's key: %d", rec.Code)
	}
	sqlExec(t, s, `update users set active = true where id = $1`, lee.ID)
	if rec, _ := mcpNew(t, s, leeKey, "tools/list", nil); rec.Code != 200 {
		t.Errorf("a reactivated user's key: %d", rec.Code)
	}

	// the administrator sees every key and can revoke any
	if rec := do(t, s, "GET", "/api/v1/admin/mcp-keys", nil, ck); rec.Code != 403 {
		t.Errorf("a user listed all keys: %d", rec.Code)
	}
	adminCk := loginAs(t, s, mkUser(t, s, "root", "admin"))
	all := decode[[]struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}](t, do(t, s, "GET", "/api/v1/admin/mcp-keys", nil, adminCk))
	if len(all) != 3 {
		t.Fatalf("admin key list: %+v", all)
	}
	i := slices.IndexFunc(all, func(k struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}) bool {
		return k.Username == "lee"
	})
	if rec := do(t, s, "DELETE", "/api/v1/admin/mcp-keys/"+itoa(all[i].ID), nil, adminCk); rec.Code != 204 {
		t.Fatalf("admin revoke: %d", rec.Code)
	}
	if rec, _ := mcpNew(t, s, leeKey, "tools/list", nil); rec.Code != 401 {
		t.Errorf("a key the admin revoked: %d", rec.Code)
	}

	// at most 20 live keys
	sqlExec(t, s, `insert into mcp_keys(user_id, name, prefix, key_hash, expires_at)
		select $1, 'k' || i, 'jsu_', decode(lpad(i::text, 8, '0'), 'hex'), now() + interval '1 day' from generate_series(1, 20) i`, kim.ID)
	if rec := do(t, s, "POST", "/api/v1/me/mcp-keys", map[string]any{"name": "21st", "expires_at": exp}, ck); rec.Code != 409 {
		t.Errorf("a 21st key: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMCPKeyToolsByRole(t *testing.T) {
	s := testServer(t)
	u, sec, adm := mkUser(t, s, "kim", ""), mkUser(t, s, "sec", "security"), mkUser(t, s, "root", "admin")
	user, userRO := toolNames(t, s, mkKey(t, s, u, false)), toolNames(t, s, mkKey(t, s, u, true))
	security, admin := toolNames(t, s, mkKey(t, s, sec, false)), toolNames(t, s, mkKey(t, s, adm, false))

	has := func(list []string, names ...string) bool {
		for _, n := range names {
			if !slices.Contains(list, n) {
				return false
			}
		}
		return true
	}
	if !has(user, append([]string{"whoami", "list_projects", "create_project", "upload_report", "update_finding", "request_exception"}, mcpToolNames...)...) ||
		has(user, "decide_exception") || has(user, "system_status") {
		t.Errorf("user tools: %v", user)
	}
	if !has(userRO, append([]string{"whoami", "list_projects", "list_members", "list_audit_log"}, mcpToolNames...)...) {
		t.Errorf("read-only tools: %v", userRO)
	}
	if !has(security, "decide_exception", "create_advisory") || has(security, "system_status") || len(security) != len(user)+2 {
		t.Errorf("security tools: %v", security)
	}
	if !has(admin, "system_status", "get_server_logs", "list_users", "update_user", "list_mcp_keys", "revoke_mcp_key", "run_keycloak_sync",
		"start_recheck", "list_all_scans", "list_notifications", "get_settings") || len(admin) <= len(security) {
		t.Errorf("admin tools: %v", admin)
	}

	// every tool of the fullest list is well-formed, and a read-only key gets exactly the read-only ones
	_, rp := mcpNew(t, s, mkKeyNamed(t, s, adm, "second"), "tools/list", nil)
	if rp.Result["cacheScope"] != "private" {
		t.Errorf("a key's tool list must not be cached for others: %v", rp.Result["cacheScope"])
	}
	seen := map[string]bool{}
	for _, raw := range rp.Result["tools"].([]any) {
		tl := raw.(map[string]any)
		name, desc := tl["name"].(string), tl["description"].(string)
		sc := tl["inputSchema"].(map[string]any)
		ann := tl["annotations"].(map[string]any)
		props, _ := sc["properties"].(map[string]any)
		if seen[name] || len(desc) < 40 || sc["type"] != "object" || sc["additionalProperties"] != false || props == nil || ann["openWorldHint"] != false {
			t.Errorf("%s: name, description, schema root or annotations: %v", name, tl)
		}
		seen[name] = true
		required, _ := sc["required"].([]any)
		for _, r := range required {
			if props[r.(string)] == nil {
				t.Errorf("%s: required %q is not a property", name, r)
			}
		}
		for arg, p := range props {
			if d, _ := p.(map[string]any)["description"].(string); d == "" && arg != "limit" && p.(map[string]any)["enum"] == nil &&
				!slices.Contains([]string{"name", "description", "title", "new_name"}, arg) {
				t.Errorf("%s.%s has no description", name, arg)
			}
		}
		readOnly := ann["readOnlyHint"] == true
		if readOnly != has(userRO, name) && has(user, name) {
			t.Errorf("%s: readOnlyHint %v, but in the read-only key's list: %v", name, readOnly, has(userRO, name))
		}
		if !readOnly && ann["destructiveHint"] == nil {
			t.Errorf("%s: a changing tool says whether it is destructive", name)
		}
	}
	for _, n := range []string{"project_summary", "list_targets", "list_scans", "list_fixes"} {
		rec, rp := mcpNew(t, s, mkKeyNamed(t, s, u, "p-"+n), "tools/call", map[string]any{"name": n, "arguments": map[string]any{}})
		if text := rec.Body.String(); rp.Result["isError"] != true || !strings.Contains(text, "project is required") {
			t.Errorf("%s without project: %s", n, text)
		}
	}

	// a tool the key does not list says why, as a tool error the model can read
	key := mkKeyNamed(t, s, u, "why")
	if msg := toolErr(t, s, key, "system_status", nil); !strings.Contains(msg, "administrator role") {
		t.Errorf("admin tool as user: %s", msg)
	}
	if msg := toolErr(t, s, key, "decide_exception", map[string]any{"id": 1, "decision": "approve"}); !strings.Contains(msg, "security or administrator") {
		t.Errorf("security tool as user: %s", msg)
	}
	if msg := toolErr(t, s, mkKeyNamed2(t, s, u, "ro2", true), "create_project", map[string]any{"key": "x1", "name": "x"}); !strings.Contains(msg, "read-only") {
		t.Errorf("write tool with a read-only key: %s", msg)
	}
	if n := qInt(t, s, `select count(*) from projects`); n != 0 {
		t.Errorf("a refused tool created a project")
	}
	if _, rp := mcpNew(t, s, key, "tools/call", map[string]any{"name": "drop_database", "arguments": map[string]any{}}); rp.Error == nil {
		t.Errorf("an unknown tool must be a protocol error")
	}

	// the role is read on every call: promoted and demoted without a new key
	sqlExec(t, s, `update users set system_role = 'admin' where id = $1`, u.ID)
	if !has(toolNames(t, s, key), "system_status") {
		t.Errorf("a promoted user's key lacks the admin tools")
	}
	sqlExec(t, s, `update users set system_role = '' where id = $1`, u.ID)
	if has(toolNames(t, s, key), "system_status") {
		t.Errorf("a demoted user's key kept the admin tools")
	}

	// a project token still gets its ten tools and none of the new ones
	_, tok := mkToken(t, s, "shop", "read")
	if got := toolNames(t, s, tok); !slices.Equal(got, mcpToolNames) {
		t.Errorf("token tools: %v", got)
	}
	if _, rp := mcpNew(t, s, tok, "tools/call", map[string]any{"name": "whoami", "arguments": map[string]any{}}); rp.Error == nil {
		t.Errorf("a token called whoami")
	}

	// the key page's list: every tool, the ones above the role marked
	type row struct {
		Name     string `json:"name"`
		Title    string `json:"title"`
		Group    string `json:"group"`
		Write    bool   `json:"write"`
		Disabled bool   `json:"disabled"`
	}
	rows := decode[[]row](t, do(t, s, "GET", "/api/v1/me/mcp-tools", nil, loginAs(t, s, sec)))
	if len(rows) != len(admin) {
		t.Fatalf("mcp-tools: %d rows, the admin has %d tools", len(rows), len(admin))
	}
	for _, r := range rows {
		if r.Title == "" || r.Disabled != (r.Group == "admin") || r.Write != !has(userRO, r.Name) && has(admin, r.Name) && r.Write {
			t.Errorf("mcp-tools row %+v", r)
		}
	}
}

func mkKeyNamed(t *testing.T, s *server, u *user, name string) string {
	return mkKeyNamed2(t, s, u, name, false)
}

func mkKeyNamed2(t *testing.T, s *server, u *user, name string, readOnly bool) string {
	t.Helper()
	plain := mcpKeyPrefix + u.Username + "_" + name
	sqlExec(t, s, `insert into mcp_keys(user_id, name, prefix, key_hash, read_only, expires_at)
		values($1, $2, left($3, 12), $4, $5, now() + interval '1 day')`, u.ID, name, plain, tokenHash(plain), readOnly)
	return plain
}

// The ten read tools with a personal key: the user's projects, and nothing of anyone else's.
func TestMCPKeyReadTools(t *testing.T) {
	s := testServer(t)
	shop, bank := mcpSeed(t, s, "shop"), mcpSeed(t, s, "bank")
	kim := mkUser(t, s, "kim", "")
	addMember(t, s, shop.pid, "user", itoa(kim.ID), "member")
	key := mkKey(t, s, kim, true) // a read-only key reads everything its user can

	type projects struct {
		Total    int `json:"total"`
		Projects []struct {
			Key    string `json:"key"`
			MyRole string `json:"my_role"`
			Open   struct {
				Critical int `json:"critical"`
				Open     int `json:"open"`
			} `json:"open_findings"`
		} `json:"projects"`
	}
	ps := callTool[projects](t, s, key, "list_projects", nil)
	if ps.Total != 1 || ps.Projects[0].Key != "shop" || ps.Projects[0].MyRole != "member" || ps.Projects[0].Open.Open != 3 {
		t.Fatalf("list_projects: %+v", ps)
	}
	sum := callTool[struct {
		Key    string `json:"key"`
		MyRole string `json:"my_role"`
	}](t, s, key, "project_summary", map[string]any{"project": "shop"})
	if sum.Key != "shop" || sum.MyRole != "member" {
		t.Errorf("project_summary: %+v", sum)
	}
	// a project the user is not in answers like one that does not exist
	gone := toolErr(t, s, key, "project_summary", map[string]any{"project": "nope"})
	if got := toolErr(t, s, key, "project_summary", map[string]any{"project": "bank"}); !strings.Contains(got, "not found") ||
		strings.ReplaceAll(got, "bank", "nope") != gone {
		t.Errorf("another project: %q vs unknown: %q", got, gone)
	}

	type findings struct {
		Total    int `json:"total"`
		Findings []struct {
			ID      int64  `json:"id"`
			Project string `json:"project"`
			RuleID  string `json:"rule_id"`
		} `json:"findings"`
	}
	all := callTool[findings](t, s, key, "list_findings", nil) // no project: everything the user can see
	if all.Total != 3 || slices.ContainsFunc(all.Findings, func(f struct {
		ID      int64  `json:"id"`
		Project string `json:"project"`
		RuleID  string `json:"rule_id"`
	}) bool {
		return f.Project != "shop"
	}) {
		t.Errorf("list_findings across projects: %+v", all)
	}
	if got := callTool[findings](t, s, key, "list_findings", map[string]any{"project": "shop", "severity": []string{"CRITICAL"}}); got.Total != 1 {
		t.Errorf("list_findings shop critical: %+v", got)
	}
	fid := findingID(t, s, shop.pid, "CVE-2024-3333", "shop-api")
	sqlExec(t, s, `update findings set assignee_id = $1 where id = $2`, kim.ID, fid)
	if got := callTool[findings](t, s, key, "list_findings", map[string]any{"assignee": "me"}); got.Total != 1 || got.Findings[0].ID != fid {
		t.Errorf("list_findings assignee me: %+v", got)
	}
	if got := callTool[findings](t, s, key, "list_findings", map[string]any{"assignee": "none"}); got.Total != 2 {
		t.Errorf("list_findings assignee none: %+v", got)
	}
	if msg := toolErr(t, s, key, "list_findings", map[string]any{"assignee": "ghost"}); !strings.Contains(msg, "not found") {
		t.Errorf("assignee ghost: %s", msg)
	}
	if msg := toolErr(t, s, key, "list_findings", map[string]any{"target": "shop-api"}); !strings.Contains(msg, "target needs project") {
		t.Errorf("target without project: %s", msg)
	}

	if f := callTool[struct {
		Project string `json:"project"`
		Target  string `json:"target"`
	}](t, s, key, "get_finding", map[string]any{"id": fid}); f.Project != "shop" || f.Target != "shop-api" {
		t.Errorf("get_finding: %+v", f)
	}
	theirs := findingID(t, s, bank.pid, "CVE-2024-3333", "bank-api")
	if msg := toolErr(t, s, key, "get_finding", map[string]any{"id": theirs}); !strings.Contains(msg, "not found") {
		t.Errorf("another project's finding: %s", msg)
	}
	if msg := toolErr(t, s, key, "get_scan", map[string]any{"id": bank.scan1}); !strings.Contains(msg, "not found") {
		t.Errorf("another project's scan: %s", msg)
	}
	if sc := callTool[struct {
		ID int64 `json:"id"`
	}](t, s, key, "get_scan", map[string]any{"id": shop.scan2}); sc.ID != shop.scan2 {
		t.Errorf("get_scan: %+v", sc)
	}

	v := callTool[struct {
		AffectedTotal int `json:"affected_total"`
		Affected      []struct {
			Project string `json:"project"`
		} `json:"affected"`
	}](t, s, key, "get_vulnerability", map[string]any{"id": "CVE-2024-1111"})
	if v.AffectedTotal != 2 || v.Affected[0].Project != "shop" || v.Affected[1].Project != "shop" {
		t.Errorf("get_vulnerability: %+v", v)
	}
	ex := callTool[struct {
		Total      int `json:"total"`
		Exceptions []struct {
			Project string `json:"project"`
		} `json:"exceptions"`
	}](t, s, key, "list_exceptions", nil)
	if ex.Total != 1 || ex.Exceptions[0].Project != "shop" {
		t.Errorf("list_exceptions: %+v", ex)
	}
	for _, name := range []string{"list_targets", "list_scans", "list_fixes"} {
		if text := toolErr(t, s, key, name, map[string]any{"project": "bank"}); !strings.Contains(text, "not found") {
			t.Errorf("%s of another project: %s", name, text)
		}
		res, text := toolRaw(t, s, key, name, map[string]any{"project": "shop"})
		if res["isError"] == true || strings.Contains(text, "bank") {
			t.Errorf("%s: %s", name, text)
		}
	}

	// security staff see every project without being a member
	sec := mkKey(t, s, mkUser(t, s, "sec", "security"), false)
	if got := callTool[projects](t, s, sec, "list_projects", nil); got.Total != 2 || got.Projects[0].MyRole != "viewer" {
		t.Errorf("security list_projects: %+v", got)
	}
	if got := callTool[findings](t, s, sec, "list_findings", nil); got.Total != 6 {
		t.Errorf("security list_findings: %+v", got)
	}
}

func TestMCPKeyWriteTools(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	kim, lee, sec := mkUser(t, s, "kim", ""), mkUser(t, s, "lee", ""), mkUser(t, s, "sec", "security")
	key, leeKey, secKey := mkKey(t, s, kim, false), mkKey(t, s, lee, false), mkKey(t, s, sec, false)
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/dev/platform')`, lee.ID)

	// create a project: the user owns it
	p := callTool[struct {
		Key    string `json:"key"`
		MyRole string `json:"my_role"`
	}](t, s, key, "create_project", map[string]any{"key": "pay", "name": "결제", "description": "결제 서비스"})
	if p.Key != "pay" || p.MyRole != "owner" {
		t.Fatalf("create_project: %+v", p)
	}
	if msg := toolErr(t, s, key, "create_project", map[string]any{"key": "pay", "name": "again"}); !strings.Contains(msg, "Conflict") {
		t.Errorf("duplicate key: %s", msg)
	}
	if msg := toolErr(t, s, key, "create_project", map[string]any{"key": "Bad Key", "name": "x"}); !strings.Contains(msg, "Invalid arguments") {
		t.Errorf("bad key: %s", msg)
	}
	if msg := toolErr(t, s, leeKey, "update_project", map[string]any{"project": "pay", "name": "mine"}); !strings.Contains(msg, "not found") {
		t.Errorf("a stranger renamed the project: %s", msg)
	}

	// members: add by username and by group, change, remove; a viewer changes nothing
	type members struct {
		Members []mcpMember `json:"members"`
	}
	m := callTool[members](t, s, key, "set_member", map[string]any{"project": "pay", "user": "lee", "role": "viewer"})
	if len(m.Members) != 2 {
		t.Fatalf("set_member: %+v", m)
	}
	if msg := toolErr(t, s, leeKey, "set_member", map[string]any{"project": "pay", "user": "lee", "role": "owner"}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a viewer made themselves owner: %s", msg)
	}
	if msg := toolErr(t, s, leeKey, "update_project", map[string]any{"project": "pay", "name": "mine"}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a viewer renamed the project: %s", msg)
	}
	callTool[members](t, s, key, "set_member", map[string]any{"project": "pay", "group": "/dev", "role": "member"})
	m = callTool[members](t, s, key, "set_member", map[string]any{"project": "pay", "user": "lee", "role": "none"})
	if len(m.Members) != 2 || !slices.ContainsFunc(m.Members, func(e mcpMember) bool { return e.Group == "/dev" && e.Role == "member" }) {
		t.Errorf("after removing lee: %+v", m)
	}
	if msg := toolErr(t, s, key, "set_member", map[string]any{"project": "pay", "user": "kim", "role": "none"}); !strings.Contains(msg, "소유자") {
		t.Errorf("the last owner left: %s", msg)
	}
	for _, bad := range []map[string]any{{"project": "pay", "role": "member"}, {"project": "pay", "user": "lee", "group": "/dev", "role": "member"},
		{"project": "pay", "user": "ghost", "role": "member"}, {"project": "pay", "user": "lee", "role": "boss"}} {
		toolErr(t, s, key, "set_member", bad)
	}
	lm := callTool[struct {
		MyRole  string      `json:"my_role"`
		Members []mcpMember `json:"members"`
	}](t, s, leeKey, "list_members", map[string]any{"project": "pay"}) // lee is in through /dev/platform now
	if lm.MyRole != "member" || len(lm.Members) != 2 {
		t.Errorf("list_members: %+v", lm)
	}
	found := callTool[struct {
		Users  []struct{ Username string } `json:"users"`
		Groups []string                    `json:"groups"`
	}](t, s, key, "find_users", map[string]any{"query": "LEE"})
	if len(found.Users) != 1 || found.Users[0].Username != "lee" {
		t.Errorf("find_users: %+v", found)
	}

	// policy
	pol := callTool[policy](t, s, key, "set_policy", map[string]any{"project": "pay", "min_severity": "HIGH", "max_count": 0})
	if !pol.Enabled || pol.MinSeverity != "HIGH" {
		t.Errorf("set_policy: %+v", pol)
	}
	if msg := toolErr(t, s, leeKey, "set_policy", map[string]any{"project": "pay", "enabled": false}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a member changed the policy: %s", msg)
	}

	// upload a report inline: lee is a member
	doc := string(trivyDoc("x", []tv{{ID: "CVE-2024-1111", Pkg: "openssl", Sev: "CRITICAL", Fixed: "3.0.9"}, {ID: "CVE-2024-2222", Pkg: "zlib", Sev: "LOW"}}, nil))
	up := callTool[struct {
		ScanID       int64 `json:"scan_id"`
		PolicyPassed bool  `json:"policy_passed"`
		Open         struct {
			Open int `json:"open"`
		} `json:"open_findings"`
	}](t, s, leeKey, "upload_report", map[string]any{"project": "pay", "report": doc, "target": "pay-api", "kind": "image", "ref": "1.0", "scanners": []string{"vuln"}})
	if up.ScanID == 0 || up.PolicyPassed || up.Open.Open != 2 {
		t.Fatalf("upload_report: %+v", up)
	}
	if n := qInt(t, s, `select count(*) from scans where id = $1 and created_by_user = $2 and ref = '1.0'`, up.ScanID, lee.ID); n != 1 {
		t.Errorf("the scan is not lee's")
	}
	if msg := toolErr(t, s, key, "upload_report", map[string]any{"project": "pay", "report": "not a report"}); !strings.Contains(msg, "보고서") {
		t.Errorf("a broken report: %s", msg)
	}
	cmds := callTool[map[string]any](t, s, leeKey, "upload_commands", map[string]any{"project": "pay"})
	if c, _ := cmds["scan_source_archive"].(string); !strings.Contains(c, "/api/v1/projects/pay/scan-jobs") || !strings.Contains(c, "$JASCA_MCP_KEY") ||
		strings.Contains(c, leeKey) {
		t.Errorf("upload_commands: %v", cmds)
	}

	// findings: assignee and deadline
	crit := findingID(t, s, qint64(t, s, `select id from projects where key = 'pay'`), "CVE-2024-1111", "pay-api")
	low := findingID(t, s, qint64(t, s, `select id from projects where key = 'pay'`), "CVE-2024-2222", "pay-api")
	f := callTool[struct {
		Assignee string     `json:"assignee"`
		DueAt    *time.Time `json:"due_at"`
	}](t, s, leeKey, "update_finding", map[string]any{"id": crit, "assignee": "me", "due_date": "2030-01-31"})
	if f.Assignee != "lee" || f.DueAt == nil || f.DueAt.In(s.cfg.Loc).Format("2006-01-02") != "2030-01-31" {
		t.Errorf("update_finding: %+v", f)
	}
	if f := callTool[struct {
		Assignee string     `json:"assignee"`
		DueAt    *time.Time `json:"due_at"`
	}](t, s, key, "update_finding", map[string]any{"id": crit, "assignee": "none", "due_date": "auto"}); f.Assignee != "" || f.DueAt == nil ||
		f.DueAt.After(time.Now().Add(8*24*time.Hour)) {
		t.Errorf("update_finding back to the rule: %+v", f)
	}
	if n := callTool[struct {
		Updated int `json:"updated"`
	}](t, s, key, "assign_findings", map[string]any{"ids": []int64{crit, low}, "assignee": "lee"}); n.Updated != 2 {
		t.Errorf("assign_findings: %+v", n)
	}
	stranger := mkKey(t, s, mkUser(t, s, "park", ""), false)
	if msg := toolErr(t, s, stranger, "update_finding", map[string]any{"id": crit, "assignee": "me"}); !strings.Contains(msg, "not found") {
		t.Errorf("a stranger took a finding: %s", msg)
	}
	if msg := toolErr(t, s, stranger, "assign_findings", map[string]any{"ids": []int64{crit}, "assignee": "me"}); !strings.Contains(msg, "Nothing was changed") {
		t.Errorf("a stranger took findings: %s", msg)
	}
	if msg := toolErr(t, s, key, "update_finding", map[string]any{"id": crit, "assignee": "park"}); !strings.Contains(msg, "볼 수 없어") {
		t.Errorf("an assignee outside the project: %s", msg)
	}

	// exceptions: request, the requester cannot decide, security does, then it is revoked
	day := time.Now().In(s.cfg.Loc).AddDate(0, 0, 30).Format("2006-01-02")
	type exs struct {
		Requested []mcpException `json:"requested"`
	}
	req := callTool[exs](t, s, leeKey, "request_exception", map[string]any{"finding_ids": []int64{low}, "resolution": "accepted",
		"reason": "내부망에서만 쓰는 이미지", "expires_on": day})
	if len(req.Requested) != 1 || req.Requested[0].Status != "pending" || req.Requested[0].Project != "pay" {
		t.Fatalf("request_exception: %+v", req)
	}
	id := req.Requested[0].ID
	if got := req.Requested[0].ExpiresAt.In(s.cfg.Loc).Format("2006-01-02 15:04"); got != day+" 23:59" {
		t.Errorf("the exception ends at %s, want the end of %s", got, day)
	}
	for _, bad := range []map[string]any{
		{"resolution": "accepted", "reason": "no target at all", "expires_on": day},
		{"finding_ids": []int64{low}, "vuln_id": "CVE-2024-2222", "resolution": "accepted", "reason": "both given", "expires_on": day},
		{"finding_ids": []int64{low}, "resolution": "accepted", "reason": "a bad date", "expires_on": "next month"},
		{"finding_ids": []int64{low}, "resolution": "accepted", "reason": "the same again", "expires_on": day}, // one is pending
		{"vuln_id": "CVE-2024-2222", "resolution": "accepted", "reason": "everywhere, by a user", "expires_on": day},
	} {
		toolErr(t, s, leeKey, "request_exception", bad)
	}
	if msg := toolErr(t, s, stranger, "request_exception", map[string]any{"finding_ids": []int64{crit}, "resolution": "accepted",
		"reason": "not my project", "expires_on": day}); !strings.Contains(msg, "Not found") {
		t.Errorf("a stranger's request: %s", msg)
	}
	if e := callTool[mcpException](t, s, secKey, "decide_exception", map[string]any{"id": id, "decision": "approve", "note": "확인"}); e.Status != "approved" {
		t.Errorf("decide_exception: %+v", e)
	}
	if st := qstr(t, s, `select status from findings where id = $1`, low); st != "accepted" {
		t.Errorf("the finding after approval: %s", st)
	}
	if msg := toolErr(t, s, secKey, "decide_exception", map[string]any{"id": id, "decision": "reject"}); !strings.Contains(msg, "Conflict") {
		t.Errorf("deciding twice: %s", msg)
	}
	// a whole project's vulnerability is a member's to ask for (security staff are viewers there); every project's is security's
	if msg := toolErr(t, s, secKey, "request_exception", map[string]any{"vuln_id": "CVE-2024-1111", "project": "pay",
		"resolution": "false_positive", "reason": "해당 코드 경로 없음", "expires_on": day}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a viewer's project-wide request: %s", msg)
	}
	if pv := callTool[exs](t, s, leeKey, "request_exception", map[string]any{"vuln_id": "CVE-2024-1111", "project": "pay",
		"resolution": "false_positive", "reason": "해당 코드 경로 없음", "expires_on": day}); pv.Requested[0].Scope != "project_vuln" {
		t.Errorf("project-wide request: %+v", pv)
	}
	mine := callTool[exs](t, s, secKey, "request_exception", map[string]any{"vuln_id": "CVE-2024-1111",
		"resolution": "false_positive", "reason": "해당 코드 경로 없음", "expires_on": day})
	if msg := toolErr(t, s, secKey, "decide_exception", map[string]any{"id": mine.Requested[0].ID, "decision": "approve"}); !strings.Contains(msg, "본인") {
		t.Errorf("deciding one's own request: %s", msg)
	}
	if msg := toolErr(t, s, leeKey, "revoke_exception", map[string]any{"id": id}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a member revoked an approved exception: %s", msg)
	}
	if e := callTool[mcpException](t, s, secKey, "revoke_exception", map[string]any{"id": id}); e.Status != "revoked" {
		t.Errorf("revoke_exception: %+v", e)
	}
	if st := qstr(t, s, `select status from findings where id = $1`, low); st != "open" {
		t.Errorf("the finding after the revoke: %s", st)
	}

	// internal advisories: security registers, everyone reads
	adv := map[string]any{"id": "INT-2026-001", "title": "사내 openssl 권고", "severity": "HIGH",
		"affected": []map[string]any{{"ecosystem": "deb", "name": "openssl", "range": "<9.9.9", "fixed": "9.9.9"}}}
	if msg := toolErr(t, s, key, "create_advisory", adv); !strings.Contains(msg, "security or administrator") {
		t.Errorf("a user registered an advisory: %s", msg)
	}
	callTool[map[string]any](t, s, secKey, "create_advisory", adv)
	if l := callTool[struct {
		Total int `json:"total"`
	}](t, s, key, "list_advisories", map[string]any{"query": "openssl"}); l.Total != 1 {
		t.Errorf("list_advisories: %+v", l)
	}

	// targets: rename and delete are the owner's
	if msg := toolErr(t, s, leeKey, "rename_target", map[string]any{"project": "pay", "target": "pay-api", "new_name": "x"}); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a member renamed a target: %s", msg)
	}
	callTool[map[string]any](t, s, key, "rename_target", map[string]any{"project": "pay", "target": "pay-api", "new_name": "pay-backend"})
	if msg := toolErr(t, s, key, "delete_target", map[string]any{"project": "pay", "target": "pay-api"}); !strings.Contains(msg, "not found") {
		t.Errorf("deleting the old name: %s", msg)
	}
	callTool[map[string]any](t, s, key, "delete_target", map[string]any{"project": "pay", "target": "pay-backend"})
	if n := qInt(t, s, `select count(*) from targets`); n != 0 {
		t.Errorf("targets left: %d", n)
	}

	// everything above is in the audit log under the person, with the key's name; an owner reads their project's log
	var n int
	s.db.QueryRow(ctx, `select count(distinct action) from audit_log where details->>'mcp_key' = 'agent' and actor_user is not null
		and action in ('project.create', 'project.members', 'policy.update', 'scan.upload', 'finding.assign', 'finding.due',
			'exception.request', 'exception.approve', 'exception.revoke', 'target.rename', 'target.delete')`).Scan(&n)
	if n != 11 {
		rows, _ := s.db.Query(ctx, `select distinct action from audit_log order by 1`)
		var got []string
		for rows.Next() {
			var a string
			rows.Scan(&a)
			got = append(got, a)
		}
		t.Errorf("audited actions through the key: %d of 11; all actions: %v", n, got)
	}
	log := callTool[struct {
		Entries []struct {
			Actor   string         `json:"actor"`
			Action  string         `json:"action"`
			Project string         `json:"project"`
			Details map[string]any `json:"details"`
		} `json:"entries"`
	}](t, s, key, "list_audit_log", map[string]any{"project": "pay", "action": "target.delete"})
	if len(log.Entries) != 1 || log.Entries[0].Actor != "kim" || log.Entries[0].Details["mcp_key"] != "agent" {
		t.Errorf("list_audit_log: %+v", log)
	}
	if msg := toolErr(t, s, stranger, "list_audit_log", nil); !strings.Contains(msg, "Not allowed") {
		t.Errorf("a stranger read the audit log: %s", msg)
	}
}

func TestMCPAdminTools(t *testing.T) {
	s := testServer(t)
	shop := mcpSeed(t, s, "shop")
	root, kim := mkUser(t, s, "root", "admin"), mkUser(t, s, "kim", "")
	key := mkKey(t, s, root, false)

	st := callTool[struct {
		Version  string `json:"version"`
		Database struct {
			Name string `json:"database"`
			Max  int    `json:"connections_max"`
		} `json:"database"`
		Trivy struct {
			Installed bool `json:"vulnerability_db_installed"`
		} `json:"trivy"`
		Scans struct {
			Done int `json:"done_last_24h"`
		} `json:"scans"`
		Totals struct {
			Projects int `json:"projects"`
			Keys     int `json:"live_mcp_keys"`
			Open     struct {
				Open int `json:"open"`
			} `json:"open_findings"`
		} `json:"totals"`
		Problems []string `json:"problems"`
	}](t, s, key, "system_status", nil)
	if st.Version != version || st.Database.Name == "" || st.Database.Max == 0 || st.Trivy.Installed || st.Scans.Done != 3 ||
		st.Totals.Projects != 1 || st.Totals.Keys != 1 || st.Totals.Open.Open != 3 {
		t.Errorf("system_status: %+v", st)
	}
	if !slices.ContainsFunc(st.Problems, func(p string) bool { return strings.Contains(p, "Trivy vulnerability DB is not installed") }) {
		t.Errorf("problems do not name the missing Trivy DB: %v", st.Problems)
	}

	// the log copy: what the process logs is there, newest last
	prev := log.Writer()
	log.SetOutput(&serverLog)
	defer log.SetOutput(prev)
	log.Printf("mcp-admin-test: keycloak sync: connection refused")
	log.Printf("mcp-admin-test: something else")
	lines := callTool[struct {
		Matched int      `json:"matched"`
		Lines   []string `json:"lines"`
	}](t, s, key, "get_server_logs", map[string]any{"query": "MCP-ADMIN-TEST", "minutes": 5})
	if lines.Matched != 2 || !strings.HasSuffix(lines.Lines[1], "something else") {
		t.Errorf("get_server_logs: %+v", lines)
	}
	if one := callTool[struct {
		Lines []string `json:"lines"`
	}](t, s, key, "get_server_logs", map[string]any{"query": "mcp-admin-test", "limit": 1}); len(one.Lines) != 1 || !strings.HasSuffix(one.Lines[0], "something else") {
		t.Errorf("get_server_logs limit 1 keeps the newest: %+v", one)
	}

	// users
	type accounts struct {
		Total int          `json:"total"`
		Users []mcpAccount `json:"users"`
	}
	if us := callTool[accounts](t, s, key, "list_users", map[string]any{"role": "administrator"}); us.Total != 2 { // root and the bootstrap admin
		t.Errorf("list_users administrators: %+v", us)
	}
	if u := callTool[mcpAccount](t, s, key, "update_user", map[string]any{"username": "kim", "role": "security"}); u.Role != "security" {
		t.Errorf("update_user: %+v", u)
	}
	if msg := toolErr(t, s, key, "update_user", map[string]any{"username": "root", "role": "user"}); !strings.Contains(msg, "자기 자신") {
		t.Errorf("lowering oneself: %s", msg)
	}
	if msg := toolErr(t, s, key, "update_user", map[string]any{"username": "admin", "active": false}); !strings.Contains(msg, "비상용") {
		t.Errorf("deactivating the local admin: %s", msg)
	}
	kimKey := mkKey(t, s, kim, false)
	if u := callTool[mcpAccount](t, s, key, "update_user", map[string]any{"username": "kim", "active": false}); u.Active {
		t.Errorf("deactivate: %+v", u)
	}
	if rec, _ := mcpNew(t, s, kimKey, "tools/list", nil); rec.Code != 401 {
		t.Errorf("a deactivated user's key: %d", rec.Code)
	}
	callTool[mcpAccount](t, s, key, "update_user", map[string]any{"username": "kim", "active": true, "role": "user"})

	// keys of everyone
	type keys struct {
		Total int `json:"total"`
		Keys  []struct {
			ID    int64  `json:"id"`
			User  string `json:"user"`
			State string `json:"state"`
		} `json:"keys"`
	}
	ks := callTool[keys](t, s, key, "list_mcp_keys", map[string]any{"user": "kim"})
	if ks.Total != 1 || ks.Keys[0].State != "live" {
		t.Fatalf("list_mcp_keys: %+v", ks)
	}
	callTool[map[string]any](t, s, key, "revoke_mcp_key", map[string]any{"id": ks.Keys[0].ID})
	if rec, _ := mcpNew(t, s, kimKey, "tools/list", nil); rec.Code != 401 {
		t.Errorf("a key the admin revoked through MCP: %d", rec.Code)
	}
	if msg := toolErr(t, s, key, "revoke_mcp_key", map[string]any{"id": 999999}); !strings.Contains(msg, "not found") {
		t.Errorf("revoking an unknown key: %s", msg)
	}

	// scans and notifications across projects
	sqlExec(t, s, `update scans set status = 'failed', error = 'trivy: boom' where id = $1`, shop.scan1)
	sc := callTool[struct {
		Scans []struct {
			ID      int64  `json:"id"`
			Project string `json:"project"`
			Error   string `json:"error"`
		} `json:"scans"`
	}](t, s, key, "list_all_scans", nil)
	if len(sc.Scans) != 1 || sc.Scans[0].ID != shop.scan1 || sc.Scans[0].Project != "shop" || sc.Scans[0].Error != "trivy: boom" {
		t.Errorf("list_all_scans: %+v", sc)
	}
	if all := callTool[struct {
		Scans []any `json:"scans"`
	}](t, s, key, "list_all_scans", map[string]any{"status": []string{"done", "failed"}, "project": "shop"}); len(all.Scans) != 3 {
		t.Errorf("list_all_scans done+failed: %d", len(all.Scans))
	}
	ch := qint64(t, s, `insert into notify_channels(kind, name, config) values('mattermost', '보안 채널', '{"webhook_url": "https://mm.example.internal/hooks/s3cr3t"}') returning id`)
	sqlExec(t, s, `insert into deliveries(channel_id, event, payload, state, attempts, last_error)
		values($1, 'new_critical', '{"project_key": "shop"}', 'failed', 4, 'status 502')`, ch)
	ns := callTool[struct {
		Deliveries []struct {
			Channel   string `json:"channel"`
			Project   string `json:"project"`
			LastError string `json:"last_error"`
		} `json:"deliveries"`
	}](t, s, key, "list_notifications", nil)
	if len(ns.Deliveries) != 1 || ns.Deliveries[0].Channel != "보안 채널" || ns.Deliveries[0].Project != "shop" || ns.Deliveries[0].LastError != "status 502" {
		t.Errorf("list_notifications: %+v", ns)
	}

	// settings: there, and without one secret
	sqlExec(t, s, `insert into settings(key, value) values('sso', '{"enabled": true, "issuer": "https://sso.example.internal/realms/x", "client_id": "jasca", "client_secret": "sso-s3cr3t"}')
		on conflict (key) do update set value = excluded.value`)
	sqlExec(t, s, `insert into settings(key, value) values('smtp', '{"host": "smtp.example.internal", "port": 587, "password": "smtp-s3cr3t"}'),
		('ai', '{"base_url": "http://llm.example.internal/v1", "api_key": "ai-s3cr3t"}'), ('sync', '{"client_id": "jasca-sync", "client_secret": "sync-s3cr3t"}')
		on conflict (key) do update set value = excluded.value`)
	_, text := toolRaw(t, s, key, "get_settings", nil)
	if strings.Contains(text, "s3cr3t") || !strings.Contains(text, "sso.example.internal") || !strings.Contains(text, "remediation_deadlines") {
		t.Errorf("get_settings: %s", text)
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &settings); len(settings) != 10 {
		t.Errorf("get_settings sections: %d", len(settings))
	}

	// sync without a service account answers with its error; recheck without a Trivy DB starts with nothing to do or is refused
	sy := callTool[struct {
		Error string `json:"error"`
	}](t, s, key, "run_keycloak_sync", nil)
	if sy.Error == "" {
		t.Errorf("run_keycloak_sync against an unreachable Keycloak reported no error")
	}
	if res, text := toolRaw(t, s, key, "start_recheck", nil); res["isError"] != true && !strings.Contains(text, "run_id") {
		t.Errorf("start_recheck: %s", text)
	}

	// Harbor: an unmapped image goes to a project
	link := qint64(t, s, `insert into harbor_links(name, base_url, robot_user, robot_secret, webhook_secret_hash)
		values('사내 Harbor', 'https://harbor.example.internal', 'robot$jasca', 'x', '\x00') returning id`)
	um := qint64(t, s, `insert into harbor_unmapped(link_id, harbor_project, repository, digest, tag) values($1, 'web', 'web/front', 'sha256:abc', '1.0') returning id`, link)
	hu := callTool[struct {
		Images []struct {
			ID         int64  `json:"id"`
			Connection string `json:"connection"`
		} `json:"images"`
	}](t, s, key, "list_harbor_unmapped", nil)
	if len(hu.Images) != 1 || hu.Images[0].ID != um || hu.Images[0].Connection != "사내 Harbor" {
		t.Errorf("list_harbor_unmapped: %+v", hu)
	}
	callTool[map[string]any](t, s, key, "assign_harbor_image", map[string]any{"id": um, "project": "shop"})
	if n := qInt(t, s, `select count(*) from harbor_unmapped`); n != 0 {
		t.Errorf("the image is still unmapped")
	}
	if msg := toolErr(t, s, key, "assign_harbor_image", map[string]any{"id": um, "project": "shop"}); !strings.Contains(msg, "not found") {
		t.Errorf("assigning twice: %s", msg)
	}

	// the administrator owns every project through the user tools as well
	if p := callTool[struct {
		MyRole string `json:"my_role"`
	}](t, s, key, "project_summary", map[string]any{"project": "shop"}); p.MyRole != "owner" {
		t.Errorf("admin on a project: %+v", p)
	}
	if got := callTool[struct {
		Entries []any `json:"entries"`
	}](t, s, key, "list_audit_log", map[string]any{"action": "user.update"}); len(got.Entries) != 3 {
		t.Errorf("admin audit log: %d user.update rows", len(got.Entries))
	}
}

func qstr(t *testing.T, s *server, q string, args ...any) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(context.Background(), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}
