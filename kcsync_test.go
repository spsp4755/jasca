package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestAdminBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://kc.example.internal/auth/realms/master": "https://kc.example.internal/auth/admin/realms/master",
		"https://kc.example.internal/realms/jasca":       "https://kc.example.internal/admin/realms/jasca",
	} {
		if got, err := adminBase(in); err != nil || got != want {
			t.Errorf("adminBase(%q)=%q,%v", in, got, err)
		}
	}
	if _, err := adminBase("https://kc.example.internal/other"); err == nil {
		t.Error("want an error without /realms/")
	}
}

func TestSyncDisablesMissingUser(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	ctx := context.Background()
	kim, park, gone, held := mkUser(t, s, "kim", ""), mkUser(t, s, "park", ""), mkUser(t, s, "gone", ""), mkUser(t, s, "held", "")
	kimC, parkC, goneC := loginAs(t, s, kim), loginAs(t, s, park), loginAs(t, s, gone)
	s.db.Exec(ctx, `update users set active=false where id=$1`, held.ID) // an admin turned this one off
	s.db.Exec(ctx, `insert into kc_groups(path) values('/old')`)
	kc.tree = []map[string]any{{"id": "g1", "name": "dev", "path": "/dev", "subGroups": []map[string]any{
		{"id": "g2", "name": "be", "path": "/dev/be", "subGroups": []map[string]any{}}}}}
	kc.member = map[string][]map[string]any{"g2": {{"id": "kim", "username": "kim", "enabled": true}}}
	kc.users = []map[string]any{
		{"id": "kim", "username": "kim", "enabled": true, "email": "kim.new@example.internal", "firstName": "민수", "lastName": "김",
			"attributes": map[string][]string{"department": {"보안실/취약점팀"}}},
		{"id": "park", "username": "park", "enabled": false},
		{"id": "held", "username": "held", "enabled": true},
		{"id": "new", "username": "newbie", "enabled": true},
	}
	admin := loginAs(t, s, mkUser(t, s, "boss", "admin"))
	kc.users = append(kc.users, map[string]any{"id": "boss", "username": "boss", "enabled": true})
	rec := do(t, s, "POST", "/api/v1/admin/sync/run", nil, admin)
	var out struct {
		Groups, Users int
		Error         string
	}
	if json.Unmarshal(rec.Body.Bytes(), &out); rec.Code != 200 || out.Error != "" || out.Groups != 2 {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	active := func(name string) bool {
		t.Helper()
		var a bool
		if err := s.db.QueryRow(ctx, `select active from users where username=$1`, name).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	sessions := func(id int64) int {
		var n int
		s.db.QueryRow(ctx, `select count(*) from sessions where user_id=$1`, id).Scan(&n)
		return n
	}
	if !active("kim") || active("park") || active("gone") || active("held") || !active("newbie") {
		t.Fatal("active flags wrong after sync")
	}
	if sessions(park.ID) != 0 || sessions(gone.ID) != 0 || sessions(kim.ID) != 1 {
		t.Fatal("sessions of disabled users were not deleted")
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, goneC); rec.Code != 401 {
		t.Fatalf("gone user /me: %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, parkC); rec.Code != 401 {
		t.Fatalf("disabled user /me: %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, kimC); rec.Code != 200 {
		t.Fatalf("kim /me: %d", rec.Code)
	}
	var email, name string
	s.db.QueryRow(ctx, `select email, name from users where username='kim'`).Scan(&email, &name)
	g, d := memberships(t, s, "kim")
	if email != "kim.new@example.internal" || name != "김민수" || !reflect.DeepEqual(g, []string{"/dev", "/dev/be"}) ||
		!reflect.DeepEqual(d, []string{"/보안실", "/보안실/취약점팀"}) {
		t.Fatalf("kim: %s %s groups %v depts %v", email, name, g, d)
	}
	var deleted bool
	s.db.QueryRow(ctx, `select deleted from kc_groups where path='/old'`).Scan(&deleted)
	if !deleted {
		t.Fatal("/old not marked deleted")
	}
	var sy map[string]any
	rec = do(t, s, "GET", "/api/v1/admin/sync", nil, admin)
	if json.Unmarshal(rec.Body.Bytes(), &sy); sy["last_run"] == nil || sy["last_error"] != "" || sy["client_secret_set"] != true {
		t.Fatalf("sync status: %s", rec.Body.String())
	}

	// Keycloak enables park again: the sync brings back only the users it disabled itself
	kc.users[1]["enabled"] = true
	if err := s.syncKeycloak(ctx); err != nil {
		t.Fatal(err)
	}
	if !active("park") || active("held") {
		t.Fatal("re-enable wrong")
	}

	// an empty user list (wrong realm, broken permission) never disables everyone
	kc.users = nil
	if err := s.syncKeycloak(ctx); err == nil || !active("kim") {
		t.Fatalf("empty list: %v", err)
	}
	rec = do(t, s, "GET", "/api/v1/admin/sync", nil, admin)
	if json.Unmarshal(rec.Body.Bytes(), &sy); sy["last_error"] == "" {
		t.Fatalf("error not recorded: %s", rec.Body.String())
	}
}

// A new Keycloak user that reuses a departed user's username never revives or merges into the old row.
func TestSyncUsernameReuse(t *testing.T) {
	s := testServer(t)
	kc := newFakeKC(t, "/realms/jasca")
	configureSSO(t, s, kc)
	ctx := context.Background()
	old := mkUser(t, s, "alice", "") // oidc_sub = "alice"
	sqlExec(t, s, `update users set system_role='security', role_from_sso=false where id=$1`, old.ID)
	pid := mkProject(t, s, "web")
	addMember(t, s, pid, "user", fmt.Sprint(old.ID), "owner")
	kc.tree = []map[string]any{{"id": "g1", "name": "dev", "path": "/dev", "subGroups": []map[string]any{}}}
	kc.member = map[string][]map[string]any{"g1": {{"id": "alice2", "username": "alice", "enabled": true}}}
	kc.users = []map[string]any{{"id": "alice2", "username": "alice", "enabled": true, "email": "b@example.internal"},
		{"id": "boss", "username": "boss", "enabled": true}}
	for i := 0; i < 2; i++ { // the second run must not flip anything back
		if err := s.syncKeycloak(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var oldName, oldEmail string
	var oldActive bool
	s.db.QueryRow(ctx, `select username, email, active from users where id=$1`, old.ID).Scan(&oldName, &oldEmail, &oldActive)
	if oldActive || oldName == "alice" || oldEmail == "b@example.internal" {
		t.Fatalf("old row: %q %q active=%v", oldName, oldEmail, oldActive)
	}
	var newID int64
	var sub, role string
	var active bool
	if err := s.db.QueryRow(ctx, `select id, oidc_sub, system_role, active from users where username='alice'`).Scan(&newID, &sub, &role, &active); err != nil {
		t.Fatal(err)
	}
	if newID == old.ID || sub != "alice2" || role != "" || !active {
		t.Fatalf("new row %d sub %q role %q active %v", newID, sub, role, active)
	}
	var owners, groups int
	s.db.QueryRow(ctx, `select count(*) from project_members where principal_kind='user' and principal=$1::text`, newID).Scan(&owners)
	s.db.QueryRow(ctx, `select count(*) from user_groups where user_id=$1`, newID).Scan(&groups)
	if owners != 0 || groups != 1 {
		t.Fatalf("new row inherited memberships %d, groups %d", owners, groups)
	}
	g, _ := memberships(t, s, oldName)
	if len(g) != 0 {
		t.Fatalf("old row got the new user's groups %v", g)
	}
}
