package main

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
)

// mkProject inserts a project directly and returns its id.
func mkProject(t *testing.T, s *server, key string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(context.Background(), `insert into projects(key, name) values($1, $1) returning id`, key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addMember(t *testing.T, s *server, projectID int64, kind, principal, role string) {
	t.Helper()
	if _, err := s.db.Exec(context.Background(), `insert into project_members(project_id, principal_kind, principal, role) values($1, $2, $3, $4)`,
		projectID, kind, principal, role); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// sqlExec runs a statement in a test and fails it on error.
func sqlExec(t *testing.T, s *server, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestRoleResolution(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	u := mkUser(t, s, "kim", "")
	role := func(u *user, pid int64) string {
		t.Helper()
		r, err := projectRole(s, ctx, u, pid)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	web := mkProject(t, s, "web")
	if r := role(u, web); r != "" {
		t.Errorf("no membership: %q", r)
	}
	addMember(t, s, web, "user", itoa(u.ID), "viewer")
	if r := role(u, web); r != "viewer" {
		t.Errorf("direct viewer: %q", r)
	}
	// the higher of a direct viewer grant and a parent-group member grant
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/dev/backend')`, u.ID)
	addMember(t, s, web, "group", "/dev", "member")
	if r := role(u, web); r != "member" {
		t.Errorf("direct viewer + group member: %q", r)
	}
	// a department grant reaches users in child departments
	sec := mkProject(t, s, "sec")
	addMember(t, s, sec, "group", "/보안실", "owner")
	if r := role(u, sec); r != "" {
		t.Errorf("before dept: %q", r)
	}
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/보안실/취약점팀')`, u.ID)
	if r := role(u, sec); r != "owner" {
		t.Errorf("child dept of an owner dept: %q", r)
	}
	// another user's grant gives nothing; a sibling path is not a parent
	other := mkUser(t, s, "lee", "")
	addMember(t, s, web, "user", itoa(other.ID), "owner")
	addMember(t, s, web, "group", "/dev/backend2", "owner")
	if r := role(u, web); r != "member" {
		t.Errorf("other grants leaked: %q", r)
	}

	paths, err := s.memberPaths(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/dev", "/dev/backend", "/보안실", "/보안실/취약점팀"}; !slices.Equal(paths, want) {
		t.Errorf("memberPaths = %q, want %q", paths, want)
	}

	adm := mkUser(t, s, "adm", "admin")
	secu := mkUser(t, s, "secu", "security")
	if r := role(adm, web); r != "owner" {
		t.Errorf("admin: %q", r)
	}
	if r := role(secu, web); r != "viewer" {
		t.Errorf("security: %q", r)
	}
	addMember(t, s, web, "user", itoa(secu.ID), "member")
	if r := role(secu, web); r != "member" {
		t.Errorf("security with member grant: %q", r)
	}
}

// R4a: a department path that is also a Keycloak group path must not grant that group's memberships.
func TestDeptCannotGrantKeycloakGroup(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	u := mkUser(t, s, "park", "")
	sqlExec(t, s, `insert into kc_groups(path) values('/개발본부'), ('/qa')`)
	sqlExec(t, s, `insert into kc_groups(path, deleted) values('/old', true)`)
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/개발본부/플랫폼팀'), ($1, '/qa'), ($1, '/old/x')`, u.ID)
	parent, own, qa, old := mkProject(t, s, "parent"), mkProject(t, s, "own"), mkProject(t, s, "qa"), mkProject(t, s, "old")
	addMember(t, s, parent, "group", "/개발본부", "owner")
	addMember(t, s, own, "group", "/개발본부/플랫폼팀", "viewer")
	addMember(t, s, qa, "group", "/qa", "owner")
	addMember(t, s, old, "group", "/old", "owner")
	for pid, want := range map[int64]string{parent: "", own: "viewer", qa: "", old: ""} {
		if r, err := projectRole(s, ctx, u, pid); err != nil || r != want {
			t.Errorf("project %d: %q %v, want %q", pid, r, err, want)
		}
	}
	// a real Keycloak membership of the same path still counts
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/qa')`, u.ID)
	if r, _ := projectRole(s, ctx, u, qa); r != "owner" {
		t.Errorf("real group membership: %q", r)
	}
	paths, _ := s.memberPaths(ctx, u.ID)
	if want := []string{"/old/x", "/qa", "/개발본부/플랫폼팀"}; !slices.Equal(paths, want) {
		t.Errorf("memberPaths = %q, want %q", paths, want)
	}
}

func TestVisibleProjectsSQL(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	u := mkUser(t, s, "choi", "")
	a, b, c := mkProject(t, s, "a-proj"), mkProject(t, s, "b-proj"), mkProject(t, s, "c-proj")
	addMember(t, s, a, "user", itoa(u.ID), "viewer")
	addMember(t, s, b, "group", "/team", "viewer")
	addMember(t, s, c, "group", "/other", "owner")
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/team/sub')`, u.ID)
	visible := func(u *user) []string {
		t.Helper()
		// $1 is taken by another condition, so the fragment must number its own args from $2
		cond, args := s.visibleProjectsSQL(u, "p", 2)
		rows, err := s.db.Query(ctx, `select key from (select *, id as project_id from projects) p where p.key <> $1 and `+cond+` order by key`,
			append([]any{"zzz"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
	if got := visible(u); !slices.Equal(got, []string{"a-proj", "b-proj"}) {
		t.Errorf("member: %q", got)
	}
	all := []string{"a-proj", "b-proj", "c-proj"}
	if got := visible(mkUser(t, s, "adm", "admin")); !slices.Equal(got, all) {
		t.Errorf("admin: %q", got)
	}
	if got := visible(mkUser(t, s, "sec", "security")); !slices.Equal(got, all) {
		t.Errorf("security: %q", got)
	}
	if got := visible(mkUser(t, s, "nobody", "")); len(got) != 0 {
		t.Errorf("no memberships: %q", got)
	}
	if got := visible(nil); len(got) != 0 {
		t.Errorf("nil user: %q", got)
	}
}

// groupsFor (display split, /me) and memberPaths (access) must apply the same rule.
func TestMembershipRuleSingleSource(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	u := mkUser(t, s, "kim", "")
	sqlExec(t, s, `insert into kc_groups(path) values('/g'), ('/개발본부'), ('/d2')`)
	sqlExec(t, s, `insert into kc_groups(path, deleted) values('/old', true)`)
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/g/h/i')`, u.ID) // nested group
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/p/q/r'), ($1, '/d2'), ($1, '/개발본부/팀/소'), ($1, '/old/x'), ($1, '/g/x')`, u.ID)
	// nested dept; dept == kc path; dept under kc path; dept under deleted kc group
	groups, depts, err := s.groupsFor(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := s.memberPaths(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// union as a set (no duplicate hiding) must equal memberPaths
	union := slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(groups), depts...))))
	if !slices.Equal(union, paths) {
		t.Errorf("groupsFor %q + %q != memberPaths %q", groups, depts, paths)
	}
	if wg := []string{"/g", "/g/h", "/g/h/i"}; !slices.Equal(groups, wg) {
		t.Errorf("groups = %q, want %q", groups, wg)
	}
	// /g is a kc group: the dept /g/x must not list it under depts even though a group path gives it
	if wd := []string{"/g/x", "/old/x", "/p", "/p/q", "/p/q/r", "/개발본부/팀", "/개발본부/팀/소"}; !slices.Equal(depts, wd) {
		t.Errorf("depts = %q, want %q", depts, wd)
	}
	want := []string{"/g", "/g/h", "/g/h/i", "/g/x", "/old/x", "/p", "/p/q", "/p/q/r", "/개발본부/팀", "/개발본부/팀/소"}
	if !slices.Equal(paths, want) {
		t.Errorf("memberPaths = %q, want %q", paths, want)
	}
}
