package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// perm is the permission a route declares when it is registered. See the API contract for the meanings.
type perm struct {
	kind string // public user admin security proj upload obj
	role string // proj and obj: viewer member owner
	obj  string // obj: the object kind, resolved by a registerObj resolver from the {id} path value
	key  bool   // a personal MCP key may call this route over REST (the uploads); everything else it does through /mcp
}

var (
	permPublic   = perm{kind: "public"}
	permUser     = perm{kind: "user"}
	permAdmin    = perm{kind: "admin"}
	permSecurity = perm{kind: "security"}          // security or admin
	permUpload   = perm{kind: "upload", key: true} // proj:member, or an API token with upload scope for the {key} project
	permScanJob  = perm{kind: "proj", role: "member", key: true}
)

func permProj(role string) perm      { return perm{kind: "proj", role: role} }
func permObj(kind, role string) perm { return perm{kind: "obj", role: role, obj: kind} }

func (p perm) validate() error {
	switch p.kind {
	case "public", "user", "admin", "security", "upload":
		return nil
	case "proj", "obj":
		if rankRole(p.role) == 0 {
			return fmt.Errorf("perm %s needs a role, got %q", p.kind, p.role)
		}
		if p.kind == "obj" && p.obj == "" {
			return errors.New("obj perm needs an object kind")
		}
		return nil
	}
	return fmt.Errorf("unknown perm kind %q", p.kind)
}

type routeInfo struct {
	pattern string
	perm    perm
	h       func(w http.ResponseWriter, r *http.Request, c *reqCtx) // run in-process by the MCP tools (mcpCall.api)
}

type user struct {
	ID         int64    `json:"id"`
	Username   string   `json:"username"`
	Name       string   `json:"name"`
	Email      string   `json:"email"`
	SystemRole string   `json:"system_role"`
	Source     string   `json:"source"` // local | sso
	Depts      []string `json:"depts"`
	Groups     []string `json:"groups"`
}

type project struct {
	ID          int64     `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   *int64    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type apiToken struct {
	ID         int64      `json:"id"`
	ProjectID  int64      `json:"project_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedBy  *int64     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// projectRole is the user's role on a project ("" = no access): admin is owner everywhere, security is at least
// viewer, everyone else gets the highest grant among their own user row and their group/department paths
// (memberPathsSQL). A var so tests can swap it.
var projectRole = func(s *server, ctx context.Context, u *user, projectID int64) (role string, err error) {
	var rank int
	err = s.db.QueryRow(ctx, `select coalesce(max(case pm.role when 'owner' then 3 when 'member' then 2 when 'viewer' then 1 end), 0)
		from project_members pm where pm.project_id = $2 and `+memberMatchSQL("$1::bigint"), u.ID, projectID).Scan(&rank)
	if err != nil {
		return "", err
	}
	return roleFor(u, rank), nil
}

// roleFor turns the rank of the user's best membership grant (0 = none) into their effective role.
func roleFor(u *user, rank int) string {
	switch u.SystemRole {
	case "admin":
		rank = 3
	case "security":
		rank = max(rank, 1)
	}
	return [...]string{"", "viewer", "member", "owner"}[rank]
}

// memberPathsSQL is a subquery of the group and department paths that make the user (arg, a bigint SQL
// expression) a member, parents included. A department path (or parent) that is also a Keycloak group path, live
// or deleted, is left out: "/개발본부/X" from the department attribute never grants Keycloak's "/개발본부" (R4a).
func memberPathsSQL(arg string) string {
	return `select distinct a.path from (select path, false as dept from user_groups where user_id = ` + arg + `
			union all select path, true from user_depts where user_id = ` + arg + `) m
		cross join lateral (select array_to_string((string_to_array(m.path, '/'))[1:i], '/') as path
			from generate_series(2, cardinality(string_to_array(m.path, '/'))) i) a
		where not (m.dept and exists (select 1 from kc_groups k where k.path = a.path))`
}

// memberMatchSQL matches project_members rows (alias pm) that grant something to the user (arg, a bigint SQL expression).
func memberMatchSQL(arg string) string {
	return `(pm.principal_kind = 'user' and pm.principal = (` + arg + `)::text
		or pm.principal_kind = 'group' and pm.principal in (` + memberPathsSQL(arg) + `))`
}

// memberPaths lists the paths memberPathsSQL yields for userID, sorted.
func (s *server) memberPaths(ctx context.Context, userID int64) ([]string, error) {
	rows, _ := s.db.Query(ctx, memberPathsSQL("$1::bigint"), userID)
	paths, err := pgx.CollectRows(rows, pgx.RowTo[string])
	slices.Sort(paths)
	return paths, err
}

// visibleProjectsSQL is the WHERE fragment that limits a list query to the projects u can see; the row's project
// id is alias.project_id and the fragment's own args start at $argN. Admin and security see every project, a nil
// user (an API token) none. Usage:
//
//	cond, args := s.visibleProjectsSQL(c.User, "f", 2)
//	rows, err := s.db.Query(ctx, `select ... from findings f where f.status = $1 and `+cond, append([]any{"open"}, args...)...)
func (s *server) visibleProjectsSQL(u *user, alias string, argN int) (cond string, args []any) {
	if !sqlAliasRe.MatchString(alias) {
		panic("visibleProjectsSQL: bad alias " + alias)
	}
	switch {
	case u == nil:
		return "false", nil
	case u.SystemRole == "admin" || u.SystemRole == "security":
		return "true", nil
	}
	return alias + ".project_id in (select pm.project_id from project_members pm where " +
		memberMatchSQL(fmt.Sprintf("$%d::bigint", argN)) + ")", []any{u.ID}
}

// callerProjectsSQL is visibleProjectsSQL for the caller of a handler that the MCP tools also run (mcp.go): a tool
// call about one project (c.Scope: an API token's own project, or the project argument of a personal key's call)
// sees exactly that project. Over REST Scope is never set.
func (s *server) callerProjectsSQL(c *reqCtx, alias string, argN int) (cond string, args []any) {
	if c.Scope == 0 {
		return s.visibleProjectsSQL(c.User, alias, argN)
	}
	if !sqlAliasRe.MatchString(alias) {
		panic("callerProjectsSQL: bad alias " + alias)
	}
	return fmt.Sprintf("%s.project_id = $%d", alias, argN), []any{c.Scope}
}

func rankRole(r string) int {
	return map[string]int{"viewer": 1, "member": 2, "owner": 3}[r]
}

// registerObj adds the resolver for obj:<kind> perms; the id is the {id} path value. fn returns
// pgx.ErrNoRows for an unknown or malformed id (anything else is a 500).
func (s *server) registerObj(kind string, fn func(ctx context.Context, id string) (projectID int64, err error)) {
	s.objs[kind] = fn
}

const projectCols = `select id, key, name, description, created_by, created_at from projects `

func scanProject(row pgx.Row) (*project, error) {
	p := &project{}
	return p, row.Scan(&p.ID, &p.Key, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt)
}

func (s *server) projectByKey(ctx context.Context, key string) (*project, error) {
	return scanProject(s.db.QueryRow(ctx, projectCols+`where key=$1`, key))
}

func (s *server) projectByID(ctx context.Context, id int64) (*project, error) {
	return scanProject(s.db.QueryRow(ctx, projectCols+`where id=$1`, id))
}

// authorize applies p to the caller, writing 401/403/404 and returning false when it does not pass.
// A project the caller cannot see is 404, never 403, so ids cannot be probed.
func (s *server) authorize(w http.ResponseWriter, r *http.Request, p perm, c *reqCtx) bool {
	ctx := r.Context()
	notFound := func(err error) bool {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			writeInternal(w, "authorize", err)
			return false
		}
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return false
	}
	forbidden := func() bool {
		writeErr(w, 403, "forbidden", "권한이 없습니다.")
		return false
	}
	switch {
	case p.kind == "public":
		return true
	case c.User == nil && c.Token == nil:
		writeErr(w, 401, "unauthorized", "로그인이 필요합니다.")
		return false
	case c.Token != nil:
		ok := p.kind == "upload" && slices.Contains(c.Token.Scopes, "upload") ||
			p.kind == "proj" && p.role == "viewer" && slices.Contains(c.Token.Scopes, "read")
		if !ok {
			return forbidden()
		}
		pr, err := s.projectByKey(ctx, r.PathValue("key"))
		if err != nil || pr.ID != c.Token.ProjectID {
			return notFound(err)
		}
		c.Project = pr
		return true
	}
	u := c.User
	switch p.kind {
	case "user":
		return true
	case "admin":
		return u.SystemRole == "admin" || forbidden()
	case "security":
		return u.SystemRole == "admin" || u.SystemRole == "security" || forbidden()
	}
	// proj, upload, obj
	var pr *project
	var err error
	if p.kind == "obj" {
		fn := s.objs[p.obj]
		if fn == nil {
			log.Printf("no resolver for obj kind %q", p.obj)
			return notFound(nil)
		}
		var pid int64
		if pid, err = fn(ctx, r.PathValue("id")); err != nil {
			return notFound(err)
		}
		pr, err = s.projectByID(ctx, pid)
	} else {
		pr, err = s.projectByKey(ctx, r.PathValue("key"))
	}
	if err != nil {
		return notFound(err)
	}
	role, err := projectRole(s, ctx, u, pr.ID)
	if err != nil || role == "" {
		return notFound(err)
	}
	need := p.role
	if p.kind == "upload" {
		need = "member"
	}
	if rankRole(role) < rankRole(need) {
		return forbidden()
	}
	c.Project, c.Role = pr, role
	return true
}

var sqlAliasRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
