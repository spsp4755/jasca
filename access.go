package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// perm is the permission a route declares when it is registered. See the API contract for the meanings.
type perm struct {
	kind string // public user admin security proj upload obj
	role string // proj and obj: viewer member owner
	obj  string // obj: the object kind, resolved by a registerObj resolver from the {id} path value
}

var (
	permPublic   = perm{kind: "public"}
	permUser     = perm{kind: "user"}
	permAdmin    = perm{kind: "admin"}
	permSecurity = perm{kind: "security"} // security or admin
	permUpload   = perm{kind: "upload"}   // proj:member, or an API token with upload scope for the {key} project
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
}

type user struct {
	ID         int64    `json:"id"`
	Username   string   `json:"username"`
	Name       string   `json:"name"`
	Email      string   `json:"email"`
	SystemRole string   `json:"system_role"`
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

// projectRole is the user's role on a project ("" = no access). Task 6 replaces it; until then project
// perms fail closed with 404.
var projectRole = func(s *server, ctx context.Context, u *user, projectID int64) (role string, err error) {
	return "", nil
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
	c.Project = pr
	return true
}
