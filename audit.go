package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).auditRoutes) }

func (s *server) auditRoutes() {
	s.handle("GET /api/v1/audit", permUser, s.handleAuditList)
}

type auditEntry struct {
	ID         int64          `json:"id"`
	At         time.Time      `json:"at"`
	ActorUser  *int64         `json:"actor_user"`
	ActorToken *int64         `json:"actor_token"`
	IP         string         `json:"ip"`
	Action     string         `json:"action"`
	ProjectID  *int64         `json:"project_id"`
	Target     string         `json:"target"`
	Details    map[string]any `json:"details"`
	Actor      string         `json:"actor"`
	ProjectKey string         `json:"project_key"` // "" when the entry has no project; kept after the project is deleted
}

// handleAuditList: admin sees everything; anyone else only the projects they own (403 when they own none).
// Keyset pagination on id (newest first): next_cursor is the last id of a full page.
func (s *server) handleAuditList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx, q := r.Context(), r.URL.Query()
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit < 1 || limit > 200 {
		limit = 50
	}
	cursor := int64(1 << 62)
	if v := q.Get("cursor"); v != "" {
		if cursor, err = strconv.ParseInt(v, 10, 64); err != nil {
			badRequest(w, "cursor가 올바르지 않습니다.")
			return
		}
	}
	where, args := "a.id < $1 and ($2 = '' or a.action = $2)", []any{cursor, q.Get("action")}
	if key := q.Get("project"); key != "" {
		// details.project_key (written by audit) still finds the rows of a deleted project
		where += " and (a.project_id = (select id from projects where key = $3) or a.project_id is null and a.details->>'project_key' = $3)"
		args = append(args, key)
	}
	if c.User.SystemRole != "admin" {
		where += ` and a.project_id in (select pm.project_id from project_members pm where pm.role = 'owner' and ` +
			memberMatchSQL("$"+strconv.Itoa(len(args)+1)+"::bigint") + `)`
		args = append(args, c.User.ID)
		var owns bool
		if err := s.db.QueryRow(ctx, `select exists (select 1 from project_members pm where pm.role = 'owner' and `+memberMatchSQL("$1::bigint")+`)`,
			c.User.ID).Scan(&owns); err != nil {
			writeInternal(w, "audit list", err)
			return
		}
		if !owns {
			writeErr(w, 403, "forbidden", "권한이 없습니다.")
			return
		}
		if key := q.Get("project"); key != "" {
			var ok bool
			if err := s.db.QueryRow(ctx, `select exists (select 1 from project_members pm join projects p on p.id = pm.project_id
				where p.key = $2 and pm.role = 'owner' and `+memberMatchSQL("$1::bigint")+`)`, c.User.ID, key).Scan(&ok); err != nil {
				writeInternal(w, "audit list", err)
				return
			}
			if !ok {
				writeErr(w, 403, "forbidden", "권한이 없습니다.")
				return
			}
		}
	}
	items, err := collect[auditEntry](ctx, s, `select a.id, a.at, a.actor_user, a.actor_token, a.ip, a.action, a.project_id, a.target, a.details,
			coalesce(u.username, ''), coalesce(p.key, a.details->>'project_key', '')
		from audit_log a left join users u on u.id = a.actor_user left join projects p on p.id = a.project_id where `+where+
		` order by a.id desc limit `+strconv.Itoa(limit+1), args...)
	if err != nil {
		writeInternal(w, "audit list", err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		n := strconv.FormatInt(items[limit-1].ID, 10)
		next = &n
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

// audit records an action by the caller in c (user or token). A failed write is logged, never fatal.
// The project's key is copied into details.project_key: project_id is set null when the project is deleted.
func (s *server) audit(ctx context.Context, c *reqCtx, action string, projectID *int64, target string, details map[string]any) {
	var userID, tokenID *int64
	ip := ""
	if c != nil {
		if c.User != nil {
			userID = &c.User.ID
		}
		if c.Token != nil {
			tokenID = &c.Token.ID
		}
		ip = c.IP
	}
	if details == nil {
		details = map[string]any{}
	}
	_, err := s.db.Exec(context.WithoutCancel(ctx), `insert into audit_log(actor_user, actor_token, ip, action, project_id, target, details)
		values($1, $2, $3, $4, $5, $6, $7::jsonb || coalesce((select jsonb_build_object('project_key', key) from projects where id = $5), '{}'))`,
		userID, tokenID, ip, action, projectID, target, details)
	if err != nil {
		log.Printf("audit %s: %v", action, err)
	}
}
