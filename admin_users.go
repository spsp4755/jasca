package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).adminRoutes) }

func (s *server) adminRoutes() {
	s.handle("GET /api/v1/admin/users", permAdmin, s.handleAdminUsers)
	s.handle("PATCH /api/v1/admin/users/{id}", permAdmin, s.handleAdminUserPatch)
	s.handle("GET /api/v1/admin/retention", permAdmin, s.handleRetentionGet)
	s.handle("PUT /api/v1/admin/retention", permAdmin, s.handleRetentionPut)
	s.handle("GET /api/v1/admin/default-policy", permSecurity, s.handleDefaultPolicyGet)
	s.handle("PUT /api/v1/admin/default-policy", permSecurity, s.handleDefaultPolicyPut)
}

type adminUser struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Source      string     `json:"source"`
	SystemRole  string     `json:"system_role"`
	RoleFromSSO bool       `json:"role_from_sso"`
	Active      bool       `json:"active"`
	LastLoginAt *time.Time `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Depts       []string   `json:"depts"`
	Groups      []string   `json:"groups"`
}

func (s *server) handleAdminUsers(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	list, err := collect[adminUser](r.Context(), s, `select id, username, name, email, source, system_role, role_from_sso, active,
			last_login_at, created_at, array(select path from user_depts where user_id = u.id order by path),
			array(select path from user_groups where user_id = u.id order by path) from users u order by username`)
	if err != nil {
		writeInternal(w, "admin users", err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *server) handleAdminUserPatch(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx, id := r.Context(), pathID(r)
	var in struct {
		SystemRole *string `json:"system_role"`
		Active     *bool   `json:"active"`
	}
	if err := readJSON(r, 4<<10, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	if in.SystemRole != nil && !slices.Contains([]string{"", "admin", "security"}, *in.SystemRole) {
		badRequest(w, "역할은 빈 값, admin, security 중 하나입니다.")
		return
	}
	if id == c.User.ID && (in.SystemRole != nil && *in.SystemRole != "admin" || in.Active != nil && !*in.Active) {
		badRequest(w, "자기 자신의 관리자 권한을 내리거나 계정을 비활성화할 수 없습니다.")
		return
	}
	var name string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `select username from users where id = $1 for update`, id).Scan(&name); err != nil {
			return err
		}
		if in.SystemRole != nil {
			if _, err := tx.Exec(ctx, `update users set system_role = $2, role_from_sso = false where id = $1`, id, *in.SystemRole); err != nil {
				return err
			}
		}
		if in.Active != nil {
			if _, err := tx.Exec(ctx, `update users set active = $2, disabled_by_sync = false where id = $1`, id, *in.Active); err != nil {
				return err
			}
			if !*in.Active {
				_, err := tx.Exec(ctx, `delete from sessions where user_id = $1`, id)
				return err
			}
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "admin user patch", err)
		return
	}
	s.audit(ctx, c, "user.update", nil, name, map[string]any{"system_role": in.SystemRole, "active": in.Active})
	u, err := collect[adminUser](ctx, s, `select id, username, name, email, source, system_role, role_from_sso, active,
			last_login_at, created_at, array(select path from user_depts where user_id = u.id order by path),
			array(select path from user_groups where user_id = u.id order by path) from users u where id = $1`, id)
	if err != nil || len(u) != 1 {
		writeInternal(w, "admin user patch", err)
		return
	}
	writeJSON(w, 200, u[0])
}

// --- retention (read by trimRaw in ingest.go, and trimmed daily for every target) ---

type retention struct {
	RawPerTarget int `json:"raw_per_target"`
	RawDays      int `json:"raw_days"`
}

func (s *server) handleRetentionGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ret := retention{20, 90}
	if _, err := s.getSetting(r.Context(), "retention", &ret); err != nil {
		writeInternal(w, "retention", err)
		return
	}
	writeJSON(w, 200, ret)
}

func (s *server) handleRetentionPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ret := retention{20, 90}
	if _, err := s.getSetting(r.Context(), "retention", &ret); err != nil { // an omitted field keeps its stored value
		writeInternal(w, "retention", err)
		return
	}
	if err := readJSON(r, 4<<10, &ret); err != nil {
		writeBodyErr(w, err)
		return
	}
	if ret.RawPerTarget < 1 || ret.RawPerTarget > 100000 || ret.RawDays < 1 || ret.RawDays > 36500 {
		badRequest(w, "개수와 일수는 1 이상이어야 합니다.")
		return
	}
	if err := s.putSetting(r.Context(), "retention", ret); err != nil {
		writeInternal(w, "retention", err)
		return
	}
	s.audit(r.Context(), c, "retention.update", nil, "", map[string]any{"raw_per_target": ret.RawPerTarget, "raw_days": ret.RawDays})
	writeJSON(w, 200, ret)
}

// --- default policy (the fallback of projectPolicy for projects without their own row) ---

func (s *server) handleDefaultPolicyGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	p := policy{Enabled: true, MinSeverity: "CRITICAL"}
	if _, err := s.getSetting(r.Context(), "default_policy", &p); err != nil {
		writeInternal(w, "default policy", err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *server) handleDefaultPolicyPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	p := policy{Enabled: true, MinSeverity: "CRITICAL"}
	if _, err := s.getSetting(r.Context(), "default_policy", &p); err != nil {
		writeInternal(w, "default policy", err)
		return
	}
	if err := readJSON(r, 4<<10, &p); err != nil {
		writeBodyErr(w, err)
		return
	}
	if !slices.Contains(policySeverities, p.MinSeverity) || p.MaxCount < 0 {
		badRequest(w, "심각도 기준은 CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN 중 하나이고 허용 건수는 0 이상이어야 합니다.")
		return
	}
	if err := s.putSetting(r.Context(), "default_policy", p); err != nil {
		writeInternal(w, "default policy", err)
		return
	}
	s.audit(r.Context(), c, "default_policy.update", nil, "", map[string]any{"min_severity": p.MinSeverity, "max_count": p.MaxCount})
	writeJSON(w, 200, p)
}

// retentionLoop trims the raw reports of every target once a day (uploads only trim their own target) and
// purges expired sessions. Started from main like syncLoop.
func (s *server) retentionLoop(ctx context.Context) {
	for {
		if err := s.trimAllRaw(ctx); err != nil {
			log.Printf("retention: %v", err)
		}
		if _, err := s.db.Exec(ctx, `delete from sessions where expires_at <= now()`); err != nil {
			log.Printf("session purge: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func (s *server) trimAllRaw(ctx context.Context) error {
	ret := retention{20, 90}
	if _, err := s.getSetting(ctx, "retention", &ret); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `update scans set raw = null where raw is not null and created_at < now() - make_interval(days => $2)
		and id not in (select id from (select id, row_number() over (partition by target_id order by created_at desc, id desc) rn
			from scans) x where rn <= $1)`, ret.RawPerTarget, ret.RawDays)
	return err
}
