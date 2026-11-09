package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *server) projectRoutes() {
	s.handle("GET /api/v1/projects", permUser, s.handleProjectList)
	s.handle("POST /api/v1/projects", permUser, s.handleProjectCreate)
	s.handle("GET /api/v1/projects/{key}", permProj("viewer"), s.handleProjectGet)
	s.handle("PATCH /api/v1/projects/{key}", permProj("owner"), s.handleProjectPatch)
	s.handle("DELETE /api/v1/projects/{key}", permProj("owner"), s.handleProjectDelete)
	s.handle("GET /api/v1/projects/{key}/members", permProj("viewer"), s.handleMembersGet)
	s.handle("PUT /api/v1/projects/{key}/members", permProj("owner"), s.handleMembersPut)
	s.handle("GET /api/v1/projects/{key}/policy", permProj("viewer"), s.handlePolicyGet)
	s.handle("PUT /api/v1/projects/{key}/policy", permProj("owner"), s.handlePolicyPut)
	s.handle("GET /api/v1/projects/{key}/notify", permProj("viewer"), s.handleNotifyGet)
	s.handle("PUT /api/v1/projects/{key}/notify", permProj("owner"), s.handleNotifyPut)
	s.handle("GET /api/v1/projects/{key}/targets", permProj("viewer"), s.handleTargetList)
}

var projectKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)

func badRequest(w http.ResponseWriter, msg string) { writeErr(w, 400, "bad_request", msg) }

func isUniqueViolation(err error) bool {
	pe, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pe.Code == "23505"
}

// sevCounts are the open findings by severity, plus the open total.
type sevCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Open     int `json:"open"`
}

// openCountsSQL is a subquery of sevCounts' six columns over the open findings (alias f) matching where.
func openCountsSQL(where string) string {
	return `(select count(*) filter (where f.severity = 'CRITICAL'), count(*) filter (where f.severity = 'HIGH'),
		count(*) filter (where f.severity = 'MEDIUM'), count(*) filter (where f.severity = 'LOW'),
		count(*) filter (where f.severity = 'UNKNOWN'), count(*) from findings f where f.status = 'open' and ` + where + `)`
}

type projectView struct {
	project
	MyRole     string     `json:"my_role"`
	Counts     sevCounts  `json:"counts"`
	LastScanAt *time.Time `json:"last_scan_at"`
}

// projectViews returns the projects u can see, or with onlyID > 0 just that one (the caller has authorized it).
func (s *server) projectViews(ctx context.Context, u *user, onlyID int64) ([]projectView, error) {
	cond, args := "p.id = $2", []any{onlyID}
	if onlyID == 0 {
		cond, args = s.visibleProjectsSQL(u, "p", 2)
	}
	var uid int64
	if u != nil {
		uid = u.ID
	}
	rows, err := s.db.Query(ctx, `select p.id, p.key, p.name, p.description, p.created_by, p.created_at,
			(select coalesce(max(case pm.role when 'owner' then 3 when 'member' then 2 when 'viewer' then 1 end), 0)
				from project_members pm where pm.project_id = p.id and `+memberMatchSQL("$1::bigint")+`),
			fc.*, (select max(t.last_scan_at) from targets t where t.project_id = p.id)
		from (select *, id as project_id from projects) p cross join lateral `+openCountsSQL("f.project_id = p.id")+` fc
		where `+cond+` order by p.key`, append([]any{uid}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []projectView{}
	for rows.Next() {
		var v projectView
		var rank int
		c := &v.Counts
		if err := rows.Scan(&v.ID, &v.Key, &v.Name, &v.Description, &v.CreatedBy, &v.CreatedAt, &rank,
			&c.Critical, &c.High, &c.Medium, &c.Low, &c.Unknown, &c.Open, &v.LastScanAt); err != nil {
			return nil, err
		}
		if u != nil {
			v.MyRole = roleFor(u, rank)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *server) handleProjectList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	list, err := s.projectViews(r.Context(), c.User, 0)
	if err != nil {
		writeInternal(w, "project list", err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *server) writeProject(w http.ResponseWriter, r *http.Request, c *reqCtx, status int) {
	list, err := s.projectViews(r.Context(), c.User, c.Project.ID)
	if err == nil && len(list) != 1 { // deleted while this request ran
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "project get", err)
		return
	}
	list[0].MyRole = c.Role
	writeJSON(w, status, list[0])
}

func (s *server) handleProjectGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	s.writeProject(w, r, c, 200)
}

func validProjectText(name, desc string) string {
	if name == "" || utf8.RuneCountInString(name) > 100 {
		return "프로젝트 이름은 1~100자로 입력하세요."
	}
	if utf8.RuneCountInString(desc) > 2000 {
		return "설명은 2000자 이하로 입력하세요."
	}
	return ""
}

func (s *server) handleProjectCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var req struct{ Key, Name, Description string }
	if err := readJSON(r, 16<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	req.Name, req.Description = strings.TrimSpace(req.Name), strings.TrimSpace(req.Description)
	if !projectKeyRe.MatchString(req.Key) {
		badRequest(w, "프로젝트 키는 영문 소문자·숫자·하이픈 2~40자이고 하이픈으로 시작할 수 없습니다.")
		return
	}
	if msg := validProjectText(req.Name, req.Description); msg != "" {
		badRequest(w, msg)
		return
	}
	var id int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `insert into projects(key, name, description, created_by) values($1, $2, $3, $4) returning id`,
			req.Key, req.Name, req.Description, c.User.ID).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `insert into project_members(project_id, principal_kind, principal, role) values($1, 'user', $2, 'owner')`,
			id, strconv.FormatInt(c.User.ID, 10))
		return err
	})
	if isUniqueViolation(err) {
		writeErr(w, 409, "conflict", "이미 있는 프로젝트 키입니다.")
		return
	}
	if err != nil {
		writeInternal(w, "project create", err)
		return
	}
	s.audit(ctx, c, "project.create", &id, req.Key, map[string]any{"name": req.Name})
	if c.Project, err = s.projectByID(ctx, id); err != nil {
		writeInternal(w, "project create", err)
		return
	}
	c.Role = "owner"
	s.writeProject(w, r, c, 201)
}

func (s *server) handleProjectPatch(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var req struct{ Name, Description *string }
	if err := readJSON(r, 16<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	name, desc := c.Project.Name, c.Project.Description
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	if msg := validProjectText(name, desc); msg != "" {
		badRequest(w, msg)
		return
	}
	if _, err := s.db.Exec(ctx, `update projects set name=$2, description=$3 where id=$1`, c.Project.ID, name, desc); err != nil {
		writeInternal(w, "project patch", err)
		return
	}
	s.audit(ctx, c, "project.update", &c.Project.ID, c.Project.Key, map[string]any{"name": name, "description": desc})
	s.writeProject(w, r, c, 200)
}

func (s *server) handleProjectDelete(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	if _, err := s.db.Exec(ctx, `delete from projects where id=$1`, c.Project.ID); err != nil {
		writeInternal(w, "project delete", err)
		return
	}
	// the project row is gone, so the audit row names it by key and id only
	s.audit(ctx, c, "project.delete", nil, c.Project.Key, map[string]any{"project_id": c.Project.ID, "name": c.Project.Name})
	w.WriteHeader(204)
}

// --- members ---

type member struct {
	PrincipalKind string `json:"principal_kind"`
	Principal     string `json:"principal"`
	Role          string `json:"role"`
	Display       string `json:"display"` // ignored on PUT
}

func (s *server) handleMembersGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select pm.principal_kind, pm.principal, pm.role,
			coalesce(nullif(u.name, ''), u.username, pm.principal)
		from project_members pm left join users u on pm.principal_kind = 'user' and u.id::text = pm.principal
		where pm.project_id = $1 order by pm.principal_kind, coalesce(u.username, pm.principal)`, c.Project.ID)
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[member])
	if err != nil {
		writeInternal(w, "members get", err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *server) handleMembersPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var list []member
	if err := readJSON(r, 256<<10, &list); err != nil {
		writeBodyErr(w, err)
		return
	}
	if len(list) > 500 {
		badRequest(w, "멤버는 500개까지 지정할 수 있습니다.")
		return
	}
	seen := map[string]bool{}
	var userIDs []int64
	owners := 0
	for i := range list {
		m := &list[i]
		m.Display = ""
		switch m.PrincipalKind {
		case "user":
			id, err := strconv.ParseInt(m.Principal, 10, 64)
			if err != nil || id <= 0 || strconv.FormatInt(id, 10) != m.Principal {
				badRequest(w, "사용자 멤버는 사용자 ID로 지정하세요.")
				return
			}
			userIDs = append(userIDs, id)
		case "group":
			if !strings.HasPrefix(m.Principal, "/") || len(m.Principal) < 2 || len(m.Principal) > 512 {
				badRequest(w, "그룹·부서 멤버는 /로 시작하는 경로로 지정하세요.")
				return
			}
		default:
			badRequest(w, "멤버 종류는 user 또는 group입니다.")
			return
		}
		if rankRole(m.Role) == 0 {
			badRequest(w, "역할은 owner, member, viewer 중 하나입니다.")
			return
		}
		if k := m.PrincipalKind + " " + m.Principal; seen[k] {
			badRequest(w, "같은 멤버가 두 번 있습니다.")
			return
		} else {
			seen[k] = true
		}
		if m.Role == "owner" {
			owners++
		}
	}
	if owners == 0 {
		badRequest(w, "owner가 최소 한 명은 있어야 합니다.")
		return
	}
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `select count(*) from users where id = any($1)`, userIDs).Scan(&n); err != nil {
			return err
		}
		if n != len(userIDs) {
			return errBadMember
		}
		// one member replacement at a time per project
		if _, err := tx.Exec(ctx, `select 1 from projects where id=$1 for update`, c.Project.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `delete from project_members where project_id=$1`, c.Project.ID); err != nil {
			return err
		}
		for _, m := range list {
			if _, err := tx.Exec(ctx, `insert into project_members(project_id, principal_kind, principal, role) values($1, $2, $3, $4)`,
				c.Project.ID, m.PrincipalKind, m.Principal, m.Role); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errBadMember) {
		badRequest(w, "없는 사용자가 포함되어 있습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "members put", err)
		return
	}
	s.audit(ctx, c, "project.members", &c.Project.ID, c.Project.Key, map[string]any{"members": list})
	w.WriteHeader(204)
}

var errBadMember = errors.New("unknown user in member list")

// --- policy ---

type policy struct {
	Enabled     bool   `json:"enabled"`
	MinSeverity string `json:"min_severity"`
	MaxCount    int    `json:"max_count"`
	NewOnly     bool   `json:"new_only"`
	FixableOnly bool   `json:"fixable_only"`
}

var policySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// projectPolicy is the project's policy row, else the setting default_policy, else enabled/CRITICAL/0.
func (s *server) projectPolicy(ctx context.Context, projectID int64) (policy, error) {
	var p policy
	err := s.db.QueryRow(ctx, `select enabled, min_severity, max_count, new_only, fixable_only from policies where project_id=$1`,
		projectID).Scan(&p.Enabled, &p.MinSeverity, &p.MaxCount, &p.NewOnly, &p.FixableOnly)
	if !errors.Is(err, pgx.ErrNoRows) {
		return p, err
	}
	p = policy{Enabled: true, MinSeverity: "CRITICAL"}
	_, err = s.getSetting(ctx, "default_policy", &p)
	return p, err
}

func (s *server) handlePolicyGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	p, err := s.projectPolicy(r.Context(), c.Project.ID)
	if err != nil {
		writeInternal(w, "policy get", err)
		return
	}
	writeJSON(w, 200, p)
}

// handlePolicyPut stores the policy; omitted fields keep their current values.
func (s *server) handlePolicyPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	p, err := s.projectPolicy(ctx, c.Project.ID)
	if err != nil {
		writeInternal(w, "policy put", err)
		return
	}
	if err := readJSON(r, 4<<10, &p); err != nil {
		writeBodyErr(w, err)
		return
	}
	if !slices.Contains(policySeverities, p.MinSeverity) {
		badRequest(w, "심각도 기준은 CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN 중 하나입니다.")
		return
	}
	if p.MaxCount < 0 {
		badRequest(w, "허용 개수는 0 이상이어야 합니다.")
		return
	}
	_, err = s.db.Exec(ctx, `insert into policies(project_id, enabled, min_severity, max_count, new_only, fixable_only)
		values($1, $2, $3, $4, $5, $6) on conflict (project_id) do update set enabled=excluded.enabled,
		min_severity=excluded.min_severity, max_count=excluded.max_count, new_only=excluded.new_only, fixable_only=excluded.fixable_only`,
		c.Project.ID, p.Enabled, p.MinSeverity, p.MaxCount, p.NewOnly, p.FixableOnly)
	if err != nil {
		writeInternal(w, "policy put", err)
		return
	}
	s.audit(ctx, c, "policy.update", &c.Project.ID, c.Project.Key, map[string]any{"policy": p})
	writeJSON(w, 200, p)
}

// --- notification subscriptions (channels and delivery are Task 12) ---

var notifyEvents = []string{"new_critical", "policy_failed", "scan_failed", "exception_requested", "exception_approved",
	"exception_rejected", "exception_expiring", "exception_expired", "new_known"}

type notifySub struct {
	ChannelID int64    `json:"channel_id"`
	Events    []string `json:"events"`
}

func (s *server) handleNotifyGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select channel_id, events from notify_subs where project_id=$1 order by channel_id`, c.Project.ID)
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[notifySub])
	if err != nil {
		writeInternal(w, "notify get", err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *server) handleNotifyPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var list []notifySub
	if err := readJSON(r, 64<<10, &list); err != nil {
		writeBodyErr(w, err)
		return
	}
	if len(list) > 100 {
		badRequest(w, "구독은 100개까지 지정할 수 있습니다.")
		return
	}
	var ids []int64
	for i := range list {
		sub := &list[i]
		if slices.Contains(ids, sub.ChannelID) {
			badRequest(w, "같은 채널이 두 번 있습니다.")
			return
		}
		ids = append(ids, sub.ChannelID)
		slices.Sort(sub.Events)
		sub.Events = slices.Compact(sub.Events)
		if len(sub.Events) == 0 {
			badRequest(w, "채널마다 이벤트를 하나 이상 고르세요.")
			return
		}
		for _, e := range sub.Events {
			if !slices.Contains(notifyEvents, e) {
				badRequest(w, "알 수 없는 알림 이벤트입니다.")
				return
			}
		}
	}
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `select count(*) from notify_channels where id = any($1)`, ids).Scan(&n); err != nil {
			return err
		}
		if n != len(ids) {
			return errBadChannel
		}
		if _, err := tx.Exec(ctx, `select 1 from projects where id=$1 for update`, c.Project.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `delete from notify_subs where project_id=$1`, c.Project.ID); err != nil {
			return err
		}
		for _, sub := range list {
			if _, err := tx.Exec(ctx, `insert into notify_subs(project_id, channel_id, events) values($1, $2, $3)`,
				c.Project.ID, sub.ChannelID, sub.Events); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errBadChannel) {
		badRequest(w, "없는 알림 채널입니다.")
		return
	}
	if err != nil {
		writeInternal(w, "notify put", err)
		return
	}
	s.audit(ctx, c, "notify.update", &c.Project.ID, c.Project.Key, map[string]any{"subs": list})
	w.WriteHeader(204)
}

var errBadChannel = errors.New("unknown notify channel")

// --- targets ---

type targetView struct {
	ID              int64      `json:"id"`
	Kind            string     `json:"kind"`
	Name            string     `json:"name"`
	LastScanAt      *time.Time `json:"last_scan_at"`
	Counts          sevCounts  `json:"counts"`
	RecheckExcluded bool       `json:"recheck_excluded"`
}

func (s *server) handleTargetList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, err := s.db.Query(r.Context(), `select t.id, t.kind, t.name, t.last_scan_at, t.recheck_excluded, fc.*
		from targets t cross join lateral `+openCountsSQL("f.target_id = t.id")+` fc
		where t.project_id = $1 order by t.name, t.kind`, c.Project.ID)
	if err != nil {
		writeInternal(w, "target list", err)
		return
	}
	defer rows.Close()
	list := []targetView{}
	for rows.Next() {
		var v targetView
		k := &v.Counts
		if err := rows.Scan(&v.ID, &v.Kind, &v.Name, &v.LastScanAt, &v.RecheckExcluded,
			&k.Critical, &k.High, &k.Medium, &k.Low, &k.Unknown, &k.Open); err != nil {
			writeInternal(w, "target list", err)
			return
		}
		list = append(list, v)
	}
	if err := rows.Err(); err != nil {
		writeInternal(w, "target list", err)
		return
	}
	writeJSON(w, 200, list)
}
