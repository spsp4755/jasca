package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Remediation deadlines and assignees: who fixes a finding, and by when (migration 006).

func init() {
	routeRegistrars = append(routeRegistrars, (*server).dueRoutes)
	workerStarters = append(workerStarters, func(ctx context.Context, s *server) { s.runDueNotices(ctx) })
}

func (s *server) dueRoutes() {
	s.handle("GET /api/v1/admin/sla", permAdmin, s.handleSLAGet)
	s.handle("PUT /api/v1/admin/sla", permAdmin, s.handleSLAPut)
	// viewer so that the finding resolves for everyone who can see it; who may change it is canTriage, checked inside
	s.handle("PATCH /api/v1/findings/{id}", permObj("finding", "viewer"), s.handleFindingPatch)
	s.handle("POST /api/v1/findings/assign", permUser, s.handleFindingAssign)
	s.handle("GET /api/v1/projects/{key}/assignees", permProj("viewer"), s.handleAssignees)
}

// --- the deadline rule ---

// slaDaysSQL is the days object of settings['sla'] ({"CRITICAL": 7, ...}), null while deadlines are switched off.
const slaDaysSQL = `(select case when (value->>'enabled')::boolean then value->'days' end from settings where key = 'sla')`

// dueExprSQL is the deadline finding f should have: none unless it is open; the date a person set; else open_since
// plus the days of its severity (none configured: no deadline).
const dueExprSQL = `(case when f.status <> 'open' then null when f.due_manual then f.due_at
	else f.open_since + make_interval(days => (` + slaDaysSQL + `->>f.severity)::int) end)`

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// applyDue applies the deadline rule to the findings matching cond (an SQL condition on f) in one statement and
// returns how many changed. Call it after anything that changes an input: status, severity, open_since, due_manual,
// the setting. A finding that stops being open loses its deadline, a manual one included: a deadline belongs to one
// open period. A changed deadline is announced again (due_warned, overdue_notified).
func applyDue(ctx context.Context, q execer, cond string, args ...any) (int64, error) {
	tag, err := q.Exec(ctx, `update findings f set due_at = `+dueExprSQL+`, due_manual = f.due_manual and f.status = 'open',
			due_warned = false, overdue_notified = false
		where `+cond+` and (`+dueExprSQL+` is distinct from f.due_at or f.due_manual and f.status <> 'open')`, args...)
	return tag.RowsAffected(), err
}

// --- the setting ---

// slaSetting is settings['sla']. Days maps CRITICAL, HIGH, MEDIUM and LOW to the days a finding of that severity
// may stay open; a severity left out or null has no deadline, and UNKNOWN never has one.
type slaSetting struct {
	Enabled bool            `json:"enabled"`
	Days    map[string]*int `json:"days"`
}

func (s *server) handleSLAGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	st := slaSetting{Days: map[string]*int{}}
	if _, err := s.getSetting(r.Context(), "sla", &st); err != nil {
		writeInternal(w, "sla get", err)
		return
	}
	writeJSON(w, 200, st)
}

// handleSLAPut replaces the setting (both fields, so that a body without days cannot wipe every deadline) and
// recalculates every open finding whose deadline nobody set by hand.
func (s *server) handleSLAPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var st slaSetting
	if err := readJSON(r, 4<<10, &st); err != nil {
		writeBodyErr(w, err)
		return
	}
	bad := st.Days == nil
	for sev, d := range st.Days {
		bad = bad || !slices.Contains(policySeverities[:4], sev) || d != nil && (*d < 1 || *d > 3650)
	}
	if bad {
		badRequest(w, "days에 CRITICAL, HIGH, MEDIUM, LOW의 기한을 1~3650일 또는 기한 없음(null)으로 보내세요. UNKNOWN에는 기한을 둘 수 없습니다.")
		return
	}
	if err := s.putSetting(ctx, "sla", st); err != nil {
		writeInternal(w, "sla put", err)
		return
	}
	n, err := applyDue(ctx, s.db, "true")
	if err != nil { // the setting is saved; the next start applies it (newServer)
		writeInternal(w, "sla recalculate", err)
		return
	}
	s.audit(ctx, c, "sla.update", nil, "", map[string]any{"enabled": st.Enabled, "days": st.Days, "recalculated": n})
	writeJSON(w, 200, map[string]any{"enabled": st.Enabled, "days": st.Days, "changed": n})
}

// --- assigning and setting a deadline by hand ---

type assigneeView struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"` // the person's name, else the username
	Username string `json:"username"`
	Active   bool   `json:"active"` // false: the account was deactivated after the assignment
}

// display is the assignee's name for text outputs (CSV, MCP), "" when nobody is assigned.
func (a *assigneeView) display() string {
	switch {
	case a == nil:
		return ""
	case !a.Active:
		return a.Name + " (비활성)"
	}
	return a.Name
}

// assigneeSQL is the assigneeView of finding f as one JSON column, null when nobody is assigned.
const assigneeSQL = `(select jsonb_build_object('id', u.id, 'name', coalesce(nullif(u.name, ''), u.username), 'username', u.username,
	'active', u.active) from users u where u.id = f.assignee_id)`

// canTriage: a member or owner of the finding's project, or a security user or admin anywhere, may assign it and
// set its deadline.
func canTriage(u *user, role string) bool {
	return rankRole(role) >= rankRole("member") || isSecurity(u)
}

// nullableID reads a JSON field that is a positive id or null (nil). ok is false for anything else, a missing field included.
func nullableID(raw json.RawMessage) (id *int64, ok bool) {
	if string(raw) == "null" {
		return nil, true
	}
	var n int64
	if json.Unmarshal(raw, &n) != nil || n < 1 {
		return nil, false
	}
	return &n, true
}

// assignee checks that user id may be given findings of the projects: an active user who can see each of them, by
// the rule every route uses (projectRole). It returns the name to show, or a Korean reason why not.
func (s *server) assignee(ctx context.Context, id int64, projects []int64) (name, problem string, err error) {
	u := &user{ID: id}
	var active bool
	err = s.db.QueryRow(ctx, `select system_role, active, coalesce(nullif(name, ''), username) from users where id = $1`, id).
		Scan(&u.SystemRole, &active, &name)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		return "", "담당자로 지정할 수 없는 사용자입니다. 활성 사용자만 지정할 수 있습니다.", nil
	}
	if err != nil {
		return "", "", err
	}
	for _, pid := range projects {
		role, err := projectRole(s, ctx, u, pid)
		if err != nil {
			return "", "", err
		}
		if role == "" {
			return "", name + " 님은 이 프로젝트를 볼 수 없어 담당자로 지정할 수 없습니다. 먼저 프로젝트 멤버로 추가하세요.", nil
		}
	}
	return name, "", nil
}

func assignDetails(d map[string]any, assignee *int64, name string) map[string]any {
	if assignee == nil {
		d["unassigned"] = true
	} else {
		d["assignee"] = name
	}
	return d
}

// handleFindingPatch changes who fixes one finding (assignee_id: a user id, or null for nobody) and by when (due_at:
// "YYYY-MM-DD", the end of that day in JASCA_TZ, or null to hand the deadline back to the rule). A field left out
// stays as it is. A past date is fine (a missed deadline put on record), but only an open finding has a deadline.
func (s *server) handleFindingPatch(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx, id := r.Context(), pathID(r)
	if !canTriage(c.User, c.Role) {
		writeErr(w, 403, "forbidden", "담당자와 기한은 프로젝트 멤버나 보안 담당자가 바꿀 수 있습니다.")
		return
	}
	var in struct {
		AssigneeID json.RawMessage `json:"assignee_id"`
		DueAt      json.RawMessage `json:"due_at"`
	}
	if err := readJSON(r, 4<<10, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	if in.AssigneeID == nil && in.DueAt == nil {
		badRequest(w, "assignee_id 또는 due_at을 보내세요.")
		return
	}
	var assignee *int64
	var name string
	if in.AssigneeID != nil {
		var ok bool
		if assignee, ok = nullableID(in.AssigneeID); !ok {
			badRequest(w, "assignee_id는 사용자 ID 또는 null입니다.")
			return
		}
		if assignee != nil {
			var problem string
			var err error
			if name, problem, err = s.assignee(ctx, *assignee, []int64{c.Project.ID}); err != nil {
				writeInternal(w, "finding assignee", err)
				return
			}
			if problem != "" {
				badRequest(w, problem)
				return
			}
		}
	}
	var due *time.Time
	if in.DueAt != nil && string(in.DueAt) != "null" {
		var day string
		json.Unmarshal(in.DueAt, &day) // not a string: day stays "" and does not parse
		d, err := time.ParseInLocation(time.DateOnly, day, s.cfg.Loc)
		if err != nil {
			badRequest(w, "due_at은 YYYY-MM-DD 날짜 또는 null입니다.")
			return
		}
		due = new(time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, s.cfg.Loc))
		if far := time.Until(*due).Abs(); far > 3650*24*time.Hour {
			badRequest(w, "기한은 오늘부터 앞뒤 10년 안의 날짜여야 합니다.")
			return
		}
	}
	var rule, pkg, status string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `select rule_id, pkg_name, status from findings where id = $1 for update`, id).Scan(&rule, &pkg, &status); err != nil {
			return err
		}
		if due != nil && status != "open" {
			return nil // answered below; nothing is written
		}
		if in.AssigneeID != nil {
			if _, err := tx.Exec(ctx, `update findings set assignee_id = $2 where id = $1`, id, assignee); err != nil {
				return err
			}
		}
		switch {
		case due != nil: // the same date again is not a new deadline to announce
			_, err := tx.Exec(ctx, `update findings set due_manual = true, due_warned = due_warned and due_at is not distinct from $2,
				overdue_notified = overdue_notified and due_at is not distinct from $2, due_at = $2 where id = $1`, id, due)
			return err
		case in.DueAt != nil:
			if _, err := tx.Exec(ctx, `update findings set due_manual = false where id = $1`, id); err != nil {
				return err
			}
			_, err := applyDue(ctx, tx, "f.id = $1", id)
			return err
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) { // deleted while this request ran
		notFoundErr(w)
		return
	}
	if err != nil {
		writeInternal(w, "finding patch", err)
		return
	}
	if due != nil && status != "open" {
		writeErr(w, 409, "conflict", "열린 결과에만 기한을 정할 수 있습니다. 해결되었거나 예외 처리된 결과에는 기한이 없습니다.")
		return
	}
	target := strings.TrimSuffix(rule+" · "+pkg, " · ")
	if in.AssigneeID != nil {
		s.audit(ctx, c, "finding.assign", &c.Project.ID, target, assignDetails(map[string]any{"finding_id": id}, assignee, name))
	}
	if due != nil {
		s.audit(ctx, c, "finding.due", &c.Project.ID, target, map[string]any{"finding_id": id, "due_at": due})
	} else if in.DueAt != nil {
		s.audit(ctx, c, "finding.due", &c.Project.ID, target, map[string]any{"finding_id": id, "auto": true})
	}
	s.handleFindingGet(w, r, c)
}

// handleFindingAssign gives up to 500 findings to one person (assignee_id null: to nobody), all or nothing. The
// caller needs canTriage on every finding's project; a finding they cannot see answers 404 like one that is not there.
func (s *server) handleFindingAssign(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var in struct {
		IDs        []int64         `json:"ids"`
		AssigneeID json.RawMessage `json:"assignee_id"`
	}
	if err := readJSON(r, 64<<10, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	slices.Sort(in.IDs)
	in.IDs = slices.Compact(in.IDs)
	assignee, ok := nullableID(in.AssigneeID)
	if len(in.IDs) == 0 || len(in.IDs) > 500 || !ok {
		badRequest(w, "ids는 결과 ID 1~500개, assignee_id는 사용자 ID 또는 null이어야 합니다.")
		return
	}
	type group struct {
		Project int64
		IDs     []int64
	}
	rows, _ := s.db.Query(ctx, `select project_id, array_agg(id order by id) from findings where id = any($1) group by project_id order by project_id`, in.IDs)
	groups, err := pgx.CollectRows(rows, pgx.RowToStructByPos[group])
	if err != nil {
		writeInternal(w, "finding assign", err)
		return
	}
	var projects []int64
	found, forbidden := 0, false
	for _, g := range groups {
		role, err := projectRole(s, ctx, c.User, g.Project)
		if err != nil {
			writeInternal(w, "finding assign", err)
			return
		}
		if role != "" {
			found += len(g.IDs)
		}
		forbidden = forbidden || !canTriage(c.User, role)
		projects = append(projects, g.Project)
	}
	if found != len(in.IDs) { // an id that does not exist, or one of a project the caller cannot see
		notFoundErr(w)
		return
	}
	if forbidden {
		writeErr(w, 403, "forbidden", "보기 전용인 프로젝트의 결과가 들어 있습니다. 담당자는 프로젝트 멤버나 보안 담당자가 지정할 수 있습니다.")
		return
	}
	var name string
	if assignee != nil {
		var problem string
		if name, problem, err = s.assignee(ctx, *assignee, projects); err != nil {
			writeInternal(w, "finding assign", err)
			return
		}
		if problem != "" {
			badRequest(w, problem)
			return
		}
	}
	tag, err := s.db.Exec(ctx, `update findings set assignee_id = $2 where id = any($1)`, in.IDs, assignee)
	if err != nil {
		writeInternal(w, "finding assign", err)
		return
	}
	for _, g := range groups {
		s.audit(ctx, c, "finding.assign", &g.Project, "", assignDetails(map[string]any{"count": len(g.IDs), "finding_ids": g.IDs}, assignee, name))
	}
	writeJSON(w, 200, map[string]any{"updated": tag.RowsAffected()})
}

// handleAssignees lists who can be given the project's findings, for the picker: active users who can see the
// project (admin and security see every project, everyone else by membership), up to 20, filtered by ?q=.
func (s *server) handleAssignees(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) > 100 {
		badRequest(w, "검색어가 너무 깁니다.")
		return
	}
	list, err := collect[assigneeView](r.Context(), s, `select u.id, coalesce(nullif(u.name, ''), u.username), u.username, u.active from users u
		where u.active and (u.username ilike $2 or u.name ilike $2 or u.email ilike $2)
			and (u.system_role in ('admin', 'security') or exists (select 1 from project_members pm
				where pm.project_id = $1 and `+memberMatchSQL("u.id")+`))
		order by u.username limit 20`, c.Project.ID, "%"+likeEscaper.Replace(q)+"%")
	if err != nil {
		writeInternal(w, "assignees", err)
		return
	}
	writeJSON(w, 200, list)
}

// --- notices ---

// runDueNotices runs notifyDue every hour until ctx ends.
func (s *server) runDueNotices(ctx context.Context) {
	for {
		s.notifyDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// notifyDue announces, once per deadline, the open findings that are past it (overdue) and those within 3 days of
// it (due_soon): one event per project and kind with the counts by severity and the five most severe findings.
// Overdue goes first and also marks the warning as given, so a deadline already missed is not "soon" as well.
func (s *server) notifyDue(ctx context.Context) {
	for _, ev := range []struct{ event, set, cond string }{
		{"overdue", "overdue_notified = true, due_warned = true", "f.due_at < now() and not f.overdue_notified"},
		{"due_soon", "due_warned = true", "f.due_at >= now() and f.due_at < now() + interval '3 days' and not f.due_warned"},
	} {
		type hit struct {
			Project                     int64
			Severity, Rule, Pkg, Target string
			DueAt                       time.Time
			Assignee                    string
		}
		hits, err := collect[hit](ctx, s, `with h as (update findings f set `+ev.set+` where f.status = 'open' and `+ev.cond+`
				returning f.id, f.project_id, f.target_id, f.severity, f.rule_id, f.pkg_name, f.due_at, f.assignee_id)
			select h.project_id, h.severity, h.rule_id, h.pkg_name, t.name, h.due_at,
				coalesce((select coalesce(nullif(u.name, ''), u.username) from users u where u.id = h.assignee_id), '')
			from h join targets t on t.id = h.target_id
			order by h.project_id, array_position(array['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'], h.severity), h.due_at, h.id`)
		if err != nil {
			log.Printf("due notices (%s): %v", ev.event, err)
			continue
		}
		for len(hits) > 0 {
			n := slices.IndexFunc(hits, func(h hit) bool { return h.Project != hits[0].Project })
			if n < 0 {
				n = len(hits)
			}
			p := map[string]any{"count": n}
			top := []map[string]any{}
			for i, h := range hits[:n] {
				k := strings.ToLower(h.Severity)
				c, _ := p[k].(int)
				p[k] = c + 1
				if i < 5 {
					top = append(top, map[string]any{"severity": h.Severity, "rule_id": h.Rule, "pkg": h.Pkg, "target": h.Target,
						"due_at": h.DueAt, "assignee": h.Assignee})
				}
			}
			p["top"] = top
			s.emit(ctx, hits[0].Project, ev.event, p)
			hits = hits[n:]
		}
	}
}
