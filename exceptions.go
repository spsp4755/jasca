package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

func init() {
	routeRegistrars = append(routeRegistrars, (*server).exceptionRoutes)
	workerStarters = append(workerStarters, func(ctx context.Context, s *server) { s.runExceptionExpiry(ctx) })
}

// workerStarters are background loops main starts with the process context, after newServer.
var workerStarters []func(ctx context.Context, s *server)

type exception struct {
	ID           int64      `json:"id"`
	Scope        string     `json:"scope"`
	ProjectID    *int64     `json:"project_id"`
	FindingID    *int64     `json:"finding_id"`
	VulnID       *string    `json:"vuln_id"`
	Resolution   string     `json:"resolution"`
	Reason       string     `json:"reason"`
	Status       string     `json:"status"`
	RequestedBy  *int64     `json:"requested_by"`
	DecidedBy    *int64     `json:"decided_by"`
	DecidedAt    *time.Time `json:"decided_at"`
	DecisionNote string     `json:"decision_note"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	ProjectKey   *string    `json:"project_key"`
	// finding scope: what the finding is, so an approver sees what is being approved
	FindingRule     *string `json:"finding_rule"`
	FindingPkg      *string `json:"finding_pkg"`
	FindingSeverity *string `json:"finding_severity"`
}

const exceptionCols = `select e.id, e.scope, e.project_id, e.finding_id, e.vuln_id, e.resolution, e.reason, e.status, e.requested_by,
		e.decided_by, e.decided_at, e.decision_note, e.expires_at, e.created_at, p.key, f.rule_id, f.pkg_name, f.severity
	from exceptions e left join projects p on p.id = e.project_id left join findings f on f.id = e.finding_id `

func (s *server) exceptionRoutes() {
	s.handle("GET /api/v1/exceptions", permUser, s.handleExceptionList)
	s.handle("POST /api/v1/exceptions", permUser, s.handleExceptionCreate)
	s.handle("POST /api/v1/exceptions/{id}/approve", permSecurity, s.decideHandler("approved"))
	s.handle("POST /api/v1/exceptions/{id}/reject", permSecurity, s.decideHandler("rejected"))
	// permUser: a global exception has no project for an obj perm; the checks are inside and answer 404 like obj perms do
	s.handle("POST /api/v1/exceptions/{id}/revoke", permUser, s.handleExceptionRevoke)
}

func isSecurity(u *user) bool { return u.SystemRole == "admin" || u.SystemRole == "security" }

func (s *server) loadException(ctx context.Context, id int64) (*exception, error) {
	rows, _ := s.db.Query(ctx, exceptionCols+`where e.id = $1`, id)
	return pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByPos[exception])
}

// project exceptions follow project visibility; global ones (no project) are visible to every logged-in user
func (s *server) handleExceptionList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	cond, args := s.visibleProjectsSQL(c.User, "e", 1)
	wh := &where{conds: []string{"(e.project_id is null or " + cond + ")"}, args: args}
	q := r.URL.Query()
	if v := q.Get("status"); v != "" {
		wh.add("e.status = any(?)", strings.Split(v, ","))
	}
	if v := q.Get("project"); v != "" {
		wh.add("p.key = ?", v)
	}
	rows, _ := s.db.Query(r.Context(), exceptionCols+`where `+wh.sql()+` order by e.id desc limit 500`, wh.args...)
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[exception])
	if err != nil {
		writeInternal(w, "exception list", err)
		return
	}
	writeJSON(w, 200, items)
}

var errDupException = errors.New("a pending request for the same scope exists")

type exceptionReq struct {
	Scope      string  `json:"scope"`
	ProjectKey string  `json:"project_key"`
	FindingIDs []int64 `json:"finding_ids"`
	VulnID     string  `json:"vuln_id"`
	Resolution string  `json:"resolution"`
	Reason     string  `json:"reason"`
	ExpiresAt  string  `json:"expires_at"`
}

func notFoundErr(w http.ResponseWriter) { writeErr(w, 404, "not_found", "찾을 수 없습니다.") }

func (s *server) handleExceptionCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var req exceptionReq
	if err := readJSON(r, 1<<20, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	req.Reason, req.VulnID = strings.TrimSpace(req.Reason), strings.TrimSpace(req.VulnID)
	exp, err := time.Parse(time.RFC3339, req.ExpiresAt)
	switch {
	case req.Resolution != "accepted" && req.Resolution != "false_positive":
		badRequest(w, "처리 방식은 accepted 또는 false_positive입니다.")
	case req.Reason == "" || utf8.RuneCountInString(req.Reason) > 2000:
		badRequest(w, "사유를 1~2000자로 입력하세요.")
	case err != nil || !exp.After(time.Now()) || exp.After(time.Now().AddDate(0, 0, 365)):
		badRequest(w, "만료일은 지금 이후, 최대 365일 이내의 RFC3339 시각이어야 합니다.")
	default:
		goto valid
	}
	return
valid:
	type target struct {
		projectID *int64
		findingID *int64
	}
	var targets []target
	role := func(projectID int64) (ok bool) { // member on the project; 404 when invisible, 403 below member
		rl, err := projectRole(s, ctx, c.User, projectID)
		if err != nil {
			writeInternal(w, "exception role", err)
			return false
		}
		if rl == "" {
			notFoundErr(w)
			return false
		}
		if rankRole(rl) < rankRole("member") {
			writeErr(w, 403, "forbidden", "권한이 없습니다.")
			return false
		}
		return true
	}
	switch req.Scope {
	case "finding":
		slices.Sort(req.FindingIDs)
		req.FindingIDs = slices.Compact(req.FindingIDs)
		if len(req.FindingIDs) == 0 || len(req.FindingIDs) > 200 {
			badRequest(w, "finding_ids는 1~200개여야 합니다.")
			return
		}
		for _, id := range req.FindingIDs {
			var pid int64
			if err := s.db.QueryRow(ctx, `select project_id from findings where id = $1`, id).Scan(&pid); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					notFoundErr(w)
				} else {
					writeInternal(w, "exception finding", err)
				}
				return
			}
			if !role(pid) {
				return
			}
			targets = append(targets, target{&pid, new(int64(id))})
		}
	case "project_vuln", "global_vuln":
		if req.VulnID == "" || utf8.RuneCountInString(req.VulnID) > 200 {
			badRequest(w, "vuln_id를 입력하세요.")
			return
		}
		if req.Scope == "global_vuln" {
			if !isSecurity(c.User) {
				writeErr(w, 403, "forbidden", "전체 범위 예외는 보안 담당자만 요청할 수 있습니다.")
				return
			}
			targets = []target{{}}
			break
		}
		pr, err := s.projectByKey(ctx, req.ProjectKey)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				notFoundErr(w)
			} else {
				writeInternal(w, "exception project", err)
			}
			return
		}
		if !role(pr.ID) {
			return
		}
		targets = []target{{projectID: &pr.ID}}
	default:
		badRequest(w, "scope는 finding, project_vuln, global_vuln 중 하나입니다.")
		return
	}
	var vuln *string
	if req.Scope != "finding" {
		vuln = &req.VulnID
	}
	var ids []int64
	err = s.tx(ctx, func(tx pgx.Tx) error {
		for _, t := range targets {
			var dup bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from exceptions where status = 'pending' and scope = $1
				and project_id is not distinct from $2 and finding_id is not distinct from $3 and vuln_id is not distinct from $4)`,
				req.Scope, t.projectID, t.findingID, vuln).Scan(&dup); err != nil {
				return err
			}
			if dup {
				return errDupException
			}
			var id int64
			if err := tx.QueryRow(ctx, `insert into exceptions(scope, project_id, finding_id, vuln_id, resolution, reason, requested_by, expires_at)
				values($1, $2, $3, $4, $5, $6, $7, $8) returning id`, req.Scope, t.projectID, t.findingID, vuln, req.Resolution, req.Reason,
				c.User.ID, exp.UTC()).Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	if errors.Is(err, errDupException) {
		writeErr(w, 409, "conflict", "같은 대상에 승인 대기 중인 요청이 이미 있습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "exception create", err)
		return
	}
	out := make([]*exception, 0, len(ids))
	for _, id := range ids {
		ex, err := s.loadException(ctx, id)
		if err != nil {
			writeInternal(w, "exception load", err)
			return
		}
		out = append(out, ex)
		s.audit(ctx, c, "exception.request", ex.ProjectID, exTarget(ex), map[string]any{"exception_id": ex.ID, "scope": ex.Scope,
			"resolution": ex.Resolution, "expires_at": ex.ExpiresAt})
		s.emitException(ctx, "exception_requested", ex, "")
	}
	writeJSON(w, 201, out)
}

func exTarget(ex *exception) string {
	if ex.VulnID != nil {
		return *ex.VulnID
	}
	if ex.FindingID != nil {
		return "finding:" + itoa(*ex.FindingID)
	}
	return ""
}

// emitException sends an exception event to its project. A global exception has none, so it goes to every project
// with a finding of that vulnerability (the projects it affects).
func (s *server) emitException(ctx context.Context, event string, ex *exception, note string) {
	pids := []int64{}
	if ex.ProjectID != nil {
		pids = append(pids, *ex.ProjectID)
	} else if ex.VulnID != nil {
		rows, _ := s.db.Query(ctx, `select distinct project_id from findings where kind = 'vuln' and rule_id = $1 order by 1`, *ex.VulnID)
		var err error
		if pids, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			log.Printf("exception %d: projects for %s: %v", ex.ID, event, err)
			return
		}
	}
	p := map[string]any{"exception_id": ex.ID, "scope": ex.Scope, "vuln_id": ex.VulnID, "finding_id": ex.FindingID, "resolution": ex.Resolution,
		"reason": ex.Reason, "expires_at": ex.ExpiresAt, "project_key": ex.ProjectKey}
	if note != "" {
		p["note"] = note
	}
	for _, pid := range pids {
		s.emit(ctx, pid, event, p)
	}
}

func (s *server) decideHandler(to string) func(http.ResponseWriter, *http.Request, *reqCtx) {
	return func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		ctx := r.Context()
		var req struct {
			Note string `json:"note"`
		}
		if r.ContentLength != 0 {
			if err := readJSON(r, 1<<16, &req); err != nil {
				writeBodyErr(w, err)
				return
			}
		}
		id := pathID(r)
		ex, err := s.loadException(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				notFoundErr(w)
			} else {
				writeInternal(w, "exception load", err)
			}
			return
		}
		if ex.RequestedBy != nil && *ex.RequestedBy == c.User.ID {
			writeErr(w, 403, "forbidden", "본인이 요청한 예외는 직접 승인하거나 반려할 수 없습니다.")
			return
		}
		conflict := false
		err = s.tx(ctx, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `update exceptions set status = $2, decided_by = $3, decided_at = now(), decision_note = $4
				where id = $1 and status = 'pending' and expires_at > now() returning id`, id, to, c.User.ID, req.Note).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				conflict = true
				return nil
			}
			if err != nil || to != "approved" {
				return err
			}
			ex.Status = to
			return applyException(ctx, tx, ex)
		})
		if err != nil {
			writeInternal(w, "exception decide", err)
			return
		}
		if conflict {
			writeErr(w, 409, "conflict", "대기 중인 예외만 처리할 수 있습니다(이미 처리되었거나 만료되었습니다).")
			return
		}
		verb := map[string]string{"approved": "approve", "rejected": "reject"}[to]
		s.audit(ctx, c, "exception."+verb, ex.ProjectID, exTarget(ex), map[string]any{"exception_id": id, "note": req.Note})
		out, _ := s.loadException(ctx, id)
		if out != nil {
			s.emitException(ctx, "exception_"+to, out, req.Note)
			writeJSON(w, 200, out)
			return
		}
		writeJSON(w, 200, ex)
	}
}

func (s *server) handleExceptionRevoke(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	ex, err := s.loadException(ctx, pathID(r))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			notFoundErr(w)
		} else {
			writeInternal(w, "exception load", err)
		}
		return
	}
	requester := ex.RequestedBy != nil && *ex.RequestedBy == c.User.ID
	if ex.ProjectID != nil {
		role, err := projectRole(s, ctx, c.User, *ex.ProjectID)
		if err != nil {
			writeInternal(w, "exception role", err)
			return
		}
		if role == "" {
			notFoundErr(w)
			return
		}
	} else if !isSecurity(c.User) && !requester {
		notFoundErr(w)
		return
	}
	if ex.Status != "pending" && ex.Status != "approved" {
		writeErr(w, 409, "conflict", "이미 종료된 예외입니다.")
		return
	}
	if !isSecurity(c.User) && !(requester && ex.Status == "pending") {
		writeErr(w, 403, "forbidden", "대기 중인 본인 요청이거나 보안 담당자만 철회할 수 있습니다.")
		return
	}
	conflict := false
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx, `update exceptions set status = 'revoked', decided_by = $2, decided_at = now()
			where id = $1 and status in ('pending', 'approved') returning id`, ex.ID, c.User.ID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			conflict = true
			return nil
		}
		if err != nil {
			return err
		}
		return releaseException(ctx, tx, ex.ID)
	})
	if err != nil {
		writeInternal(w, "exception revoke", err)
		return
	}
	if conflict {
		writeErr(w, 409, "conflict", "이미 종료된 예외입니다.")
		return
	}
	s.audit(ctx, c, "exception.revoke", ex.ProjectID, exTarget(ex), map[string]any{"exception_id": ex.ID, "was": ex.Status})
	out, err := s.loadException(ctx, ex.ID)
	if err != nil {
		writeInternal(w, "exception load", err)
		return
	}
	writeJSON(w, 200, out)
}

// exceptionMatchSQL: finding f is covered by exception e.
const exceptionMatchSQL = `(e.scope = 'finding' and e.finding_id = f.id
	or e.scope = 'project_vuln' and f.kind = 'vuln' and e.project_id = f.project_id and e.vuln_id = f.rule_id
	or e.scope = 'global_vuln' and f.kind = 'vuln' and e.vuln_id = f.rule_id)`

// applyException sets the exception's resolution on the open findings in its scope.
func applyException(ctx context.Context, tx pgx.Tx, ex *exception) error {
	_, err := tx.Exec(ctx, `update findings f set status = e.resolution, exception_id = e.id from exceptions e
		where e.id = $1 and f.status = 'open' and `+exceptionMatchSQL, ex.ID)
	return err
}

// reapplyExceptions gives the open findings selected by cond (an SQL condition on f, with one arg) the resolution of an
// approved, unexpired exception that covers them. Used for new findings and after an exception ends.
func reapplyExceptions(ctx context.Context, tx pgx.Tx, cond string, arg any) error {
	_, err := tx.Exec(ctx, `update findings f set status = e.resolution, exception_id = e.id from exceptions e
		where e.status = 'approved' and e.expires_at > now() and f.status = 'open' and `+cond+` and `+exceptionMatchSQL, arg)
	return err
}

// releaseException takes the exception off its findings: accepted/false_positive go back to open (fixed stays fixed),
// then any other active exception that also covers them is applied again.
func releaseException(ctx context.Context, tx pgx.Tx, id int64) error {
	var projects []int64
	rows, _ := tx.Query(ctx, `update findings set exception_id = null,
			status = case when status in ('accepted', 'false_positive') then 'open' else status end
		where exception_id = $1 returning project_id`, id)
	projects, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil || len(projects) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `update findings f set status = e.resolution, exception_id = e.id from exceptions e
		where e.status = 'approved' and e.expires_at > now() and f.status = 'open' and f.project_id = any($1) and `+exceptionMatchSQL, projects)
	return err
}

// runExceptionExpiry runs expireExceptions every hour until ctx ends.
func (s *server) runExceptionExpiry(ctx context.Context) {
	for {
		s.expireExceptions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// expireExceptions expires what is past its date (findings go back to open, event), and warns once about approved
// exceptions that end within 7 days.
func (s *server) expireExceptions(ctx context.Context) {
	var expired, warn []*exception
	err := s.tx(ctx, func(tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, `update exceptions set status = 'expired' where status in ('pending', 'approved') and expires_at <= now()
			returning id`)
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := releaseException(ctx, tx, id); err != nil {
				return err
			}
		}
		expired = loadExceptions(ctx, tx, ids)
		rows, _ = tx.Query(ctx, `update exceptions set expiry_warned = true where status = 'approved' and not expiry_warned
			and expires_at <= now() + interval '7 days' returning id`)
		wids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		warn = loadExceptions(ctx, tx, wids)
		return err
	})
	if err != nil {
		log.Printf("exception expiry: %v", err)
		return
	}
	for _, ex := range expired {
		s.audit(ctx, nil, "exception.expire", ex.ProjectID, exTarget(ex), map[string]any{"exception_id": ex.ID})
		s.emitException(ctx, "exception_expired", ex, "")
	}
	for _, ex := range warn {
		s.emitException(ctx, "exception_expiring", ex, "")
	}
}

func loadExceptions(ctx context.Context, tx pgx.Tx, ids []int64) []*exception {
	if len(ids) == 0 {
		return nil
	}
	rows, _ := tx.Query(ctx, exceptionCols+`where e.id = any($1)`, ids)
	out, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByPos[exception])
	if err != nil {
		log.Printf("exception expiry: load: %v", err)
	}
	return out
}
