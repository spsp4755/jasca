package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
)

func (s *server) findingRoutes() {
	s.registerObj("finding", s.objByID(`select project_id from findings where id = $1`))
	s.handle("GET /api/v1/findings", permUser, s.handleFindingList)
	s.handle("GET /api/v1/findings.csv", permUser, s.handleFindingCSV)
	s.handle("GET /api/v1/findings/{id}", permObj("finding", "viewer"), s.handleFindingGet)
}

// pathID is the {id} path value of an obj route; its resolver has already checked that it is a number.
func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

// objByID makes an obj resolver from a query that maps a bigint id ($1) to its project id.
func (s *server) objByID(q string) func(ctx context.Context, id string) (int64, error) {
	return func(ctx context.Context, id string) (int64, error) {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return 0, pgx.ErrNoRows
		}
		var pid int64
		return pid, s.db.QueryRow(ctx, q, n).Scan(&pid)
	}
}

const findingUpsertSQL = `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, title, severity,
		pkg_name, pkg_version, fixed_version, pkg_path, location, origin, details)
	values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	on conflict (target_id, fingerprint) do update set last_seen_at = now(), title = excluded.title,
		severity = excluded.severity, pkg_version = excluded.pkg_version, fixed_version = excluded.fixed_version,
		location = excluded.location, details = excluded.details
	returning id, xmax = 0`

// upsertFindings inserts each finding, or touches the target's existing one with the same fingerprint (last_seen,
// severity, versions; status and origin are kept). It also fills the vulns catalog, links every finding to
// scanID in scan_findings and records the inserted ones as that scan's 'new' changes. It never resolves anything.
// fs must have unique fingerprints (the parsers ensure it).
func (s *server) upsertFindings(ctx context.Context, tx pgx.Tx, projectID, targetID, scanID int64, fs []formats.Finding, origin string) (newIDs []int64, err error) {
	if err := upsertVulns(ctx, tx, fs); err != nil {
		return nil, err
	}
	all := make([]int64, 0, len(fs))
	err = sendBatches(ctx, tx, len(fs), func(b *pgx.Batch, i int) {
		f := fs[i]
		details := f.Details
		if details == nil {
			details = map[string]any{}
		}
		b.Queue(findingUpsertSQL, projectID, targetID, f.Fingerprint, f.Kind, f.Tool, f.RuleID, f.Title, f.Severity,
			f.PkgName, f.PkgVersion, f.FixedVersion, f.PkgPath, f.Location, origin, details).QueryRow(func(row pgx.Row) error {
			var id int64
			var inserted bool
			if err := row.Scan(&id, &inserted); err != nil {
				return err
			}
			all = append(all, id)
			if inserted {
				newIDs = append(newIDs, id)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `insert into scan_findings(scan_id, finding_id) select $1, unnest($2::bigint[]) on conflict do nothing`, scanID, all); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `insert into scan_changes(scan_id, finding_id, change) select $1, unnest($2::bigint[]), 'new'`, scanID, newIDs)
	return newIDs, err
}

// sendBatches queues n statements with queue(b, i) and sends them at most 1000 per round trip.
func sendBatches(ctx context.Context, tx pgx.Tx, n int, queue func(b *pgx.Batch, i int)) error {
	for start := 0; start < n; start += 1000 {
		b := &pgx.Batch{}
		for i := start; i < min(start+1000, n); i++ {
			queue(b, i)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
	}
	return nil
}

// --- reading ---

type findingView struct {
	ID            int64           `json:"id"`
	ProjectID     int64           `json:"project_id"`
	ProjectKey    string          `json:"project_key"`
	TargetID      int64           `json:"target_id"`
	TargetKind    string          `json:"target_kind"`
	TargetName    string          `json:"target_name"`
	Kind          string          `json:"kind"`
	Tool          string          `json:"tool"`
	RuleID        string          `json:"rule_id"`
	Title         string          `json:"title"`
	Severity      string          `json:"severity"`
	PkgName       string          `json:"pkg_name"`
	PkgVersion    string          `json:"pkg_version"`
	FixedVersion  string          `json:"fixed_version"`
	PkgPath       string          `json:"pkg_path"`
	Location      string          `json:"location"`
	Status        string          `json:"status"`
	Origin        string          `json:"origin"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	FixedAt       *time.Time      `json:"fixed_at"`
	ReopenedCount int             `json:"reopened_count"`
	ExceptionID   *int64          `json:"exception_id"`
	Details       json.RawMessage `json:"details"`
	Assignee      *assigneeView   `json:"assignee"`
	DueAt         *time.Time      `json:"due_at"` // only an open finding has one; overdue = it is in the past
	DueManual     bool            `json:"due_manual"`
	// only GET /findings/{id} fills these: not columns of findingCols
	PendingExceptionID *int64 `json:"pending_exception_id,omitempty" db:"-"`
	SLADays            *int   `json:"sla_days,omitempty" db:"-"` // the days the deadline setting gives this severity
}

const findingCols = `select f.id, f.project_id, p.key, f.target_id, t.kind, t.name, f.kind, f.tool, f.rule_id, f.title, f.severity,
		f.pkg_name, f.pkg_version, f.fixed_version, f.pkg_path, f.location, f.status, f.origin, f.first_seen_at,
		f.last_seen_at, f.fixed_at, f.reopened_count, f.exception_id, f.details, ` + assigneeSQL + `, f.due_at, f.due_manual
	from findings f join targets t on t.id = f.target_id join projects p on p.id = f.project_id `

// where collects AND-ed SQL conditions; each ? in a condition becomes the $n of its value.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, v any) {
	w.args = append(w.args, v)
	w.conds = append(w.conds, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(w.args))))
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return "true"
	}
	return strings.Join(w.conds, " and ")
}

// visibleWhere starts a findings filter with the projects u can see.
func (s *server) visibleWhere(u *user) *where {
	cond, args := s.visibleProjectsSQL(u, "f", 1)
	return &where{conds: []string{cond}, args: args}
}

// findingFilter adds the list query parameters to w; it returns a message for the user when one is invalid.
// u is the caller, for assignee=me (nil for an API token).
func findingFilter(q url.Values, w *where, u *user) string {
	if v := q.Get("project"); v != "" {
		w.add("f.project_id = (select id from projects where key = ?)", v)
	}
	if v := q.Get("target_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return "target_id는 숫자여야 합니다."
		}
		w.add("f.target_id = ?", n)
	}
	for _, col := range []string{"severity", "status", "kind", "origin"} {
		if v := q.Get(col); v != "" {
			w.add("f."+col+" = any(?)", strings.Split(v, ","))
		}
	}
	switch q.Get("fixable") {
	case "":
	case "true":
		w.conds = append(w.conds, "f.fixed_version <> ''")
	case "false":
		w.conds = append(w.conds, "f.fixed_version = ''")
	default:
		return "fixable은 true 또는 false입니다."
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		if utf8.RuneCountInString(v) > 200 {
			return "검색어가 너무 깁니다."
		}
		w.add("(f.rule_id ilike ? or f.pkg_name ilike ? or f.title ilike ?)", "%"+likeEscaper.Replace(v)+"%")
	}
	switch v := q.Get("assignee"); v {
	case "":
	case "none":
		w.conds = append(w.conds, "f.assignee_id is null")
	default:
		n, err := strconv.ParseInt(v, 10, 64)
		if v == "me" && u != nil {
			n, err = u.ID, nil
		}
		if err != nil {
			return "assignee는 me, none 또는 사용자 ID입니다."
		}
		w.add("f.assignee_id = ?", n)
	}
	switch q.Get("due") {
	case "":
	case "overdue":
		w.conds = append(w.conds, "f.status = 'open' and f.due_at < now()")
	case "soon": // within 7 days and not past
		w.conds = append(w.conds, "f.status = 'open' and f.due_at >= now() and f.due_at < now() + interval '7 days'")
	default:
		return "due는 overdue 또는 soon입니다."
	}
	return ""
}

func (s *server) handleFindingList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	s.writeFindings(w, r, c.User, s.visibleWhere(c.User))
}

// Lists put what to fix first on top: CRITICAL down to UNKNOWN, the newest first inside a severity. With sort=due
// it is the earliest deadline first, and the findings without a deadline last.
var severityRank = map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}

const (
	sevRankSQL      = `coalesce(array_position(array['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'], f.severity), 5)`
	findingOrder    = ` order by ` + sevRankSQL + `, f.id desc`
	findingOrderDue = ` order by f.due_at nulls last, f.id desc`
)

// findingSort reads the sort parameter: the ORDER BY to use and whether it is the deadline order.
func findingSort(q url.Values) (order string, byDue bool, msg string) {
	switch q.Get("sort") {
	case "", "severity":
		return findingOrder, false, ""
	case "due":
		return findingOrderDue, true, ""
	}
	return "", false, "sort는 severity 또는 due입니다."
}

// writeFindings answers {items, next_cursor, total} for the findings matching base plus the query parameters (u is
// the caller, see findingFilter), with keyset pagination: the cursor is "<severity rank>.<id>" of the last row seen,
// or with sort=due "<its due_at, - for none>.<id>".
func (s *server) writeFindings(w http.ResponseWriter, r *http.Request, u *user, f *where) {
	ctx := r.Context()
	q := r.URL.Query()
	if msg := findingFilter(q, f, u); msg != "" {
		badRequest(w, msg)
		return
	}
	order, byDue, msg := findingSort(q)
	if msg != "" {
		badRequest(w, msg)
		return
	}
	limit, msg := pageLimit(q.Get("limit"))
	if msg != "" {
		badRequest(w, msg)
		return
	}
	var total int
	if err := s.db.QueryRow(ctx, `select count(*) from findings f where `+f.sql(), f.args...).Scan(&total); err != nil {
		writeInternal(w, "finding count", err)
		return
	}
	if v := q.Get("cursor"); v != "" {
		i := strings.LastIndexByte(v, '.') // a due_at has dots of its own
		head, tail := v[:max(i, 0)], v[i+1:]
		id, err := strconv.ParseInt(tail, 10, 64)
		n := len(f.args) + 1
		switch {
		case err != nil || i < 0:
			err = cmp.Or(err, strconv.ErrSyntax)
		case byDue && head == "-": // the deadlines are through: on to the rest of the findings without one
			f.args = append(f.args, id)
			f.conds = append(f.conds, fmt.Sprintf("f.due_at is null and f.id < $%d", n))
		case byDue:
			var due time.Time
			due, err = time.Parse(time.RFC3339Nano, head)
			f.args = append(f.args, due, id)
			f.conds = append(f.conds, fmt.Sprintf("(f.due_at > $%d or f.due_at is null or f.due_at = $%d and f.id < $%d)", n, n, n+1))
		default:
			var rank int
			rank, err = strconv.Atoi(head)
			f.args = append(f.args, rank, id)
			f.conds = append(f.conds, fmt.Sprintf("(%s > $%d or (%s = $%d and f.id < $%d))", sevRankSQL, n, sevRankSQL, n, n+1))
		}
		if err != nil {
			badRequest(w, "cursor가 잘못되었습니다.")
			return
		}
	}
	rows, _ := s.db.Query(ctx, findingCols+`where `+f.sql()+order+` limit `+strconv.Itoa(limit), f.args...)
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[findingView])
	if err != nil {
		writeInternal(w, "finding list", err)
		return
	}
	var next *string
	if len(items) == limit {
		last := items[len(items)-1]
		head := strconv.Itoa(cmp.Or(severityRank[last.Severity], 5))
		if byDue {
			head = "-"
			if last.DueAt != nil {
				head = last.DueAt.UTC().Format(time.RFC3339Nano)
			}
		}
		next = new(head + "." + itoa(last.ID))
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next, "total": total})
}

// pageLimit reads a limit parameter: 50 by default, at most 200.
func pageLimit(v string) (int, string) {
	if v == "" {
		return 50, ""
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, "limit은 1 이상의 숫자여야 합니다."
	}
	return min(n, 200), ""
}

// handleFindingGet also names the exception request that waits for a decision and would cover the finding
// (pending_exception_id), so the screen can show that instead of offering a second request, and the days the
// deadline setting gives the finding's severity (sla_days), so the screen can say where a deadline comes from.
func (s *server) handleFindingGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), findingCols+`where f.id = $1`, pathID(r))
	f, err := pgx.CollectOneRow(rows, pgx.RowToStructByPos[findingView])
	if err == nil {
		err = s.db.QueryRow(r.Context(), `select (select min(e.id) from exceptions e join findings f on f.id = $1
			where e.status = 'pending' and e.expires_at > now() and `+exceptionMatchSQL+`), (`+slaDaysSQL+`->>$2)::int`,
			f.ID, f.Severity).Scan(&f.PendingExceptionID, &f.SLADays)
	}
	if err != nil {
		writeInternal(w, "finding get", err)
		return
	}
	writeJSON(w, 200, f)
}

// csvCell quotes every cell, and defuses a leading = + - @ (or tab / CR) that a spreadsheet would run as a formula.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		v = "'" + v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func (s *server) handleFindingCSV(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	f := s.visibleWhere(c.User)
	order, _, msg := findingSort(r.URL.Query())
	if msg = cmp.Or(findingFilter(r.URL.Query(), f, c.User), msg); msg != "" {
		badRequest(w, msg)
		return
	}
	rows, err := s.db.Query(r.Context(), findingCols+`where `+f.sql()+order, f.args...)
	if err != nil {
		writeInternal(w, "finding csv", err)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	bw.WriteString("\ufeff") // Excel reads Hangul as UTF-8 only with a BOM
	line := func(cells ...string) {
		for i, v := range cells {
			if i > 0 {
				bw.WriteByte(',')
			}
			bw.WriteString(csvCell(v))
		}
		bw.WriteString("\r\n")
	}
	line("프로젝트", "대상 종류", "대상", "종류", "도구", "규칙/취약점 ID", "제목", "심각도", "상태", "패키지", "설치 버전",
		"조치 버전", "패키지 경로", "위치", "출처", "처음 발견", "마지막 발견", "해결 시각", "담당자", "조치 기한")
	at := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.In(s.cfg.Loc).Format(time.RFC3339)
	}
	for rows.Next() {
		v, err := pgx.RowToStructByPos[findingView](rows)
		if err != nil {
			log.Printf("finding csv: %v", err)
			return
		}
		line(v.ProjectKey, v.TargetKind, v.TargetName, v.Kind, v.Tool, v.RuleID, v.Title, v.Severity, v.Status, v.PkgName,
			v.PkgVersion, v.FixedVersion, v.PkgPath, v.Location, v.Origin, at(&v.FirstSeenAt), at(&v.LastSeenAt), at(v.FixedAt),
			v.Assignee.display(), at(v.DueAt))
	}
	if err := rows.Err(); err != nil {
		log.Printf("finding csv: %v", err) // the header is out; the truncated file is all we can give
	}
}
