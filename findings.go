package main

import (
	"bufio"
	"context"
	"encoding/json"
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
// severity, versions; status and origin are kept). It also fills the vulns catalog and links every finding to
// scanID in scan_findings. It never resolves anything. fs must have unique fingerprints (the parsers ensure it).
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
	_, err = tx.Exec(ctx, `insert into scan_findings(scan_id, finding_id) select $1, unnest($2::bigint[]) on conflict do nothing`, scanID, all)
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
}

const findingCols = `select f.id, f.project_id, p.key, f.target_id, t.kind, t.name, f.kind, f.tool, f.rule_id, f.title, f.severity,
		f.pkg_name, f.pkg_version, f.fixed_version, f.pkg_path, f.location, f.status, f.origin, f.first_seen_at,
		f.last_seen_at, f.fixed_at, f.reopened_count, f.exception_id, f.details
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
func findingFilter(q url.Values, w *where) string {
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
	return ""
}

func (s *server) handleFindingList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	s.writeFindings(w, r, s.visibleWhere(c.User))
}

// writeFindings answers {items, next_cursor, total} for the findings matching base plus the query parameters,
// newest first, with keyset pagination (cursor = the last id seen).
func (s *server) writeFindings(w http.ResponseWriter, r *http.Request, f *where) {
	ctx := r.Context()
	q := r.URL.Query()
	if msg := findingFilter(q, f); msg != "" {
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
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			badRequest(w, "cursor가 잘못되었습니다.")
			return
		}
		f.add("f.id < ?", n)
	}
	rows, _ := s.db.Query(ctx, findingCols+`where `+f.sql()+` order by f.id desc limit `+strconv.Itoa(limit), f.args...)
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[findingView])
	if err != nil {
		writeInternal(w, "finding list", err)
		return
	}
	var next *int64
	if len(items) == limit {
		next = &items[len(items)-1].ID
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

func (s *server) handleFindingGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), findingCols+`where f.id = $1`, pathID(r))
	f, err := pgx.CollectOneRow(rows, pgx.RowToStructByPos[findingView])
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
	if msg := findingFilter(r.URL.Query(), f); msg != "" {
		badRequest(w, msg)
		return
	}
	rows, err := s.db.Query(r.Context(), findingCols+`where `+f.sql()+` order by f.id desc`, f.args...)
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
		"조치 버전", "패키지 경로", "위치", "출처", "처음 발견", "마지막 발견", "해결 시각")
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
			v.PkgVersion, v.FixedVersion, v.PkgPath, v.Location, v.Origin, at(&v.FirstSeenAt), at(&v.LastSeenAt), at(v.FixedAt))
	}
	if err := rows.Err(); err != nil {
		log.Printf("finding csv: %v", err) // the header is out; the truncated file is all we can give
	}
}
