package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
	"github.com/spsp4755/jasca/internal/versions"
)

func init() {
	routeRegistrars = append(routeRegistrars, (*server).advisoryRoutes)
}

// ecoAliases maps the names advisory authors use to the ecosystem names of the package inventory (and of internal/versions).
var ecoAliases = map[string]string{"pypi": "pip", "golang": "gomod", "rubygems": "gem", "crates.io": "cargo", "sles": "suse", "opensuse": "suse"}

func normEco(e string) string {
	e = strings.ToLower(strings.TrimSpace(e))
	if a, ok := ecoAliases[e]; ok {
		return a
	}
	return e
}

type advAffected struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"name"`
	Range     string `json:"range"`
	Fixed     string `json:"fixed"`
	Alias     string `json:"package,omitempty"` // accepted on input as an alias of name (the CSV header word); never stored
}

type advisory struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	Affected    []advAffected `json:"affected"`
	Refs        []string      `json:"refs"`
	Active      bool          `json:"active"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Warnings    []string      `json:"warnings" db:"-"`
}

type advisoryReq struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	Affected    []advAffected `json:"affected"`
	Refs        []string      `json:"refs"`
	Active      *bool         `json:"active"`
}

var advIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9-]{2,40}$`)

// check normalises a in place and returns a Korean message for the first problem. needID is false for previews.
func (a *advisoryReq) check(needID bool) string {
	a.ID, a.Title, a.Severity = strings.TrimSpace(a.ID), strings.TrimSpace(a.Title), strings.ToUpper(strings.TrimSpace(a.Severity))
	switch {
	case needID && !advIDRe.MatchString(a.ID):
		return "id는 대문자로 시작하는 대문자·숫자·하이픈 3~41자여야 합니다(예: INT-2026-001)."
	case a.Title == "" || utf8.RuneCountInString(a.Title) > 300:
		return "제목을 1~300자로 입력하세요."
	case !slices.Contains([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}, a.Severity):
		return "심각도는 CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN 중 하나입니다."
	case len(a.Affected) == 0 || len(a.Affected) > 200:
		return "영향 받는 패키지(affected)를 1~200개 입력하세요."
	}
	for i := range a.Affected {
		it := &a.Affected[i]
		if it.Package == "" {
			it.Package = it.Alias
		}
		it.Alias = ""
		it.Ecosystem, it.Package = normEco(it.Ecosystem), strings.TrimSpace(it.Package)
		it.Range, it.Fixed = strings.TrimSpace(it.Range), strings.TrimSpace(it.Fixed)
		if it.Ecosystem == "" || it.Package == "" || it.Range == "" {
			return fmt.Sprintf("영향 항목 %d: 생태계, 패키지, 취약 범위는 필수입니다.", i+1)
		}
		if _, err := versions.Matches(it.Ecosystem, "0", it.Range); err != nil {
			return fmt.Sprintf("영향 항목 %d: 취약 범위 %q를 해석할 수 없습니다.", i+1, it.Range)
		}
	}
	if a.Refs == nil {
		a.Refs = []string{}
	}
	return ""
}

func (s *server) advisoryRoutes() {
	s.handle("GET /api/v1/advisories", permUser, s.handleAdvisoryList)
	s.handle("GET /api/v1/advisories/{id}", permUser, s.handleAdvisoryGet)
	s.handle("POST /api/v1/advisories", permSecurity, s.handleAdvisoryCreate)
	s.handle("POST /api/v1/advisories/preview", permSecurity, s.handleAdvisoryPreview)
	s.handle("POST /api/v1/advisories/import", permSecurity, s.handleAdvisoryImport)
	s.handle("PUT /api/v1/advisories/{id}", permSecurity, s.handleAdvisoryPut)
	s.handle("DELETE /api/v1/advisories/{id}", permSecurity, s.handleAdvisoryDelete)
}

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const advisoryCols = `select id, title, description, severity, affected, refs, active, created_at, updated_at from advisories `

func loadAdvisories(ctx context.Context, q queryer, activeOnly bool, ids ...string) ([]*advisory, error) {
	sql := advisoryCols + `where ($1 or active) and (coalesce(cardinality($2::text[]), 0) = 0 or id = any($2)) order by id`
	rows, _ := q.Query(ctx, sql, !activeOnly, ids)
	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByPos[advisory])
}

// addWarnings fills Warnings: generic comparison for ecosystems without a comparator, and the number of findings
// whose installed version could not be compared.
func (s *server) addWarnings(ctx context.Context, advs []*advisory) error {
	unc := map[string]int{}
	rows, _ := s.db.Query(ctx, `select rule_id, count(*) from findings where tool = 'advisory' and status <> 'fixed'
		and details->>'version_uncertain' = 'true' group by rule_id`)
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return err
		}
		unc[id] = n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, a := range advs {
		a.Warnings = []string{}
		for _, it := range a.Affected {
			if w := "generic comparison for " + it.Ecosystem; !versions.Known(it.Ecosystem) && !slices.Contains(a.Warnings, w) {
				a.Warnings = append(a.Warnings, w)
			}
		}
		if n := unc[a.ID]; n > 0 {
			a.Warnings = append(a.Warnings, fmt.Sprintf("설치 버전을 비교하지 못한 패키지 %d개를 확인 필요 상태로 등록했습니다(오탐일 수 있음).", n))
		}
	}
	return nil
}

func (s *server) handleAdvisoryList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	advs, err := loadAdvisories(r.Context(), s.db, false)
	if err == nil {
		err = s.addWarnings(r.Context(), advs)
	}
	if err != nil {
		writeInternal(w, "advisory list", err)
		return
	}
	writeJSON(w, 200, advs)
}

func (s *server) handleAdvisoryGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	advs, err := loadAdvisories(r.Context(), s.db, false, r.PathValue("id"))
	if err == nil && len(advs) == 1 {
		err = s.addWarnings(r.Context(), advs)
	}
	switch {
	case err != nil:
		writeInternal(w, "advisory get", err)
	case len(advs) == 0:
		notFoundErr(w)
	default:
		writeJSON(w, 200, advs[0])
	}
}

type advMatch struct {
	adv                         *advisory
	item                        advAffected
	projectID, targetID, scanID int64
	project, target             string
	pkg, version, path          string
	uncertain                   bool
}

// findAdvMatches compares the packages of each non-excluded target's inventory (latestInventorySQL; one target when
// targetID > 0) with the affected items of advs. shortcut: package names match exactly or lower-cased, an
// index-friendly approximation of case-insensitive names; upgrade if a registry needs more normalisation.
func findAdvMatches(ctx context.Context, q queryer, advs []*advisory, targetID int64) ([]advMatch, error) {
	var out []advMatch
	for _, a := range advs {
		for _, it := range a.Affected {
			rows, _ := q.Query(ctx, `select t.id, t.project_id, pr.key, t.name, p.scan_id, p.name, p.version, p.path
				from targets t
				join projects pr on pr.id = t.project_id
				join packages p on p.scan_id = `+latestInventorySQL+`
				where p.ecosystem = $1 and p.name = any($2) and not t.recheck_excluded and ($3 = 0 or t.id = $3)
				order by t.id, p.name, p.path`, it.Ecosystem, []string{it.Package, strings.ToLower(it.Package)}, targetID)
			for rows.Next() {
				m := advMatch{adv: a, item: it}
				if err := rows.Scan(&m.targetID, &m.projectID, &m.project, &m.target, &m.scanID, &m.pkg, &m.version, &m.path); err != nil {
					return nil, err
				}
				ok, err := versions.Matches(it.Ecosystem, m.version, it.Range)
				if err != nil { // a missed vulnerability is worse than a false alarm
					ok, m.uncertain = true, true
				}
				if ok {
					out = append(out, m)
				}
			}
			if err := rows.Err(); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// syncAdvisories makes the stored advisory findings equal to the matches of the active advisories in advs: new
// matches get findings (with origin advisory, attached to the target's latest scan, fixed ones reopened), and
// advisory findings in scope that no longer match become fixed. Scope: advID (one advisory's findings, "" = any)
// and targetID (one target, 0 = all). Excluded targets are never touched. Returns the number of matches.
func (s *server) syncAdvisories(ctx context.Context, tx pgx.Tx, advs []*advisory, advID string, targetID int64) (int, error) {
	var active []*advisory
	for _, a := range advs {
		if a.Active {
			active = append(active, a)
		}
	}
	ms, err := findAdvMatches(ctx, tx, active, targetID)
	if err != nil {
		return 0, err
	}
	type tkey struct{ project, target, scan int64 }
	byTarget := map[tkey][]formats.Finding{}
	var order []tkey
	seen := map[string]bool{}
	var keepT []int64
	var keepFP [][]byte
	for _, m := range ms {
		f := formats.Finding{Kind: "vuln", Tool: "advisory", RuleID: m.adv.ID, Title: m.adv.Title, Severity: m.adv.Severity,
			PkgName: m.pkg, PkgVersion: m.version, FixedVersion: m.item.Fixed, PkgPath: m.path, Details: map[string]any{"advisory": m.adv.ID},
			Vuln: &formats.VulnInfo{Title: m.adv.Title, Description: m.adv.Description, Refs: m.adv.Refs}}
		if m.uncertain {
			f.Details["version_uncertain"] = true
		}
		f.Fingerprint = formats.Fingerprint(f)
		if k := fmt.Sprint(m.targetID, string(f.Fingerprint)); seen[k] {
			continue
		} else {
			seen[k] = true
		}
		tk := tkey{m.projectID, m.targetID, m.scanID}
		if _, ok := byTarget[tk]; !ok {
			order = append(order, tk)
		}
		byTarget[tk] = append(byTarget[tk], f)
		keepT, keepFP = append(keepT, m.targetID), append(keepFP, f.Fingerprint)
	}
	for _, tk := range order {
		if _, err := s.upsertFindings(ctx, tx, tk.project, tk.target, tk.scan, byTarget[tk], "advisory"); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `update findings f set status = 'open', fixed_at = null, reopened_count = reopened_count + 1
		from unnest($1::bigint[], $2::bytea[]) m(t, fp) where f.target_id = m.t and f.fingerprint = m.fp and f.status = 'fixed'`, keepT, keepFP); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `update findings f set status = 'fixed', fixed_at = now() where f.tool = 'advisory' and f.status <> 'fixed'
		and ($1 = '' or f.rule_id = $1) and ($2::bigint = 0 or f.target_id = $2)
		and not exists (select 1 from targets t where t.id = f.target_id and t.recheck_excluded)
		and not exists (select 1 from unnest($3::bigint[], $4::bytea[]) m(t, fp) where m.t = f.target_id and m.fp = f.fingerprint)`,
		advID, targetID, keepT, keepFP); err != nil {
		return 0, err
	}
	if len(keepT) > 0 {
		if advID != "" {
			err = reapplyExceptions(ctx, tx, "f.rule_id = $1", advID)
		} else {
			err = reapplyExceptions(ctx, tx, "f.target_id = $1", targetID)
		}
	}
	return len(ms), err
}

func (s *server) readAdvisoryReq(w http.ResponseWriter, r *http.Request, needID bool) (*advisoryReq, bool) {
	var req advisoryReq
	if err := readJSON(r, 4<<20, &req); err != nil {
		writeBodyErr(w, err)
		return nil, false
	}
	if msg := req.check(needID); msg != "" {
		badRequest(w, msg)
		return nil, false
	}
	return &req, true
}

const advisoryUpsertSQL = `insert into advisories(id, title, description, severity, affected, refs, active, created_by)
	values($1, $2, $3, $4, $5, $6, $7, $8)
	on conflict (id) do update set title = excluded.title, description = excluded.description, severity = excluded.severity,
		affected = excluded.affected, refs = excluded.refs, active = excluded.active, updated_at = now()
	returning (xmax = 0)`

func (s *server) handleAdvisoryCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	req, ok := s.readAdvisoryReq(w, r, true)
	if !ok {
		return
	}
	var matched int
	exists := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `insert into advisories(id, title, description, severity, affected, refs, active, created_by)
			values($1, $2, $3, $4, $5, $6, $7, $8) on conflict do nothing`, req.ID, req.Title, req.Description, req.Severity,
			req.Affected, req.Refs, req.Active == nil || *req.Active, c.User.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			exists = true
			return nil
		}
		matched, err = s.syncStored(ctx, tx, req.ID)
		return err
	})
	if err != nil {
		writeInternal(w, "advisory create", err)
		return
	}
	if exists {
		writeErr(w, 409, "conflict", "같은 ID의 Advisory가 이미 있습니다.")
		return
	}
	s.audit(ctx, c, "advisory.create", nil, req.ID, map[string]any{"matched": matched, "severity": req.Severity})
	s.writeStoredAdvisory(w, 201, req.ID)
}

// syncStored re-matches one stored advisory against every latest inventory.
func (s *server) syncStored(ctx context.Context, tx pgx.Tx, id string) (int, error) {
	advs, err := loadAdvisories(ctx, tx, false, id)
	if err != nil || len(advs) == 0 {
		return 0, err
	}
	return s.syncAdvisories(ctx, tx, advs, id, 0)
}

func (s *server) writeStoredAdvisory(w http.ResponseWriter, status int, id string) {
	advs, err := loadAdvisories(context.Background(), s.db, false, id)
	if err == nil && len(advs) == 1 {
		err = s.addWarnings(context.Background(), advs)
	}
	if err != nil || len(advs) != 1 {
		writeInternal(w, "advisory load", fmt.Errorf("%v (%d rows)", err, len(advs)))
		return
	}
	writeJSON(w, status, advs[0])
}

func (s *server) handleAdvisoryPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id := r.PathValue("id")
	var req advisoryReq
	if err := readJSON(r, 4<<20, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if req.ID == "" {
		req.ID = id
	}
	if msg := req.check(true); msg != "" || req.ID != id {
		if msg == "" {
			msg = "본문의 id가 경로의 id와 다릅니다."
		}
		badRequest(w, msg)
		return
	}
	var matched int
	found := true
	err := s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `update advisories set title = $2, description = $3, severity = $4, affected = $5, refs = $6,
			active = $7, updated_at = now() where id = $1`, id, req.Title, req.Description, req.Severity, req.Affected, req.Refs,
			req.Active == nil || *req.Active)
		if err != nil {
			return err
		}
		if found = tag.RowsAffected() == 1; !found {
			return nil
		}
		matched, err = s.syncStored(ctx, tx, id)
		return err
	})
	if err != nil {
		writeInternal(w, "advisory put", err)
		return
	}
	if !found {
		notFoundErr(w)
		return
	}
	s.audit(ctx, c, "advisory.update", nil, id, map[string]any{"matched": matched, "active": req.Active == nil || *req.Active})
	s.writeStoredAdvisory(w, 200, id)
}

func (s *server) handleAdvisoryDelete(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id := r.PathValue("id")
	found := true
	err := s.tx(ctx, func(tx pgx.Tx) error {
		advs, err := loadAdvisories(ctx, tx, false, id)
		if err != nil {
			return err
		}
		if found = len(advs) == 1; !found {
			return nil
		}
		advs[0].Active = false // the sync fixes every open finding of it
		if _, err := s.syncAdvisories(ctx, tx, advs, id, 0); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `delete from advisories where id = $1`, id)
		return err
	})
	if err != nil {
		writeInternal(w, "advisory delete", err)
		return
	}
	if !found {
		notFoundErr(w)
		return
	}
	s.audit(ctx, c, "advisory.delete", nil, id, nil)
	w.WriteHeader(204)
}

// handleAdvisoryPreview lists what an advisory would hit, without saving anything.
func (s *server) handleAdvisoryPreview(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	req, ok := s.readAdvisoryReq(w, r, false)
	if !ok {
		return
	}
	a := &advisory{ID: req.ID, Title: req.Title, Severity: req.Severity, Affected: req.Affected, Active: true}
	ms, err := findAdvMatches(r.Context(), s.db, []*advisory{a}, 0)
	if err != nil {
		writeInternal(w, "advisory preview", err)
		return
	}
	out := []map[string]string{}
	for _, m := range ms {
		if len(out) == 1000 {
			break
		}
		out = append(out, map[string]string{"project_key": m.project, "target": m.target, "pkg": m.pkg, "version": m.version})
	}
	writeJSON(w, 200, out)
}

// handleAdvisoryImport reads a CSV (raw body or multipart "file") with the header
// id,title,severity,ecosystem,package,range,fixed,description,refs. Rows with one id make one advisory. Any bad
// row rejects the whole file.
func (s *server) handleAdvisoryImport(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var src io.Reader = http.MaxBytesReader(w, r.Body, 10<<20)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			writeBodyErr(w, err)
			return
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			badRequest(w, "file 필드에 CSV 파일을 첨부하세요.")
			return
		}
		defer f.Close()
		src = f
	}
	data, err := io.ReadAll(src)
	if err != nil {
		writeBodyErr(w, err)
		return
	}
	reqs, msg := parseAdvisoryCSV(data)
	if msg != "" {
		badRequest(w, msg)
		return
	}
	created, updated, matched := 0, 0, 0
	err = s.tx(ctx, func(tx pgx.Tx) error {
		for _, a := range reqs {
			var inserted bool
			if err := tx.QueryRow(ctx, advisoryUpsertSQL, a.ID, a.Title, a.Description, a.Severity, a.Affected, a.Refs, true, c.User.ID).Scan(&inserted); err != nil {
				return err
			}
			if inserted {
				created++
			} else {
				updated++
			}
			n, err := s.syncStored(ctx, tx, a.ID)
			if err != nil {
				return err
			}
			matched += n
		}
		return nil
	})
	if err != nil {
		writeInternal(w, "advisory import", err)
		return
	}
	for _, a := range reqs {
		s.audit(ctx, c, "advisory.import", nil, a.ID, map[string]any{"severity": a.Severity})
	}
	writeJSON(w, 200, map[string]int{"created": created, "updated": updated, "matched": matched})
}

func parseAdvisoryCSV(data []byte) ([]*advisoryReq, string) {
	rd := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	head, err := rd.Read()
	if err != nil {
		return nil, "CSV 머리글(id,title,severity,ecosystem,package,range,fixed,description,refs)을 읽을 수 없습니다."
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, k := range []string{"id", "title", "severity", "ecosystem", "package", "range"} {
		if _, ok := col[k]; !ok {
			return nil, "CSV 머리글에 " + k + " 열이 없습니다."
		}
	}
	var out []*advisoryReq
	byID := map[string]*advisoryReq{}
	for row := 2; ; row++ {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Sprintf("%d행: CSV를 읽을 수 없습니다.", row)
		}
		get := func(k string) string {
			if i, ok := col[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		one := advisoryReq{ID: get("id"), Title: get("title"), Description: get("description"), Severity: get("severity"),
			Affected: []advAffected{{Ecosystem: get("ecosystem"), Package: get("package"), Range: get("range"), Fixed: get("fixed")}},
			Refs:     strings.FieldsFunc(get("refs"), func(r rune) bool { return unicode.IsSpace(r) || r == '|' || r == ';' })}
		if msg := one.check(true); msg != "" {
			return nil, fmt.Sprintf("%d행: %s", row, msg)
		}
		if first := byID[one.ID]; first != nil {
			first.Affected = append(first.Affected, one.Affected...)
			continue
		}
		byID[one.ID] = &one
		out = append(out, &one)
	}
	if len(out) == 0 {
		return nil, "가져올 행이 없습니다."
	}
	return out, ""
}
