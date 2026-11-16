package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Exploitation data (악용 정보): the CISA KEV catalog says which CVEs are being exploited, EPSS gives every CVE the
// probability of exploitation in the next 30 days. Both are carried into the closed network as files and uploaded
// on 관리 → Trivy DB; a finding gets them through its CVE id (vuln_intel.cve = findings.rule_id).

func init() { routeRegistrars = append(routeRegistrars, (*server).intelRoutes) }

func (s *server) intelRoutes() {
	s.handle("GET /api/v1/admin/intel", permAdmin, s.handleIntelGet)
	s.handle("POST /api/v1/admin/intel", permAdmin, s.handleIntelUpload)
}

// intelSource is what one uploaded file gave: the day the data is from (nil when the file did not say), how many
// CVEs, and when it was uploaded.
type intelSource struct {
	Date     *time.Time `json:"date"`
	Count    int        `json:"count"`
	LoadedAt *time.Time `json:"loaded_at"`
}

// intelStatus is the setting "intel". A source that was never uploaded has Count 0 and no LoadedAt.
type intelStatus struct {
	KEV  intelSource `json:"kev"`
	EPSS intelSource `json:"epss"`
}

// intelState says which exploitation data is loaded and how old it is.
func (s *server) intelState(ctx context.Context) (intelStatus, error) {
	var st intelStatus
	_, err := s.getSetting(ctx, "intel", &st)
	return st, err
}

const (
	intelMaxBytes = 256 << 20 // the uncompressed file: EPSS is about 12MB, KEV 2MB
	intelMaxRows  = 5_000_000
	kevActionMax  = 200 // characters of requiredAction kept: the usual one-sentence form
	// kevSQL is true for a finding f whose vulnerability is in the KEV catalog; it needs no join, so counts can use it
	kevSQL = `exists (select 1 from vuln_intel k where k.cve = f.rule_id and k.kev)`
	// intelJoin gives a query over findings f the alias vi (null columns when nothing is known about the id)
	intelJoin = ` left join vuln_intel vi on vi.cve = f.rule_id `
)

var (
	cveRE       = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	errIntelBad = errors.New("not a KEV catalog or an EPSS score file")
)

type kevEntry struct {
	CVE        string
	Added      time.Time
	Ransomware bool
	Action     string
}

type epssRow struct {
	CVE       string
	EPSS, Pct float64
}

// parseKEV reads CISA's known_exploited_vulnerabilities.json. Every entry must be a CVE with a date, and the
// catalog's own count must match, so a cut-off or edited file is refused as a whole.
func parseKEV(r io.Reader) ([]kevEntry, *time.Time, error) {
	var doc struct {
		DateReleased    string `json:"dateReleased"`
		Count           *int   `json:"count"`
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
			Action     string `json:"requiredAction"`
		} `json:"vulnerabilities"`
	}
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errIntelBad, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, fmt.Errorf("%w: text after the JSON document", errIntelBad)
	}
	n := len(doc.Vulnerabilities)
	if n == 0 || doc.Count != nil && *doc.Count != n {
		return nil, nil, fmt.Errorf("%w: %d entries do not match the catalog's count", errIntelBad, n)
	}
	out, seen := make([]kevEntry, 0, n), make(map[string]bool, n)
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE))
		added, err := time.Parse(time.DateOnly, v.DateAdded)
		if !cveRE.MatchString(id) || err != nil {
			return nil, nil, fmt.Errorf("%w: entry %q added %q", errIntelBad, clip(v.CVE, 40), clip(v.DateAdded, 20))
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		action := strings.TrimSpace(v.Action)
		if utf8.RuneCountInString(action) > kevActionMax { // newer entries carry a paragraph for US agencies: not worth a screen
			action = ""
		}
		out = append(out, kevEntry{id, added, strings.EqualFold(v.Ransomware, "Known"), action})
	}
	var date *time.Time
	if t, err := time.Parse(time.RFC3339, doc.DateReleased); err == nil {
		date = &t
	}
	return out, date, nil
}

// parseEPSS reads FIRST's epss_scores-YYYY-MM-DD.csv (already gunzipped): an optional "#model_version:…,score_date:…"
// line, the header cve,epss,percentile, then one row per CVE with two numbers from 0 to 1.
func parseEPSS(r io.Reader) ([]epssRow, *time.Time, error) {
	br := bufio.NewReader(r)
	var date *time.Time
	if b, _ := br.Peek(1); len(b) == 1 && b[0] == '#' {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, nil, fmt.Errorf("%w: only a comment line", errIntelBad)
		}
		for _, kv := range strings.Split(strings.TrimSpace(line[1:]), ",") {
			if v, ok := strings.CutPrefix(kv, "score_date:"); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					date = &t
				} else if t, err := time.Parse("2006-01-02T15:04:05-0700", v); err == nil { // files before 2024 wrote +0000
					date = &t
				}
			}
		}
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord, cr.ReuseRecord = 3, true
	head, err := cr.Read()
	if err != nil || head[0] != "cve" || head[1] != "epss" || head[2] != "percentile" {
		return nil, nil, fmt.Errorf("%w: header is not cve,epss,percentile", errIntelBad)
	}
	var out []epssRow
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errIntelBad, err)
		}
		id := strings.ToUpper(rec[0])
		e, err1 := strconv.ParseFloat(rec[1], 64)
		p, err2 := strconv.ParseFloat(rec[2], 64)
		// !(x >= 0 && x <= 1) also refuses NaN
		if !cveRE.MatchString(id) || err1 != nil || err2 != nil || !(e >= 0 && e <= 1) || !(p >= 0 && p <= 1) {
			return nil, nil, fmt.Errorf("%w: row %d: %s", errIntelBad, len(out)+1, clip(strings.Join(rec, ","), 80))
		}
		if len(out) == intelMaxRows {
			return nil, nil, fmt.Errorf("%w: more than %d rows", errIntelBad, intelMaxRows)
		}
		out = append(out, epssRow{id, e, p})
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("%w: no rows", errIntelBad)
	}
	return out, date, nil
}

// parseIntel tells the two files apart by content (gzip is opened first) and parses the one it is.
func parseIntel(r io.Reader) (kev []kevEntry, epss []epssRow, date *time.Time, err error) {
	br := bufio.NewReader(r)
	if b, _ := br.Peek(2); len(b) == 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %w", errIntelBad, err)
		}
		br = bufio.NewReader(zr)
	}
	limited := &io.LimitedReader{R: br, N: intelMaxBytes + 1}
	br = bufio.NewReader(limited)
	head, _ := br.Peek(64)
	head = bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	switch {
	case bytes.HasPrefix(head, []byte("{")):
		br.Discard(bytes.Index(mustPeek(br), []byte("{"))) // a BOM or blank lines before the document
		kev, date, err = parseKEV(br)
	case bytes.HasPrefix(head, []byte("#")), bytes.HasPrefix(head, []byte("cve,")):
		br.Discard(bytes.IndexAny(mustPeek(br), "#c"))
		epss, date, err = parseEPSS(br)
	default:
		err = errIntelBad
	}
	if err == nil && limited.N <= 0 {
		err = fmt.Errorf("%w: larger than %dMB", errIntelBad, intelMaxBytes>>20)
	}
	return kev, epss, date, err
}

func mustPeek(br *bufio.Reader) []byte { b, _ := br.Peek(64); return b }

// replaceKEV makes the KEV columns of vuln_intel equal to list in one transaction and returns the CVEs that were not
// listed before (all of them on the first upload).
func (s *server) replaceKEV(ctx context.Context, list []kevEntry, date *time.Time) (newly []string, err error) {
	ids, added, ransom, action := make([]string, len(list)), make([]time.Time, len(list)), make([]bool, len(list)), make([]string, len(list))
	for i, k := range list {
		ids[i], added[i], ransom[i], action[i] = k.CVE, k.Added, k.Ransomware, k.Action
	}
	err = s.intelTx(ctx, "kev", intelSource{date, len(list), new(time.Now().UTC())}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `select coalesce(array_agg(x order by x), '{}') from unnest($1::text[]) x
			where not exists (select 1 from vuln_intel v where v.cve = x and v.kev)`, ids).Scan(&newly); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `update vuln_intel set kev = false, kev_added = null, kev_ransomware = false, kev_action = ''
			where kev and cve <> all($1)`, ids)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `insert into vuln_intel(cve, kev, kev_added, kev_ransomware, kev_action)
			select x.cve, true, x.added, x.ransom, x.action from unnest($1::text[], $2::date[], $3::bool[], $4::text[]) x(cve, added, ransom, action)
			on conflict (cve) do update set kev = true, kev_added = excluded.kev_added,
				kev_ransomware = excluded.kev_ransomware, kev_action = excluded.kev_action`, ids, added, ransom, action)
		return err
	})
	return newly, err
}

// replaceEPSS makes the EPSS columns equal to rows in one transaction. The rows go through a temporary table with
// COPY; a row whose numbers did not change is left alone, so a weekly upload rewrites only what moved.
func (s *server) replaceEPSS(ctx context.Context, rows []epssRow, date *time.Time) error {
	return s.intelTx(ctx, "epss", intelSource{date, len(rows), new(time.Now().UTC())}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `create temp table intel_load (cve text, epss float8, pct float8) on commit drop`); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"intel_load"}, []string{"cve", "epss", "pct"},
			pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) { return []any{rows[i].CVE, rows[i].EPSS, rows[i].Pct}, nil })); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into vuln_intel(cve, epss, epss_pct)
			select distinct on (cve) cve, epss, pct from intel_load order by cve
			on conflict (cve) do update set epss = excluded.epss, epss_pct = excluded.epss_pct
			where (vuln_intel.epss, vuln_intel.epss_pct) is distinct from (excluded.epss, excluded.epss_pct)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `update vuln_intel v set epss = null, epss_pct = null
			where v.epss is not null and not exists (select 1 from intel_load l where l.cve = v.cve)`)
		return err
	})
}

// intelTx runs one source's replacement: uploads take turns, a row that neither source names any more goes, and
// the source's date and count are stored with the data.
func (s *server) intelTx(ctx context.Context, source string, st intelSource, replace func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtext('jasca.intel'))`); err != nil {
		return err
	}
	if err := replace(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `delete from vuln_intel where not kev and epss is null`); err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]intelSource{source: st})
	if _, err := tx.Exec(ctx, `insert into settings(key, value) values('intel', $1)
		on conflict (key) do update set value = settings.value || excluded.value, updated_at = now()`, json.RawMessage(b)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// notifyKEV tells each project that has open findings of the newly listed CVEs (event kev_listed), once per upload.
func (s *server) notifyKEV(ctx context.Context, newly []string) {
	if len(newly) == 0 {
		return
	}
	rows, err := s.db.Query(ctx, `select f.project_id, f.severity, f.rule_id, f.pkg_name, t.name
		from findings f join targets t on t.id = f.target_id
		where f.status = 'open' and f.rule_id = any($1) order by f.project_id, `+sevRankSQL+`, f.id`, newly)
	if err != nil {
		log.Printf("notify kev_listed: %v", err)
		return
	}
	type item struct {
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Pkg      string `json:"pkg"`
		Target   string `json:"target"`
	}
	type group struct {
		count int
		cves  map[string]bool
		top   []item
	}
	var order []int64
	byProject := map[int64]*group{}
	for rows.Next() {
		var pid int64
		var it item
		if err := rows.Scan(&pid, &it.Severity, &it.RuleID, &it.Pkg, &it.Target); err != nil {
			log.Printf("notify kev_listed: %v", err)
			break
		}
		g := byProject[pid]
		if g == nil {
			g = &group{cves: map[string]bool{}}
			byProject[pid], order = g, append(order, pid)
		}
		g.count++
		g.cves[it.RuleID] = true
		if len(g.top) < 5 {
			g.top = append(g.top, it)
		}
	}
	rows.Close()
	for _, pid := range order {
		g := byProject[pid]
		s.emit(ctx, pid, "kev_listed", map[string]any{"count": g.count, "cves": len(g.cves), "top": g.top})
	}
}

func (s *server) handleIntelGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	st, err := s.intelState(r.Context())
	if err != nil {
		writeInternal(w, "intel", err)
		return
	}
	writeJSON(w, 200, st)
}

// handleIntelUpload takes a KEV catalog (JSON) or an EPSS score file (.csv.gz or .csv) as multipart "file"; which
// one it is comes from the content and goes back as "kind". The file is checked completely before anything is
// replaced: a bad file is refused and the stored data stays.
func (s *server) handleIntelUpload(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxReportMB<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		badRequest(w, "multipart/form-data 형식으로 file을 보내세요.")
		return
	}
	for {
		part, err := mr.NextPart()
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeErr(w, 413, "too_large", fmt.Sprintf("파일이 너무 큽니다. %dMB까지 올릴 수 있습니다.", s.cfg.MaxReportMB))
			return
		}
		if err != nil { // io.EOF included: no file part
			badRequest(w, "KEV 또는 EPSS 파일(file)을 올리세요.")
			return
		}
		if part.FormName() != "file" {
			io.Copy(io.Discard, part)
			continue
		}
		kev, epss, date, err := parseIntel(part)
		if err != nil {
			s.audit(ctx, c, "intel.upload_failed", nil, "", map[string]any{"error": clip(err.Error(), 300)})
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				writeErr(w, 413, "too_large", fmt.Sprintf("파일이 너무 큽니다. %dMB까지 올릴 수 있습니다.", s.cfg.MaxReportMB))
				return
			}
			writeErr(w, 400, "bad_file", "KEV 목록(known_exploited_vulnerabilities.json)이나 EPSS 점수 파일(epss_scores-….csv.gz)이 아니거나 내용이 잘렸습니다. 기존 정보를 그대로 사용합니다.")
			return
		}
		ctx = context.WithoutCancel(ctx) // checked and about to be stored: finish even if the browser left
		kind, count, start := "epss", len(epss), time.Now()
		var newly []string
		if kev != nil {
			kind, count = "kev", len(kev)
			newly, err = s.replaceKEV(ctx, kev, date)
		} else {
			err = s.replaceEPSS(ctx, epss, date)
		}
		if err != nil {
			writeInternal(w, "intel upload", err)
			return
		}
		log.Printf("intel: %s replaced, %d CVEs in %s", kind, count, time.Since(start).Round(time.Millisecond))
		details := map[string]any{"count": count, "data_at": date}
		if kind == "kev" {
			details["newly_listed"] = len(newly)
			s.notifyKEV(ctx, newly)
		}
		s.audit(ctx, c, "intel.upload", nil, kind, details)
		st, err := s.intelState(ctx)
		if err != nil {
			writeInternal(w, "intel", err)
			return
		}
		writeJSON(w, 200, struct {
			intelStatus
			Kind        string `json:"kind"`
			NewlyListed int    `json:"newly_listed"` // KEV only: CVEs that were not in the previous catalog
		}{st, kind, len(newly)})
		return
	}
}

// intelStaleAfter: the files are carried in with the weekly Trivy DB, so two weeks means a round was missed.
const intelStaleAfter = 14 * 24 * time.Hour

// The 관리 → 시스템 상태 row: without the files, or with old ones, 악용 확인 marks are missing without anyone noticing.
func init() {
	sysChecks = append(sysChecks, func(ctx context.Context, s *server) sysCheck {
		c := sysCheck{Key: "intel", Label: "악용 정보", State: "ok", Link: "/admin/trivy"}
		st, err := s.intelState(ctx)
		if err != nil {
			c.State, c.Value, c.Action = "bad", "확인하지 못했습니다", "데이터베이스 상태를 확인하세요."
			return c
		}
		var parts, todo []string
		for _, src := range []struct {
			name string
			v    intelSource
		}{{"KEV", st.KEV}, {"EPSS", st.EPSS}} {
			switch {
			case src.v.LoadedAt == nil || src.v.Date == nil:
				parts, todo = append(parts, src.name+" 올리지 않음"), append(todo, src.name)
			case time.Since(*src.v.Date) >= intelStaleAfter:
				parts = append(parts, fmt.Sprintf("%s %s (%d일 전)", src.name, src.v.Date.In(s.cfg.Loc).Format("2006-01-02"), int(time.Since(*src.v.Date).Hours()/24)))
				todo = append(todo, src.name)
			default:
				parts = append(parts, fmt.Sprintf("%s %s", src.name, src.v.Date.In(s.cfg.Loc).Format("2006-01-02")))
			}
		}
		c.Value = strings.Join(parts, " · ")
		if len(todo) > 0 {
			c.State = "warn"
			c.Action = strings.Join(todo, ", ") + " 파일을 인터넷 PC에서 새로 받아 관리 → Trivy DB의 악용 정보에 올리세요. 오래되면 최근에 악용이 확인된 취약점이 표시되지 않습니다."
		}
		return c
	})
}
