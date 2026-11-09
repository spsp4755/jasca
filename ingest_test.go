package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spsp4755/jasca/internal/formats"
)

func init() {
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "POST", Path: "/api/v1/projects/{key}/scans"},
		matrixCase{Method: "GET", Path: "/api/v1/projects/{key}/scans"},
		matrixCase{Method: "GET", Path: "/api/v1/scans/{scan}"},
		matrixCase{Method: "GET", Path: "/api/v1/scans/{scan}/findings"},
		matrixCase{Method: "GET", Path: "/api/v1/scans/{scan}/raw"},
		matrixCase{Method: "GET", Path: "/api/v1/findings/{finding}"},
		matrixCase{Method: "GET", Path: "/api/v1/findings?project={key}", List: "items"},
		matrixCase{Method: "GET", Path: "/api/v1/findings?target_id={target}", List: "items"},
		matrixCase{Method: "GET", Path: "/api/v1/vulns/CVE-2024-0001", List: "affected"})
	// the base finding's CVE gets a catalog row, so the vulns case answers 200 (shared catalog, no B findings)
	matrixFixtures = append(matrixFixtures, func(t *testing.T, s *server, projB *project) map[string]string {
		sqlExec(t, s, `insert into vulns(id, title) values('CVE-2024-0001', 'shared') on conflict do nothing`)
		return nil
	})
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("internal/formats/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseReport(t *testing.T, parser string, b []byte) *formats.Report {
	t.Helper()
	p, _ := formats.Get(parser)
	r, err := p.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// tv is one vulnerability in a trivyDoc.
type tv struct{ ID, Pkg, Sev, Fixed, Title, Desc, Modified string }

var docSeq int

// trivyDoc builds a small Trivy filesystem report: one os-pkgs result with vulns, plus a config result when misconf
// is non-nil. Every call gives different bytes, so two docs are never duplicates of each other.
func trivyDoc(name string, vulns []tv, misconf []string) []byte {
	docSeq++
	vs := []map[string]any{}
	for _, v := range vulns {
		vs = append(vs, map[string]any{"VulnerabilityID": v.ID, "PkgName": cmp.Or(v.Pkg, "zlib"), "InstalledVersion": "1.0",
			"FixedVersion": v.Fixed, "Severity": cmp.Or(v.Sev, "HIGH"), "Title": v.Title, "Description": v.Desc,
			"LastModifiedDate": v.Modified})
	}
	results := []map[string]any{{"Target": name, "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": vs}}
	if misconf != nil {
		ms := []map[string]any{}
		for _, id := range misconf {
			ms = append(ms, map[string]any{"ID": id, "Title": id, "Severity": "MEDIUM", "Status": "FAIL"})
		}
		results = append(results, map[string]any{"Target": "Dockerfile", "Class": "config", "Type": "dockerfile", "Misconfigurations": ms})
	}
	b, _ := json.Marshal(struct {
		SchemaVersion                       int
		ArtifactName, ArtifactType, Created string
		Results                             []map[string]any
	}{2, name, "filesystem", fmt.Sprint(docSeq), results})
	return b
}

type uploadResp struct {
	ScanID    int64          `json:"scan_id"`
	TargetID  int64          `json:"target_id"`
	Summary   map[string]int `json:"summary"`
	Policy    policyResult   `json:"policy"`
	Duplicate bool           `json:"duplicate"`
}

func upload(t *testing.T, s *server, key, query string, body []byte, auth ...any) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, s, "POST", "/api/v1/projects/"+key+"/scans?"+query, body, auth...)
}

func mustUpload(t *testing.T, s *server, key, query string, body []byte, auth ...any) uploadResp {
	t.Helper()
	rec := upload(t, s, key, query, body, auth...)
	if rec.Code != 201 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	return decode[uploadResp](t, rec)
}

func qInt(t *testing.T, s *server, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// findingState returns the status, reopened_count and whether fixed_at is set for the target's finding of ruleID.
func findingState(t *testing.T, s *server, targetID int64, ruleID string) (status string, reopened int, fixedAt bool) {
	t.Helper()
	err := s.db.QueryRow(context.Background(), `select status, reopened_count, fixed_at is not null from findings
		where target_id=$1 and rule_id=$2`, targetID, ruleID).Scan(&status, &reopened, &fixedAt)
	if err != nil {
		t.Fatalf("finding %s on target %d: %v", ruleID, targetID, err)
	}
	return
}

// memberSession makes a project "web" with a member user and returns the project id and the user's cookie.
func memberSession(t *testing.T, s *server) (int64, *http.Cookie) {
	t.Helper()
	u := mkUser(t, s, "dev", "")
	pid := mkProject(t, s, "web")
	addMember(t, s, pid, "user", itoa(u.ID), "member")
	return pid, loginAs(t, s, u)
}

func TestIngestTrivyImage(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, tok := mkToken(t, s, "web", "upload")
	raw := readFixture(t, "trivy/image-alpine.json")
	rep := parseReport(t, "trivy", raw)
	res := mustUpload(t, s, "web", "", raw, tok)

	want := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "open": 0}
	for _, f := range rep.Findings {
		want[strings.ToLower(f.Severity)]++
		want["open"]++
	}
	if !maps.Equal(res.Summary, want) || res.Duplicate {
		t.Errorf("summary %v (dup %v), want %v", res.Summary, res.Duplicate, want)
	}
	if n := qInt(t, s, `select count(*) from findings where target_id=$1`, res.TargetID); n != len(rep.Findings) || n == 0 {
		t.Errorf("findings %d, want %d", n, len(rep.Findings))
	}
	if n := qInt(t, s, `select count(*) from scan_findings where scan_id=$1`, res.ScanID); n != len(rep.Findings) {
		t.Errorf("scan_findings %d", n)
	}
	if n := qInt(t, s, `select count(*) from packages where scan_id=$1`, res.ScanID); n != len(rep.Packages) {
		t.Errorf("packages %d, want %d", n, len(rep.Packages))
	}
	var kind, name, ref, source, format, status, osFamily string
	var tokenSet, lastScan bool
	var gz, policyJSON []byte
	err := s.db.QueryRow(ctx, `select t.kind, t.name, s.ref, s.source, s.format, s.status, s.summary->'os'->>'family',
			s.created_by_token is not null, t.last_scan_at is not null, s.raw, s.policy
		from scans s join targets t on t.id = s.target_id where s.id=$1`, res.ScanID).
		Scan(&kind, &name, &ref, &source, &format, &status, &osFamily, &tokenSet, &lastScan, &gz, &policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "image" || name != "alpine" || ref != "3.12" || source != "upload" || format != "trivy" || status != "done" ||
		osFamily != "alpine" || !tokenSet || !lastScan {
		t.Errorf("scan row: %s %s %s %s %s %s os=%s token=%v last=%v", kind, name, ref, source, format, status, osFamily, tokenSet, lastScan)
	}
	if !bytes.Equal(gunzip(t, gz), raw) {
		t.Error("raw is not the gzip of the upload")
	}
	// default policy: no open CRITICAL allowed
	if res.Policy.Passed != (want["critical"] == 0) || res.Policy.Error != "" || !res.Policy.Passed && len(res.Policy.Reasons) == 0 {
		t.Errorf("policy %+v with %d critical", res.Policy, want["critical"])
	}
	var stored policyResult
	if err := json.Unmarshal(policyJSON, &stored); err != nil || stored.Passed != res.Policy.Passed {
		t.Errorf("stored policy %s", policyJSON)
	}
	var v *formats.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Vuln != nil && rep.Findings[i].Vuln.Title != "" {
			v = &rep.Findings[i]
			break
		}
	}
	if v != nil {
		var title string
		s.db.QueryRow(ctx, `select title from vulns where id=$1`, v.RuleID).Scan(&title)
		if title != v.Vuln.Title {
			t.Errorf("catalog title %q, want %q", title, v.Vuln.Title)
		}
	}
	if n := auditCount(t, s, "scan.upload"); n != 1 {
		t.Errorf("audit rows %d", n)
	}
}

func TestIngestRejectsBadInput(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "web", "upload")
	raw := readFixture(t, "trivy/image-alpine.json")
	gzHeader := http.Header{"Content-Encoding": {"gzip"}}
	big := bytes.Repeat([]byte(" "), 60<<20)

	wantCode(t, upload(t, s, "web", "", big, tok), 413, "60MB body")
	// the limit applies after decoding: 60MB of spaces compresses to a few KB
	wantCode(t, upload(t, s, "web", "", gzipped(big), tok, gzHeader), 413, "60MB decoded")
	for name, body := range map[string][]byte{
		"truncated":      raw[:len(raw)/2],
		"truncated gzip": gzipped(raw)[:2000],
		"not gzip":       raw,
	} {
		h := http.Header{}
		if name != "truncated" {
			h = gzHeader
		}
		rec := upload(t, s, "web", "", body, tok, h)
		if rec.Code != 400 || errCode(t, rec) != "bad_request" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"png":          upload(t, s, "web", "", png, tok),
		"empty":        upload(t, s, "web", "", nil, tok),
		"bogus format": upload(t, s, "web", "format=bogus", raw, tok),
	} {
		if rec.Code != 400 || errCode(t, rec) != "unsupported_format" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	wantCode(t, upload(t, s, "web", "kind=vm", raw, tok), 400, "bad kind")
	wantCode(t, upload(t, s, "web", "target="+strings.Repeat("x", 600), raw, tok), 400, "long target")
	// SARIF names no target: one must be given
	wantCode(t, upload(t, s, "web", "", readFixture(t, "sarif/semgrep.sarif"), tok), 400, "sarif without target")
	for _, table := range []string{"targets", "scans", "findings", "packages", "scan_findings", "vulns"} {
		if n := qInt(t, s, `select count(*) from `+table); n != 0 {
			t.Errorf("%s has %d rows after rejected uploads", table, n)
		}
	}
}

func TestIngestDuplicateWithin10Min(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "web", "upload")
	raw := readFixture(t, "trivy/image-alpine.json")
	first := mustUpload(t, s, "web", "", raw, tok)

	rec := upload(t, s, "web", "", gzipped(raw), tok, http.Header{"Content-Encoding": {"gzip"}})
	wantCode(t, rec, 200, "duplicate")
	dup := decode[uploadResp](t, rec)
	if !dup.Duplicate || dup.ScanID != first.ScanID || !maps.Equal(dup.Summary, first.Summary) || dup.Policy.Passed != first.Policy.Passed {
		t.Errorf("duplicate %+v, first %+v", dup, first)
	}
	if n := qInt(t, s, `select count(*) from scans`); n != 1 {
		t.Errorf("scans %d", n)
	}
	// the same bytes for another target are a new scan
	if other := mustUpload(t, s, "web", "target=other", raw, tok); other.Duplicate || other.ScanID == first.ScanID {
		t.Errorf("other target %+v", other)
	}
	sqlExec(t, s, `update scans set created_at = now() - interval '11 minutes'`)
	if later := mustUpload(t, s, "web", "", raw, tok); later.Duplicate || later.ScanID == first.ScanID {
		t.Errorf("after 10 minutes %+v", later)
	}
}

func TestAutoResolveScopedToTargetAndTool(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	X, Y := tv{ID: "CVE-2024-1000"}, tv{ID: "CVE-2024-2000", Pkg: "openssl"}
	a := mustUpload(t, s, "web", "", trivyDoc("A", []tv{X, Y}, nil), ck)

	// another target's scan never touches A
	mustUpload(t, s, "web", "", trivyDoc("B", []tv{Y}, nil), ck)
	if st, _, _ := findingState(t, s, a.TargetID, X.ID); st != "open" {
		t.Errorf("B upload changed A: %s", st)
	}
	// another tool's complete scan of A never touches A's trivy findings
	sast := mustUpload(t, s, "web", "target=A&kind=fs", readFixture(t, "sarif/semgrep.sarif"), ck)
	if sast.TargetID != a.TargetID {
		t.Fatalf("sarif target %d, want %d", sast.TargetID, a.TargetID)
	}
	if st, _, _ := findingState(t, s, a.TargetID, X.ID); st != "open" {
		t.Errorf("semgrep upload changed trivy finding: %s", st)
	}

	// a complete trivy scan of A without X fixes X; accepted Y keeps its status; semgrep results stay open
	sqlExec(t, s, `update findings set status='accepted' where target_id=$1 and rule_id=$2`, a.TargetID, Y.ID)
	mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), ck)
	if st, _, fixedAt := findingState(t, s, a.TargetID, X.ID); st != "fixed" || !fixedAt {
		t.Errorf("X after trivy scan without it: %s fixed_at=%v", st, fixedAt)
	}
	if st, _, _ := findingState(t, s, a.TargetID, Y.ID); st != "accepted" {
		t.Errorf("accepted Y became %s", st)
	}
	if n := qInt(t, s, `select count(*) from findings where target_id=$1 and kind='sast' and status='open'`, a.TargetID); n != 2 {
		t.Errorf("open semgrep findings %d, want 2", n)
	}
	// X comes back: open again, counted as reopened; Y stays accepted
	res, err := s.ingest(context.Background(), ingestInput{ProjectID: qint64(t, s, `select id from projects where key='web'`),
		TargetKind: "fs", TargetName: "A", Source: "upload", Report: parseReport(t, "trivy", trivyDoc("A", []tv{X, Y}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	st, reopened, fixedAt := findingState(t, s, a.TargetID, X.ID)
	if st != "open" || reopened != 1 || fixedAt {
		t.Errorf("X back: %s reopened=%d fixed_at=%v", st, reopened, fixedAt)
	}
	xID := qint64(t, s, `select id from findings where target_id=$1 and rule_id=$2`, a.TargetID, X.ID)
	if !slices.Equal(res.Reopened, []int64{xID}) || len(res.New) != 0 || len(res.Fixed) != 0 {
		t.Errorf("result new=%v fixed=%v reopened=%v", res.New, res.Fixed, res.Reopened)
	}
	if st, _, _ := findingState(t, s, a.TargetID, Y.ID); st != "accepted" {
		t.Errorf("accepted Y after reappearing: %s", st)
	}
	// and gone again: the result lists it as fixed
	res, err = s.ingest(context.Background(), ingestInput{ProjectID: res.ProjectID, TargetKind: "fs", TargetName: "A",
		Source: "upload", Report: parseReport(t, "trivy", trivyDoc("A", []tv{Y}, nil))})
	if err != nil || !slices.Equal(res.Fixed, []int64{xID}) {
		t.Errorf("fixed %v err %v", res.Fixed, err)
	}
}

func qint64(t *testing.T, s *server, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestScannersParamCompletesKinds(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	c := mustUpload(t, s, "web", "", trivyDoc("C", nil, []string{"DS002"}), ck)
	// Trivy JSON doesn't say which scanners ran: without the param, no misconfig results means "not scanned"
	mustUpload(t, s, "web", "", trivyDoc("C", nil, nil), ck)
	if st, _, _ := findingState(t, s, c.TargetID, "DS002"); st != "open" {
		t.Errorf("misconfig without scanners param: %s", st)
	}
	wantCode(t, upload(t, s, "web", "scanners=vuln,bogus", trivyDoc("C", nil, nil), ck), 400, "unknown scanner")
	mustUpload(t, s, "web", "scanners=vuln,misconfig", trivyDoc("C", nil, nil), ck)
	if st, _, _ := findingState(t, s, c.TargetID, "DS002"); st != "fixed" {
		t.Errorf("misconfig with scanners=vuln,misconfig: %s", st)
	}
}

func TestSeverityIsPerFinding(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, ck := memberSession(t, s)
	const z = "CVE-2024-3000"
	old := "2024-01-01T00:00:00Z"
	a := mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: z, Sev: "LOW", Title: "first title", Modified: old}}, nil), ck)
	b := mustUpload(t, s, "web", "", trivyDoc("B", []tv{{ID: z, Sev: "HIGH", Title: "second title", Desc: "filled later", Modified: old}}, nil), ck)
	sev := func(target int64) string {
		var v string
		s.db.QueryRow(ctx, `select severity from findings where target_id=$1 and rule_id=$2`, target, z).Scan(&v)
		return v
	}
	catalog := func() (title, desc, modified string) {
		s.db.QueryRow(ctx, `select title, description, to_char(last_modified_at at time zone 'UTC', 'YYYY') from vulns where id=$1`, z).
			Scan(&title, &desc, &modified)
		return
	}
	if sev(a.TargetID) != "LOW" || sev(b.TargetID) != "HIGH" {
		t.Errorf("severities A=%s B=%s", sev(a.TargetID), sev(b.TargetID))
	}
	if title, desc, _ := catalog(); title != "first title" || desc != "filled later" {
		t.Errorf("catalog %q %q: the title is filled once, empty fields are filled", title, desc)
	}
	if a.Summary["low"] != 1 || b.Summary["high"] != 1 {
		t.Errorf("summaries %v %v", a.Summary, b.Summary)
	}
	// uploads only fill empty fields: a newer or older record never replaces the shared text
	mustUpload(t, s, "web", "", trivyDoc("C", []tv{{ID: z, Sev: "CRITICAL", Title: "newer title", Modified: "2025-01-01T00:00:00Z"}}, nil), ck)
	if title, desc, mod := catalog(); title != "first title" || desc != "filled later" || mod != "2024" {
		t.Errorf("catalog after newer record %q %q %s", title, desc, mod)
	}
	mustUpload(t, s, "web", "", trivyDoc("D", []tv{{ID: z, Title: "stale title", Modified: "2023-01-01T00:00:00Z"}}, nil), ck)
	if title, _, mod := catalog(); title != "first title" || mod != "2024" {
		t.Errorf("catalog after older record %q %s", title, mod)
	}
	if sev(a.TargetID) != "LOW" || sev(b.TargetID) != "HIGH" {
		t.Errorf("severities changed: A=%s B=%s", sev(a.TargetID), sev(b.TargetID))
	}
	// a finding takes the severity of its own latest scan
	mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: z, Sev: "MEDIUM"}}, nil), ck)
	if sev(a.TargetID) != "MEDIUM" || sev(b.TargetID) != "HIGH" {
		t.Errorf("after rescan of A: A=%s B=%s", sev(a.TargetID), sev(b.TargetID))
	}
}

type scanResp struct {
	ID         int64          `json:"id"`
	TargetID   int64          `json:"target_id"`
	TargetName string         `json:"target_name"`
	Status     string         `json:"status"`
	Summary    map[string]any `json:"summary"`
	HasRaw     bool           `json:"has_raw"`
	Diff       struct {
		New, Fixed, Unchanged int
		PreviousScanID        *int64 `json:"previous_scan_id"`
	} `json:"diff"`
}

func TestScanRoutes(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	X, Y, W := tv{ID: "CVE-2024-1000"}, tv{ID: "CVE-2024-2000"}, tv{ID: "CVE-2024-4000"}
	doc1 := trivyDoc("A", []tv{X, Y}, nil)
	s1 := mustUpload(t, s, "web", "", doc1, ck)
	s2 := mustUpload(t, s, "web", "", trivyDoc("A", []tv{Y, W}, nil), ck)

	type list struct {
		Items      []scanResp `json:"items"`
		NextBefore *int64     `json:"next_before"`
	}
	l := decode[list](t, do(t, s, "GET", "/api/v1/projects/web/scans", nil, ck))
	if len(l.Items) != 2 || l.Items[0].ID != s2.ScanID || l.NextBefore != nil || l.Items[0].TargetName != "A" {
		t.Errorf("scan list %+v", l)
	}
	l = decode[list](t, do(t, s, "GET", "/api/v1/projects/web/scans?limit=1", nil, ck))
	if len(l.Items) != 1 || l.NextBefore == nil || *l.NextBefore != s2.ScanID {
		t.Fatalf("page 1 %+v", l)
	}
	l = decode[list](t, do(t, s, "GET", fmt.Sprintf("/api/v1/projects/web/scans?limit=1&before=%d&target_id=%d", *l.NextBefore, s1.TargetID), nil, ck))
	if len(l.Items) != 1 || l.Items[0].ID != s1.ScanID {
		t.Errorf("page 2 %+v", l)
	}
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/scans?target_id=x", nil, ck), 400, "bad target_id")

	sc := decode[scanResp](t, do(t, s, "GET", fmt.Sprintf("/api/v1/scans/%d", s2.ScanID), nil, ck))
	d := sc.Diff
	if d.New != 1 || d.Fixed != 1 || d.Unchanged != 1 || d.PreviousScanID == nil || *d.PreviousScanID != s1.ScanID ||
		sc.Status != "done" || !sc.HasRaw || sc.Summary["high"] != float64(2) {
		t.Errorf("scan %+v", sc)
	}
	first := decode[scanResp](t, do(t, s, "GET", fmt.Sprintf("/api/v1/scans/%d", s1.ScanID), nil, ck))
	if first.Diff.New != 2 || first.Diff.PreviousScanID != nil {
		t.Errorf("first scan diff %+v", first.Diff)
	}

	type flist struct {
		Items []struct {
			RuleID string `json:"rule_id"`
		} `json:"items"`
		Total int `json:"total"`
	}
	fl := decode[flist](t, do(t, s, "GET", fmt.Sprintf("/api/v1/scans/%d/findings", s2.ScanID), nil, ck))
	var ids []string
	for _, f := range fl.Items {
		ids = append(ids, f.RuleID)
	}
	slices.Sort(ids)
	if fl.Total != 2 || !slices.Equal(ids, []string{Y.ID, W.ID}) {
		t.Errorf("scan findings %+v", fl)
	}

	rec := do(t, s, "GET", fmt.Sprintf("/api/v1/scans/%d/raw", s1.ScanID), nil, ck)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/gzip" || !bytes.Equal(gunzip(t, rec.Body.Bytes()), doc1) {
		t.Errorf("raw: %d %s", rec.Code, rec.Header())
	}
	sqlExec(t, s, `update scans set raw = null where id=$1`, s1.ScanID)
	wantCode(t, do(t, s, "GET", fmt.Sprintf("/api/v1/scans/%d/raw", s1.ScanID), nil, ck), 404, "raw past retention")
	wantCode(t, do(t, s, "GET", "/api/v1/scans/abc", nil, ck), 404, "malformed id")
}

func TestRawRetention(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	if err := s.putSetting(context.Background(), "retention", map[string]int{"raw_per_target": 1, "raw_days": 1}); err != nil {
		t.Fatal(err)
	}
	s1 := mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), ck)
	other := mustUpload(t, s, "web", "", trivyDoc("B", nil, nil), ck)
	sqlExec(t, s, `update scans set created_at = now() - interval '2 days'`)
	s2 := mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), ck)
	s3 := mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), ck)
	hasRaw := func(id int64) bool {
		return qInt(t, s, `select count(*) from scans where id=$1 and raw is not null`, id) == 1
	}
	// s1 is old and not the newest; s2 is not the newest but within a day; another target is not trimmed
	if hasRaw(s1.ScanID) || !hasRaw(s2.ScanID) || !hasRaw(s3.ScanID) || !hasRaw(other.ScanID) {
		t.Errorf("raw kept: s1=%v s2=%v s3=%v other=%v", hasRaw(s1.ScanID), hasRaw(s2.ScanID), hasRaw(s3.ScanID), hasRaw(other.ScanID))
	}
	if n := qInt(t, s, `select count(*) from scans`); n != 4 {
		t.Errorf("scan rows %d", n)
	}
}

func TestAfterIngestHooks(t *testing.T) {
	s := testServer(t)
	pid, ck := memberSession(t, s)
	saved := afterIngest
	t.Cleanup(func() { afterIngest = saved })
	var got []*ingestResult
	afterIngest = append(afterIngest, func(ctx context.Context, hs *server, r *ingestResult) {
		if hs != s {
			t.Error("hook got another server")
		}
		got = append(got, r)
	})
	doc := trivyDoc("A", []tv{{ID: "CVE-2024-1000"}, {ID: "CVE-2024-2000"}}, nil)
	res := mustUpload(t, s, "web", "", doc, ck)
	if len(got) != 1 || got[0].ScanID != res.ScanID || got[0].ProjectID != pid || len(got[0].New) != 2 || got[0].Policy.Passed != res.Policy.Passed {
		t.Fatalf("hook calls %+v", got)
	}
	wantCode(t, upload(t, s, "web", "", doc, ck), 200, "duplicate")
	if len(got) != 1 {
		t.Error("hooks ran for a duplicate")
	}
}

func TestPreCreatedScan(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, _ := memberSession(t, s)
	tid := qint64(t, s, `insert into targets(project_id, kind, name) values($1, 'fs', 'A') returning id`, pid)
	sid := qint64(t, s, `insert into scans(project_id, target_id, source, format, status) values($1, $2, 'server', 'trivy', 'running') returning id`, pid, tid)
	doc := trivyDoc("A", []tv{{ID: "CVE-2024-1000"}}, nil)
	res, err := s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "server",
		Report: parseReport(t, "trivy", doc), Raw: doc, ScanID: &sid})
	if err != nil || res.ScanID != sid || res.TargetID != tid || len(res.New) != 1 {
		t.Fatalf("ingest %+v %v", res, err)
	}
	if n := qInt(t, s, `select count(*) from scans where id=$1 and status='done' and source='server' and finished_at is not null and raw is not null`, sid); n != 1 {
		t.Error("pre-created scan not finished")
	}
	if n := qInt(t, s, `select count(*) from scans`); n != 1 {
		t.Errorf("scans %d", n)
	}

	// a scan canceled while it ran is not finished, and nothing of the report is written
	sid2 := qint64(t, s, `insert into scans(project_id, target_id, source, format, status) values($1, $2, 'server', 'trivy', 'canceled') returning id`, pid, tid)
	doc2 := trivyDoc("A", []tv{{ID: "CVE-2024-9999"}}, nil)
	_, err = s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "server",
		Report: parseReport(t, "trivy", doc2), Raw: doc2, ScanID: &sid2})
	if !errors.Is(err, errScanCanceled) {
		t.Errorf("canceled scan: %v", err)
	}
	// a finished scan is not refilled either (generic error)
	if _, err = s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "server",
		Report: parseReport(t, "trivy", doc2), Raw: doc2, ScanID: &sid}); err == nil || errors.Is(err, errScanCanceled) {
		t.Errorf("done scan: %v", err)
	}
	if n := qInt(t, s, `select count(*) from scans where id=$1 and status='canceled' and raw is null`, sid2); n != 1 {
		t.Error("canceled scan was changed")
	}
	if n := qInt(t, s, `select count(*) from findings where rule_id='CVE-2024-9999'`) + qInt(t, s, `select count(*) from packages where scan_id=$1`, sid2); n != 0 {
		t.Errorf("rows written for a canceled scan: %d", n)
	}
}

// The scan is committed before the policy and the hooks run, so a client hanging up must not stop them.
func TestPostCommitSurvivesCancel(t *testing.T) {
	s := testServer(t)
	pid, _ := memberSession(t, s)
	saved := afterIngest
	t.Cleanup(func() { afterIngest = saved })
	ctx, cancel := context.WithCancel(context.Background())
	var later error
	ran := 0
	afterIngest = append(afterIngest,
		func(context.Context, *server, *ingestResult) { cancel() }, // the client hangs up
		func(context.Context, *server, *ingestResult) { panic("broken hook") },
		func(hctx context.Context, hs *server, r *ingestResult) {
			ran++
			later = hs.db.QueryRow(hctx, `select 1`).Scan(new(int))
		})
	doc := trivyDoc("A", []tv{{ID: "CVE-2024-1000", Sev: "CRITICAL"}}, nil)
	res, err := s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "upload",
		Report: parseReport(t, "trivy", doc), Raw: doc})
	if err != nil {
		t.Fatal(err)
	}
	if ran != 1 || later != nil {
		t.Errorf("hook after cancel and panic: ran=%d err=%v", ran, later)
	}
	if n := qInt(t, s, `select count(*) from scans where id=$1 and policy->>'passed' = 'false'`, res.ScanID); n != 1 {
		t.Error("policy not stored")
	}
	// over HTTP too: a panicking hook does not turn the committed upload into a 500
	afterIngest = append(saved, func(context.Context, *server, *ingestResult) { panic("broken hook") })
	u := mkUser(t, s, "dev2", "")
	addMember(t, s, pid, "user", itoa(u.ID), "member")
	mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), loginAs(t, s, u))
}

// No uploader can rewrite the shared catalog text for every project, and a future date is dropped.
func TestCatalogCannotBePoisoned(t *testing.T) {
	e := newExEnv(t)
	e.project(t, "pa")
	_, bck, _ := e.project(t, "pb")
	mustUpload(t, e.s, "pb", "target=app&kind=fs", trivyDoc("app", []tv{{ID: "CVE-2024-7777", Title: "real", Desc: "real", Modified: "2026-10-01T00:00:00Z"}}, nil), bck)
	mustUpload(t, e.s, "pb", "target=app&kind=fs", trivyDoc("app", []tv{{ID: "CVE-2024-7777", Title: "evil", Desc: "go to http://evil", Modified: "9999-01-01T00:00:00Z"}}, nil), bck)
	var title, desc string
	e.s.db.QueryRow(context.Background(), `select title, description from vulns where id='CVE-2024-7777'`).Scan(&title, &desc)
	if title != "real" || desc != "real" {
		t.Errorf("catalog text replaced: %q %q", title, desc)
	}
	mustUpload(t, e.s, "pb", "target=app&kind=fs", trivyDoc("app", []tv{{ID: "CVE-2024-8888", Title: "t", Modified: "9999-01-01T00:00:00Z"}}, nil), bck)
	if n := qInt(t, e.s, `select count(*) from vulns where last_modified_at > now() or published_at > now()`); n != 0 {
		t.Errorf("%d catalog rows keep a future date", n)
	}
}
