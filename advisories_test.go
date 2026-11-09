package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type advView struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Severity string           `json:"severity"`
	Affected []map[string]any `json:"affected"`
	Active   bool             `json:"active"`
	Warnings []string         `json:"warnings"`
}

func pkgDoc(name, typ string, pkgs ...[2]string) []byte {
	docSeq++
	ps := []map[string]any{}
	for _, p := range pkgs {
		ps = append(ps, map[string]any{"Name": p[0], "Version": p[1]})
	}
	b, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": name, "ArtifactType": "filesystem", "Created": docSeq,
		"Results": []map[string]any{{"Target": "pkgs", "Class": "lang-pkgs", "Type": typ, "Packages": ps}}})
	return b
}

func advBody(id, eco, pkg, rng string) map[string]any {
	return map[string]any{"id": id, "title": "사내 취약점", "severity": "HIGH", "description": "d",
		"affected": []map[string]any{{"ecosystem": eco, "package": pkg, "range": rng, "fixed": "1.3.1"}}}
}

func advFindings(t *testing.T, s *server, id string) (open, fixed int) {
	t.Helper()
	return qInt(t, s, `select count(*) from findings where rule_id=$1 and tool='advisory' and status='open'`, id),
		qInt(t, s, `select count(*) from findings where rule_id=$1 and tool='advisory' and status='fixed'`, id)
}

func TestEcoAliases(t *testing.T) {
	for in, want := range map[string]string{"pypi": "pip", "PyPI": "pip", "golang": "gomod", "rubygems": "gem", "crates.io": "cargo",
		"maven": "maven", "sles": "suse", "opensuse": "suse", " npm ": "npm", "weird": "weird"} {
		if got := normEco(in); got != want {
			t.Errorf("normEco(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdvisoryMatchesExistingInventory(t *testing.T) {
	e := newExEnv(t)
	_, mck, tid := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}, [2]string{"lodash", "4.17.21"}), mck)
	// members may read advisories but not write them
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), mck), 403, "member create")
	rec := do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), e.secA)
	wantCode(t, rec, 201, "create")
	var f struct {
		Status, Origin, Tool, Severity, Fixed, Pkg, Ver string
		Kind                                            string
	}
	if err := e.s.db.QueryRow(context.Background(), `select status, origin, tool, severity, fixed_version, pkg_name, pkg_version, kind
		from findings where rule_id='INT-2026-001' and target_id=$1`, tid).Scan(&f.Status, &f.Origin, &f.Tool, &f.Severity, &f.Fixed, &f.Pkg, &f.Ver, &f.Kind); err != nil {
		t.Fatalf("no finding without a rescan: %v", err)
	}
	if f.Status != "open" || f.Origin != "advisory" || f.Tool != "advisory" || f.Severity != "HIGH" || f.Fixed != "1.3.1" || f.Kind != "vuln" || f.Ver != "1.3.0" {
		t.Errorf("finding = %+v", f)
	}
	if n := qInt(t, e.s, `select count(*) from findings where rule_id='INT-2026-001'`); n != 1 {
		t.Errorf("findings = %d (lodash must not match)", n)
	}
	if n := qInt(t, e.s, `select count(*) from vulns where id='INT-2026-001'`); n != 1 {
		t.Errorf("catalog rows = %d", n)
	}
	// visible through the findings API and linked to the latest scan
	rec = do(t, e.s, "GET", "/api/v1/findings?origin=advisory", nil, mck)
	if p := decode[struct{ Total int }](t, rec); p.Total != 1 {
		t.Errorf("findings api total = %d", p.Total)
	}
	if n := qInt(t, e.s, `select count(*) from scan_findings sf join findings f on f.id=sf.finding_id where f.rule_id='INT-2026-001'`); n != 1 {
		t.Errorf("scan_findings = %d", n)
	}
	// the next scan of the target keeps it (a trivy-complete scan must not fix advisory findings)
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Errorf("after rescan open = %d", o)
	}
	// a rescan without the package fixes it
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"lodash", "4.17.21"}), mck)
	if o, fx := advFindings(t, e.s, "INT-2026-001"); o != 0 || fx != 1 {
		t.Errorf("package gone: open=%d fixed=%d", o, fx)
	}
	// and a scan that brings a vulnerable version matches at ingest
	up := mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.0.0"}), mck)
	if up.Summary["high"] != 1 { // matched inside the ingest, before the summary and the policy
		t.Errorf("upload summary misses the advisory finding: %v", up.Summary)
	}
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Errorf("new scan: open = %d", o)
	}
	if n := qInt(t, e.s, `select reopened_count from findings where rule_id='INT-2026-001'`); n != 1 {
		t.Errorf("reopened_count = %d", n)
	}
	if n := auditCount(t, e.s, "advisory.create"); n != 1 {
		t.Errorf("audit = %d", n)
	}
}

func TestAdvisoryUpdateUnmatchFixes(t *testing.T) {
	e := newExEnv(t)
	_, mck, _ := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "pypi", "left-pad", "<1.3.1"), e.secA), 201, "create pypi")
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 0 {
		t.Fatalf("pypi advisory matched an npm package")
	}
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), e.secA), 200, "put npm")
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Fatalf("open = %d", o)
	}
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", advBody("INT-2026-001", "npm", "left-pad", "<1.0.0"), e.secA), 200, "put narrower")
	if o, fx := advFindings(t, e.s, "INT-2026-001"); o != 0 || fx != 1 {
		t.Errorf("narrowed: open=%d fixed=%d", o, fx)
	}
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", advBody("INT-2026-001", "npm", "left-pad", "<2"), e.secA), 200, "put wider")
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Fatalf("widened open = %d", o)
	}
	// deactivate
	b := advBody("INT-2026-001", "npm", "left-pad", "<2")
	b["active"] = false
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", b, e.secA), 200, "deactivate")
	if o, fx := advFindings(t, e.s, "INT-2026-001"); o != 0 || fx != 1 {
		t.Errorf("deactivated: open=%d fixed=%d", o, fx)
	}
	// a scan does not bring an inactive advisory back
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 0 {
		t.Errorf("inactive advisory matched a new scan")
	}
	// delete after re-activating
	b["active"] = true
	do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", b, e.secA)
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Fatalf("reactivated open = %d", o)
	}
	wantCode(t, do(t, e.s, "DELETE", "/api/v1/advisories/INT-2026-001", nil, e.secA), 204, "delete")
	if o, fx := advFindings(t, e.s, "INT-2026-001"); o != 0 || fx != 1 {
		t.Errorf("deleted: open=%d fixed=%d", o, fx)
	}
	wantCode(t, do(t, e.s, "GET", "/api/v1/advisories/INT-2026-001", nil, mck), 404, "get deleted")
}

func csvBody(rows ...string) string {
	return "id,title,severity,ecosystem,package,range,fixed,description,refs\n" + strings.Join(rows, "\n") + "\n"
}

func TestAdvisoryImportCSV(t *testing.T) {
	e := newExEnv(t)
	_, mck, _ := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	bad := csvBody(`INT-2026-001,첫째,HIGH,npm,left-pad,<1.3.1,1.3.1,설명,https://example.internal/a`,
		`INT-2026-002,둘째,SEVERE,npm,lodash,<4,4.0.0,설명,`)
	rec := do(t, e.s, "POST", "/api/v1/advisories/import", bad, e.secA)
	wantCode(t, rec, 400, "bad row")
	if !strings.Contains(rec.Body.String(), "3행") {
		t.Errorf("message lacks the row number: %s", rec.Body.String())
	}
	if n := qInt(t, e.s, `select count(*) from advisories`); n != 0 {
		t.Errorf("saved %d advisories from a bad file", n)
	}
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories/import", csvBody(`INT-2026-001,첫째,HIGH,npm,left-pad,<1.3.1,1.3.1,설명,`), mck), 403, "member import")
	good := csvBody(`INT-2026-001,첫째,HIGH,npm,left-pad,<1.3.1,1.3.1,설명,https://example.internal/a`,
		`INT-2026-002,둘째,low,pypi,requests,"<2.0, >=1.0",2.0,"쉼표, 있는 설명",`,
		`INT-2026-002,둘째,low,npm,requests,<2.0,2.0,,`)
	rec = do(t, e.s, "POST", "/api/v1/advisories/import", good, e.secA)
	wantCode(t, rec, 200, "good import")
	if n := qInt(t, e.s, `select count(*) from advisories`); n != 2 {
		t.Errorf("advisories = %d", n)
	}
	if n := qInt(t, e.s, `select jsonb_array_length(affected) from advisories where id='INT-2026-002'`); n != 2 {
		t.Errorf("rows with the same id must merge into one advisory, affected = %d", n)
	}
	if o, _ := advFindings(t, e.s, "INT-2026-001"); o != 1 {
		t.Errorf("imported advisory did not match: %d", o)
	}
	// multipart upload works the same
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "a.csv")
	fw.Write([]byte(csvBody(`INT-2026-003,셋째,HIGH,npm,left-pad,<9,9,,`)))
	mw.Close()
	req := bytes.NewReader(buf.Bytes())
	r := httpReq(t, e.s, "POST", "/api/v1/advisories/import", req, mw.FormDataContentType(), e.secA)
	wantCode(t, r, 200, "multipart import")
}

func TestAdvisoryValidation(t *testing.T) {
	e := newExEnv(t)
	post := func(b map[string]any, want int) {
		t.Helper()
		wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", b, e.secA), want, "create")
	}
	post(advBody("bad id", "npm", "x", "<1"), 400)
	post(advBody("I1", "npm", "x", "<1"), 400) // id too short? pattern needs 3+ chars after the first
	post(advBody("INT-2026-001", "npm", "x", "<<<"), 400)
	post(advBody("INT-2026-001", "npm", "", "<1"), 400)
	post(advBody("INT-2026-001", "npm", "x", ""), 400)
	b := advBody("INT-2026-001", "npm", "x", "<1")
	b["severity"] = "SEVERE"
	post(b, 400)
	b = advBody("INT-2026-001", "npm", "x", "<1")
	b["affected"] = []any{}
	post(b, 400)
	post(advBody("INT-2026-001", "npm", "x", "<1"), 201)
	post(advBody("INT-2026-001", "npm", "x", "<1"), 409)
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-9999", advBody("INT-9999", "npm", "x", "<1"), e.secA), 404, "put unknown")
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", advBody("INT-2026-002", "npm", "x", "<1"), e.secA), 400, "id mismatch")
}

func TestAdvisoryWarningsAndUncertainVersion(t *testing.T) {
	e := newExEnv(t)
	_, mck, tid := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "nuget", [2]string{"foo", "1.0.0"}, [2]string{"bar", "not a version!!"}), mck)
	// unknown ecosystem: generic comparison still matches, with a warning
	b := advBody("INT-2026-001", "nuget", "foo", "<2.0.0")
	b["affected"] = append(b["affected"].([]map[string]any), map[string]any{"ecosystem": "swiftpm", "package": "foo", "range": "<2", "fixed": ""})
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", b, e.secA), 201, "create")
	rec := do(t, e.s, "GET", "/api/v1/advisories/INT-2026-001", nil, mck)
	wantCode(t, rec, 200, "get")
	a := decode[advView](t, rec)
	if !containsStr(a.Warnings, "generic comparison for swiftpm") {
		t.Errorf("warnings = %v", a.Warnings)
	}
	// an installed version that cannot be compared: still a finding, flagged, and counted in the warnings
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-002", "nuget", "bar", "<2.0.0"), e.secA), 201, "create 2")
	var uncertain bool
	if err := e.s.db.QueryRow(context.Background(), `select coalesce((details->>'version_uncertain')::bool, false) from findings
		where rule_id='INT-2026-002' and target_id=$1`, tid).Scan(&uncertain); err != nil || !uncertain {
		t.Fatalf("uncertain finding: %v %v", uncertain, err)
	}
	a = decode[advView](t, do(t, e.s, "GET", "/api/v1/advisories/INT-2026-002", nil, mck))
	if len(a.Warnings) != 1 || !strings.Contains(a.Warnings[0], "1") {
		t.Errorf("warnings = %v", a.Warnings)
	}
	l := decode[[]advView](t, do(t, e.s, "GET", "/api/v1/advisories", nil, mck))
	if len(l) != 2 {
		t.Errorf("list = %d", len(l))
	}
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestHarborTargetsExcluded(t *testing.T) {
	e := newExEnv(t)
	_, mck, tid := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	sqlExec(t, e.s, `update targets set recheck_excluded = true where id=$1`, tid)
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), e.secA), 201, "create")
	if n := qInt(t, e.s, `select count(*) from findings where rule_id='INT-2026-001'`); n != 0 {
		t.Errorf("excluded target matched: %d", n)
	}
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	if n := qInt(t, e.s, `select count(*) from findings where rule_id='INT-2026-001'`); n != 0 {
		t.Errorf("excluded target matched at ingest: %d", n)
	}
	rec := do(t, e.s, "POST", "/api/v1/advisories/preview", advBody("", "npm", "left-pad", "<1.3.1"), e.secA)
	wantCode(t, rec, 200, "preview")
	if p := decode[[]map[string]string](t, rec); len(p) != 0 {
		t.Errorf("preview included an excluded target: %v", p)
	}
	sqlExec(t, e.s, `update targets set recheck_excluded = false where id=$1`, tid)
	rec = do(t, e.s, "POST", "/api/v1/advisories/preview", advBody("", "npm", "left-pad", "<1.3.1"), e.secA)
	p := decode[[]map[string]string](t, rec)
	if len(p) != 1 || p[0]["project_key"] != "web" || p[0]["pkg"] != "left-pad" || p[0]["version"] != "1.3.0" || p[0]["target"] != "app" {
		t.Errorf("preview = %v", p)
	}
	if n := qInt(t, e.s, `select count(*) from findings where rule_id=''`); n != 0 {
		t.Errorf("preview wrote findings")
	}
}

func TestAdvisoryFindingGetsActiveException(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web")
	ex := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "INT-2026-001"}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 200)
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), e.secA), 201, "create")
	if st := fstatus(t, e.s, pid, "INT-2026-001"); st != "accepted" {
		t.Errorf("status = %s", st)
	}
}

func httpReq(t *testing.T, s *server, method, path string, body *bytes.Reader, ctype string, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}
