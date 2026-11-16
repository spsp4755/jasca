package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func intelFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/intel/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(b)
	zw.Close()
	return out.Bytes()
}

func postIntel(t *testing.T, s *server, ck *http.Cookie, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, h := multipartReq(t, nil, file)
	return do(t, s, "POST", "/api/v1/admin/intel", body, ck, h)
}

func TestIntelParsers(t *testing.T) {
	kevDoc, epssDoc := intelFixture(t, "kev.json"), intelFixture(t, "epss.csv")
	kev, epss, date, err := parseIntel(bytes.NewReader(kevDoc))
	if err != nil || len(kev) != 3 || epss != nil || date == nil || date.Format("2006-01-02") != "2026-11-13" {
		t.Fatalf("kev: %v %d %v %v", err, len(kev), epss, date)
	}
	if k := kev[0]; k.CVE != "CVE-2021-44228" || !k.Ransomware || k.Added.Format("2006-01-02") != "2021-12-10" || !strings.HasPrefix(k.Action, "Apply mitigations") || kev[1].Ransomware {
		t.Errorf("kev entries %+v", kev)
	}
	// a paragraph-long required action (the newer catalog entries) is not kept
	long := bytes.Replace(kevDoc, []byte("Apply updates per vendor instructions."), []byte(strings.Repeat("Apply updates. ", 20)), 1)
	if kev, _, _, err := parseIntel(bytes.NewReader(long)); err != nil || kev[1].Action != "" || kev[2].Action == "" {
		t.Errorf("long action: %v %+v", err, kev)
	}
	for name, doc := range map[string][]byte{"plain": epssDoc, "gzip": gz(epssDoc), "bom and no comment": append([]byte("\xef\xbb\xbf"), epssDoc[bytes.IndexByte(epssDoc, '\n')+1:]...)} {
		kev, epss, date, err := parseIntel(bytes.NewReader(doc))
		if err != nil || kev != nil || len(epss) != 6 || epss[0] != (epssRow{"CVE-2021-44228", 0.94358, 0.99957}) {
			t.Fatalf("epss %s: %v %v %v", name, err, kev, epss)
		}
		if hasDate := date != nil && date.Format("2006-01-02") == "2026-11-16"; hasDate != (name != "bom and no comment") {
			t.Errorf("epss %s: date %v", name, date)
		}
	}
	bad := map[string][]byte{
		"empty":                    nil,
		"other json":               []byte(`{"SchemaVersion": 2, "Results": []}`),
		"kev cut off":              kevDoc[:len(kevDoc)/2],
		"kev count mismatch":       bytes.Replace(kevDoc, []byte(`"count": 3`), []byte(`"count": 1781`), 1),
		"kev not a cve":            bytes.Replace(kevDoc, []byte("CVE-2099-10001"), []byte("GHSA-xxxx-yyyy-zzzz"), 1),
		"kev bad date":             bytes.Replace(kevDoc, []byte("2026-11-12"), []byte("12/11/2026"), 1),
		"kev trailing text":        append(append([]byte{}, kevDoc...), []byte("{}")...),
		"epss gzip cut off":        gz(epssDoc)[:40],
		"epss row cut off":         epssDoc[:len(epssDoc)-9],
		"epss wrong header":        bytes.Replace(epssDoc, []byte("cve,epss,percentile"), []byte("cve,cvss,percentile"), 1),
		"epss only header":         []byte("#model_version:v1,score_date:2026-11-16T00:00:00Z\ncve,epss,percentile\n"),
		"epss huge number":         bytes.Replace(epssDoc, []byte("0.50312"), []byte("1e309"), 1),
		"epss above one":           bytes.Replace(epssDoc, []byte("0.50312"), []byte("50.312"), 1),
		"epss negative percentile": bytes.Replace(epssDoc, []byte("0.97511"), []byte("-0.1"), 1),
		"epss nan":                 bytes.Replace(epssDoc, []byte("0.50312"), []byte("NaN"), 1),
		"epss not a cve":           bytes.Replace(epssDoc, []byte("CVE-2099-10003"), []byte("'; drop table x"), 1),
		"a tarball":                gz([]byte("trivy.db\x00\x00\x00")),
	}
	for name, doc := range bad {
		if kev, epss, _, err := parseIntel(bytes.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted (%d kev, %d epss)", name, len(kev), len(epss))
		}
	}
}

func TestIntelUpload(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, dev := memberSession(t, s)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	kevDoc, epssDoc := intelFixture(t, "kev.json"), intelFixture(t, "epss.csv")

	wantCode(t, postIntel(t, s, dev, kevDoc), 403, "a member uploads")
	wantCode(t, do(t, s, "GET", "/api/v1/admin/intel", nil, dev), 403, "a member reads the state")
	if st := decode[intelStatus](t, do(t, s, "GET", "/api/v1/admin/intel", nil, admin)); st.KEV.LoadedAt != nil || st.EPSS.Count != 0 {
		t.Errorf("state before any upload %+v", st)
	}

	// findings before the data: no badge, no score, and the KEV filter matches nothing
	mustUpload(t, s, "web", "target=api&kind=image", trivyDoc("api", []tv{
		{ID: "CVE-2099-10001", Sev: "HIGH", Fixed: "2.0"}, {ID: "CVE-2099-10004", Sev: "HIGH"}, {ID: "CVE-2099-10009", Sev: "CRITICAL"},
		{ID: "CVE-2021-44228", Sev: "CRITICAL", Pkg: "log4j"}, {ID: "GHSA-aaaa-bbbb-cccc", Sev: "LOW"}}, nil), dev)
	ch := mkChannel(t, s, "mattermost", "sec", `{"url":"http://127.0.0.1:1/hook"}`, true)
	sqlExec(t, s, `insert into notify_subs values($1,$2,'{kev_listed}')`, pid, ch)
	type row struct {
		RuleID  string   `json:"rule_id"`
		KEV     bool     `json:"kev"`
		EPSS    *float64 `json:"epss"`
		EPSSPct *float64 `json:"epss_percentile"`
	}
	type page struct {
		Items      []row   `json:"items"`
		NextCursor *string `json:"next_cursor"`
		Total      int     `json:"total"`
	}
	list := func(q string) page {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/findings?"+q, nil, dev)
		wantCode(t, rec, 200, q)
		return decode[page](t, rec)
	}
	ids := func(p page) string {
		var out []string
		for _, r := range p.Items {
			out = append(out, strings.TrimPrefix(r.RuleID, "CVE-"))
		}
		return strings.Join(out, " ")
	}
	if p := list("kev=true"); p.Total != 0 {
		t.Errorf("KEV filter without data: %+v", p)
	}
	if p := list(""); p.Items[0].KEV || p.Items[0].EPSS != nil {
		t.Errorf("row without data %+v", p.Items[0])
	}

	// a bad file is refused and audited; nothing is stored
	rec := postIntel(t, s, admin, kevDoc[:200])
	if wantCode(t, rec, 400, "cut-off catalog"); errCode(t, rec) != "bad_file" {
		t.Errorf("code %s", rec.Body.String())
	}
	wantCode(t, postIntel(t, s, admin, nil), 400, "no file")
	if n := qint64(t, s, `select count(*) from vuln_intel`); n != 0 {
		t.Errorf("%d rows after refused uploads", n)
	}

	// KEV: stored, state and audit say so, every listed CVE is new, and the project hears about its two open ones
	type result struct {
		intelStatus
		Kind        string `json:"kind"`
		NewlyListed int    `json:"newly_listed"`
	}
	rec = postIntel(t, s, admin, kevDoc)
	wantCode(t, rec, 200, "kev upload")
	if r := decode[result](t, rec); r.Kind != "kev" || r.NewlyListed != 3 || r.KEV.Count != 3 || r.KEV.LoadedAt == nil ||
		r.KEV.Date.Format("2006-01-02") != "2026-11-13" || r.EPSS.LoadedAt != nil {
		t.Errorf("kev result %+v", r)
	}
	if n := qint64(t, s, `select count(*) from audit_log where action = 'intel.upload' and target = 'kev' and details->>'newly_listed' = '3'`); n != 1 {
		t.Errorf("audit rows %d", n)
	}
	if n := qint64(t, s, `select count(*) from audit_log where action = 'intel.upload_failed'`); n != 1 {
		t.Errorf("failed-upload audit rows %d", n)
	}
	var payload string
	if err := s.db.QueryRow(ctx, `select payload::text from deliveries where event = 'kev_listed'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	msg := s.renderMsg(ctx, "kev_listed", []byte(payload)).text()
	if !strings.HasPrefix(msg, "[web] 악용이 확인된 취약점 2건\n") || !strings.Contains(msg, "- CRITICAL CVE-2021-44228 (log4j) · 대상 api") ||
		!strings.Contains(msg, "- HIGH CVE-2099-10001 (zlib) · 대상 api") {
		t.Errorf("message:\n%s", msg)
	}

	// EPSS (gzipped, as it is published): scores join the same rows; a CVE in neither file has no row
	rec = postIntel(t, s, admin, gz(epssDoc))
	wantCode(t, rec, 200, "epss upload")
	if r := decode[result](t, rec); r.Kind != "epss" || r.EPSS.Count != 6 || r.EPSS.Date.Format("2006-01-02") != "2026-11-16" || r.KEV.Count != 3 {
		t.Errorf("epss result %+v", r)
	}
	if n := qint64(t, s, `select count(*) from vuln_intel`); n != 7 { // 3 KEV + 6 EPSS, two in both
		t.Errorf("%d rows", n)
	}

	// the list: inside a severity KEV comes first; the fields are filled
	p := list("")
	if got := ids(p); got != "2021-44228 2099-10009 2099-10001 2099-10004 GHSA-aaaa-bbbb-cccc" {
		t.Errorf("default order: %s", got)
	}
	if r := p.Items[0]; !r.KEV || r.EPSS == nil || *r.EPSS != 0.94358 || *r.EPSSPct != 0.99957 {
		t.Errorf("log4shell row %+v", r)
	}
	if r := p.Items[1]; r.KEV || r.EPSS != nil {
		t.Errorf("a CVE no file names %+v", r)
	}
	if p := list("kev=true"); p.Total != 2 || ids(p) != "2021-44228 2099-10001" {
		t.Errorf("KEV filter: %d %s", p.Total, ids(p))
	}
	wantCode(t, do(t, s, "GET", "/api/v1/findings?kev=no", nil, dev), 400, "kev=no")
	// keyset pages, one row at a time, in both new orders
	for sort, want := range map[string]string{
		"":     "2021-44228 2099-10009 2099-10001 2099-10004 GHSA-aaaa-bbbb-cccc",
		"epss": "2021-44228 2099-10001 2099-10004 GHSA-aaaa-bbbb-cccc 2099-10009", // no score last, newest first
	} {
		var got []string
		cursor := ""
		for i := 0; i < 10; i++ {
			pg := list("limit=1&sort=" + sort + cursor)
			if len(pg.Items) == 0 {
				break
			}
			got = append(got, strings.TrimPrefix(pg.Items[0].RuleID, "CVE-"))
			if pg.NextCursor == nil {
				break
			}
			cursor = "&cursor=" + *pg.NextCursor
		}
		if strings.Join(got, " ") != want {
			t.Errorf("sort=%s pages: %v", sort, got)
		}
	}
	wantCode(t, do(t, s, "GET", "/api/v1/findings?sort=epss&cursor=x.1", nil, dev), 400, "bad epss cursor")
	wantCode(t, do(t, s, "GET", "/api/v1/findings?sort=cvss", nil, dev), 400, "unknown sort")

	// CSV: three columns at the end
	csv := strings.Split(strings.TrimSpace(do(t, s, "GET", "/api/v1/findings.csv", nil, dev).Body.String()), "\r\n")
	if !strings.HasSuffix(csv[0], `"조치 기한","악용 확인(KEV)","EPSS","EPSS 백분위"`) || !strings.HasSuffix(csv[1], `,"Y","0.94358","0.99957"`) ||
		!strings.HasSuffix(csv[2], `,"","",""`) {
		t.Errorf("csv:\n%s", strings.Join(csv[:3], "\n"))
	}

	// vulnerability detail, report summary, home count
	type vuln struct {
		KEV   *vulnKEV    `json:"kev"`
		EPSS  *float64    `json:"epss"`
		Intel intelStatus `json:"intel"`
	}
	if v := decode[vuln](t, do(t, s, "GET", "/api/v1/vulns/CVE-2021-44228", nil, dev)); v.KEV == nil || v.KEV.DateAdded != "2021-12-10" ||
		!v.KEV.Ransomware || v.KEV.RequiredAction == "" || v.EPSS == nil || *v.EPSS != 0.94358 || v.Intel.KEV.Count != 3 {
		t.Errorf("vuln %+v", v)
	}
	if v := decode[vuln](t, do(t, s, "GET", "/api/v1/vulns/CVE-2099-10004", nil, dev)); v.KEV != nil || v.EPSS == nil || *v.EPSS != 0.04753 {
		t.Errorf("vuln with a score only %+v", v)
	}
	if v := decode[vuln](t, do(t, s, "GET", "/api/v1/vulns/GHSA-aaaa-bbbb-cccc", nil, dev)); v.KEV != nil || v.EPSS != nil || v.Intel.EPSS.Count != 6 {
		t.Errorf("vuln without data %+v", v)
	}
	rep := decode[struct {
		Summary  struct{ KEV int }
		Findings []row
	}](t, do(t, s, "GET", "/api/v1/projects/web/report", nil, dev))
	if rep.Summary.KEV != 2 || !rep.Findings[0].KEV || rep.Findings[1].KEV {
		t.Errorf("report %+v", rep)
	}
	dash := decode[struct {
		KEV struct {
			Open   int
			Loaded bool
		}
	}](t, do(t, s, "GET", "/api/v1/dashboard", nil, dev))
	if dash.KEV.Open != 2 || !dash.KEV.Loaded {
		t.Errorf("dashboard %+v", dash)
	}
	other := loginAs(t, s, mkUser(t, s, "outsider", "")) // sees no project
	if d := decode[struct{ KEV struct{ Open int } }](t, do(t, s, "GET", "/api/v1/dashboard", nil, other)); d.KEV.Open != 0 {
		t.Errorf("an outsider's count %+v", d)
	}

	// a second catalog: one CVE dropped, one added. Only the added one is new, and only its project is told;
	// the dropped one loses the flag but keeps its EPSS row, and a row left with nothing goes.
	kev2 := bytes.Replace(bytes.Replace(kevDoc, []byte("CVE-2099-10001"), []byte("CVE-2099-10009"), 1), []byte("CVE-2099-10002"), []byte("CVE-2099-10008"), 1)
	rec = postIntel(t, s, admin, kev2)
	wantCode(t, rec, 200, "second catalog")
	if r := decode[result](t, rec); r.NewlyListed != 2 {
		t.Errorf("second catalog: newly listed %d", r.NewlyListed)
	}
	if err := s.db.QueryRow(ctx, `select payload::text from deliveries where event = 'kev_listed' order by id desc limit 1`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `event = 'kev_listed'`); n != 2 || !strings.Contains(payload, "CVE-2099-10009") || strings.Contains(payload, "CVE-2021-44228") {
		t.Errorf("%d deliveries, last %s", n, payload)
	}
	if p := list("kev=true"); ids(p) != "2021-44228 2099-10009" {
		t.Errorf("KEV after the second catalog: %s", ids(p))
	}
	if n := qint64(t, s, `select count(*) from vuln_intel where cve = 'CVE-2099-10001' and not kev and epss is not null`); n != 1 {
		t.Error("the dropped CVE lost its EPSS row or kept the flag")
	}
	if n := qint64(t, s, `select count(*) from vuln_intel where cve = 'CVE-2099-10002'`); n != 0 {
		t.Error("a row with neither KEV nor EPSS stayed")
	}
	// the same catalog again: nothing is new, nobody is told
	wantCode(t, postIntel(t, s, admin, kev2), 200, "same catalog again")
	if n := countDeliveries(t, s, `event = 'kev_listed'`); n != 2 {
		t.Errorf("%d deliveries after an unchanged catalog", n)
	}
	// a smaller EPSS file: scores it no longer has are cleared
	epss2 := []byte("cve,epss,percentile\nCVE-2021-44228,0.5,0.9\n")
	wantCode(t, postIntel(t, s, admin, epss2), 200, "smaller epss")
	if n := qint64(t, s, `select count(*) from vuln_intel where epss is not null`); n != 1 {
		t.Errorf("%d scores after the smaller file", n)
	}
	if st, err := s.intelState(ctx); err != nil || st.EPSS.Count != 1 || st.EPSS.Date != nil || st.KEV.Count != 3 {
		t.Errorf("state %+v %v", st, err)
	}
	// a refused file after good ones keeps them
	wantCode(t, postIntel(t, s, admin, []byte("cve,epss,percentile\nCVE-2021-44228,2,0.9\n")), 400, "score above one")
	if n := qint64(t, s, `select count(*) from vuln_intel where kev`); n != 3 {
		t.Errorf("%d KEV rows after a refused file", n)
	}
}

// One COPY of a real-size file: every row arrives, and a second load of the same rows rewrites none.
func TestIntelEPSSBulk(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	rows := make([]epssRow, 300_000)
	for i := range rows {
		rows[i] = epssRow{fmt.Sprintf("CVE-%d-%05d", 2000+i/20000, i%20000+1000), float64(i%100000) / 100000, float64(i%99991) / 100000}
	}
	if err := s.replaceEPSS(ctx, rows, nil); err != nil {
		t.Fatal(err)
	}
	if n := qint64(t, s, `select count(*) from vuln_intel where epss is not null`); n != int64(len(rows)) {
		t.Fatalf("%d rows", n)
	}
	before := qint64(t, s, `select sum(xmin::text::bigint) from vuln_intel`)
	if err := s.replaceEPSS(ctx, rows, nil); err != nil {
		t.Fatal(err)
	}
	if after := qint64(t, s, `select sum(xmin::text::bigint) from vuln_intel`); after != before {
		t.Error("unchanged rows were rewritten")
	}
}

func TestIntelFixesAndMCP(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	mustUpload(t, s, "web", "target=api&kind=image", fixDoc("api", map[string][]fv{
		"npm": {
			{"CVE-2022-0001", "aaa-critical", "1.0.0", "1.0.1", "CRITICAL"},
			{"CVE-2099-10001", "lodash", "4.17.20", "4.17.21", "MEDIUM"},
			{"CVE-2022-0002", "lodash", "4.17.20", "4.17.21", "LOW"},
			{"CVE-2099-10002", "left-pad", "1.0.0", "", "LOW"},
			{"CVE-2022-0003", "zz-nofix", "1.0.0", "", "CRITICAL"},
		}}), ck)
	wantCode(t, postIntel(t, s, admin, intelFixture(t, "kev.json")), 200, "kev")
	wantCode(t, postIntel(t, s, admin, intelFixture(t, "epss.csv")), 200, "epss")
	plan := decode[fixPlan](t, do(t, s, "GET", "/api/v1/projects/web/fixes", nil, ck))
	// the MEDIUM upgrade that fixes an exploited vulnerability comes before the CRITICAL one that does not
	if len(plan.Groups) != 2 || plan.Groups[0].Package != "lodash" || plan.Groups[0].KEV != 1 || plan.Groups[1].KEV != 0 ||
		!plan.Groups[0].Findings[0].KEV || plan.Groups[0].Findings[1].KEV {
		t.Errorf("groups %+v", plan.Groups)
	}
	if len(plan.NoFixGroups) != 2 || plan.NoFixGroups[0].Package != "left-pad" || plan.NoFixGroups[0].KEV != 1 {
		t.Errorf("no-fix groups %+v", plan.NoFixGroups)
	}

	_, tok := mkToken(t, s, "web", "read")
	type finding struct {
		RuleID string   `json:"rule_id"`
		KEV    bool     `json:"kev"`
		EPSS   *float64 `json:"epss"`
	}
	all := callTool[struct{ Findings []finding }](t, s, tok, "list_findings", nil)
	kev := callTool[struct {
		Total    int
		Findings []finding
	}](t, s, tok, "list_findings", map[string]any{"kev": true})
	if len(all.Findings) != 5 || kev.Total != 2 || !kev.Findings[0].KEV || kev.Findings[0].RuleID != "CVE-2099-10001" ||
		kev.Findings[0].EPSS == nil || *kev.Findings[0].EPSS != 0.50312 {
		t.Errorf("list_findings: all %+v kev %+v", all, kev)
	}
	fixes := callTool[struct {
		Upgrades []struct {
			Package string
			KEV     int
		}
	}](t, s, tok, "list_fixes", nil)
	if fixes.Upgrades[0].Package != "lodash" || fixes.Upgrades[0].KEV != 1 || fixes.Upgrades[1].KEV != 0 {
		t.Errorf("list_fixes %+v", fixes)
	}
	v := callTool[struct {
		KEV  *vulnKEV
		EPSS *float64
	}](t, s, tok, "get_vulnerability", map[string]any{"id": "CVE-2099-10001"})
	if v.KEV == nil || v.KEV.DateAdded != "2026-11-12" || v.EPSS == nil {
		t.Errorf("get_vulnerability %+v", v)
	}
}
