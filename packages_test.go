package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func init() {
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "GET", Path: "/api/v1/packages?q=matrix-pkg", List: "items"},
		matrixCase{Method: "GET", Path: "/api/v1/packages?q=matrix-pkg&project={key}", List: "items"})
	// B's base scan gets a package, so the cases above would list it if the search leaked
	matrixFixtures = append(matrixFixtures, func(t *testing.T, s *server, projB *project) map[string]string {
		sqlExec(t, s, `insert into packages(scan_id, name, version, ecosystem)
			select id, 'matrix-pkg', '1.0', 'npm' from scans where project_id = $1`, projB.ID)
		return nil
	})
}

type invVuln struct{ ID, Pkg, Version, Path, Sev string }

// invDoc is a Trivy image report with one lang-pkgs result of typ: pkgs are "name@version" or
// "name@version@file path", vulns the findings on them (at one of those paths, as Trivy reports them).
func invDoc(typ string, pkgs []string, vulns ...invVuln) []byte {
	docSeq++
	ps, vs := []map[string]any{}, []map[string]any{}
	for _, p := range pkgs {
		f := append(strings.Split(p, "@"), "")
		ps = append(ps, map[string]any{"Name": f[0], "Version": f[1], "FilePath": f[2]})
	}
	for _, v := range vulns {
		vs = append(vs, map[string]any{"VulnerabilityID": v.ID, "PkgName": v.Pkg, "InstalledVersion": v.Version, "PkgPath": v.Path, "Severity": v.Sev})
	}
	b, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": "x", "ArtifactType": "container_image",
		"Created": fmt.Sprint(docSeq), "Results": []map[string]any{{"Target": "app", "Class": "lang-pkgs", "Type": typ,
			"Packages": ps, "Vulnerabilities": vs}}})
	return b
}

type pkgList struct {
	Items []struct {
		ProjectKey     string   `json:"project_key"`
		TargetID       int64    `json:"target_id"`
		TargetKind     string   `json:"target_kind"`
		TargetName     string   `json:"target_name"`
		Ecosystem      string   `json:"ecosystem"`
		Name           string   `json:"name"`
		Version        string   `json:"version"`
		Paths          []string `json:"paths"`
		PathCount      int      `json:"path_count"`
		ScanID         int64    `json:"scan_id"`
		OpenFindings   int      `json:"open_findings"`
		WorstSeverity  string   `json:"worst_severity"`
		VersionUnknown bool     `json:"version_unknown"`
	} `json:"items"`
	Truncated  bool      `json:"truncated"`
	Ecosystems []string  `json:"ecosystems"`
	Totals     pkgTotals `json:"totals"`
}

// rows renders the items as "project/target name version" (a "?" marks version_unknown), in answer order.
func (l pkgList) rows() string {
	var out []string
	for _, r := range l.Items {
		u := ""
		if r.VersionUnknown {
			u = "?"
		}
		out = append(out, fmt.Sprintf("%s/%s %s %s%s", r.ProjectKey, r.TargetName, r.Name, r.Version, u))
	}
	return strings.Join(out, " | ")
}

const log4j = "org.apache.logging.log4j:log4j-"

// pkgSeed: project web (visible to the member) has shop-api (maven: core 2.14.1 at two paths with two open
// findings, api 2.14.1 without; an older scan had core 2.10.0), shop-web (npm: log4js 6.9.1 and one with a version
// semver cannot read) and a target without any package list. Project ops (not visible) has core 2.17.1.
func pkgSeed(t *testing.T, s *server) (member any, opsTok string, apiScan int64) {
	t.Helper()
	_, ck := memberSession(t, s)
	_, opsTok = mkToken(t, s, "ops", "upload", "read")
	api := "target=shop-api&kind=image&scanners=vuln&ref="
	mustUpload(t, s, "web", api+"v1", invDoc("jar", []string{log4j + "core@2.10.0@app/old.jar"}), ck)
	apiScan = mustUpload(t, s, "web", api+"v2", invDoc("jar",
		[]string{log4j + "core@2.14.1@app/lib/b.jar", log4j + "core@2.14.1@app/lib/a.jar", log4j + "api@2.14.1@app/lib/api.jar"},
		invVuln{"CVE-2021-44228", log4j + "core", "2.14.1", "app/lib/a.jar", "CRITICAL"},
		invVuln{"CVE-2021-45046", log4j + "core", "2.14.1", "app/lib/b.jar", "HIGH"}), ck).ScanID
	mustUpload(t, s, "web", "target=shop-web&kind=repo&scanners=vuln", invDoc("npm", []string{"log4js@6.9.1", "log4js-next@1.x"}), ck)
	mustUpload(t, s, "web", "target=infra&kind=repo&scanners=misconfig", trivyDoc("infra", nil, []string{"DS002"}), ck)
	mustUpload(t, s, "ops", "target=batch&kind=image&scanners=vuln", invDoc("jar", []string{log4j + "core@2.17.1"}), opsTok)
	return ck, opsTok, apiScan
}

func TestPackageSearch(t *testing.T) {
	s := testServer(t)
	ck, opsTok, apiScan := pkgSeed(t, s)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	search := func(q string, auth any) pkgList {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/packages?"+q, nil, auth)
		wantCode(t, rec, 200, q)
		return decode[pkgList](t, rec)
	}
	const (
		api   = "web/shop-api " + log4j + "api 2.14.1"
		core  = "web/shop-api " + log4j + "core 2.14.1"
		js    = "web/shop-web log4js 6.9.1"
		jsBad = "web/shop-web log4js-next 1.x"
		ops   = "ops/batch " + log4j + "core 2.17.1"
	)

	all := search("q=LOG4J", ck) // any case, any part of the name; the member's projects only, the latest inventory only
	if all.rows() != strings.Join([]string{api, core, js, jsBad}, " | ") || all.Truncated {
		t.Fatalf("q=LOG4J: %s", all.rows())
	}
	if all.Totals != (pkgTotals{Matched: 4, Projects: 1, Targets: 2, TargetsSearched: 2, TargetsWithoutInventory: 1}) ||
		!slices.Equal(all.Ecosystems, []string{"maven", "npm"}) {
		t.Errorf("totals %+v ecosystems %v", all.Totals, all.Ecosystems)
	}
	if r := all.Items[1]; r.TargetKind != "image" || r.Ecosystem != "maven" || r.ScanID != apiScan || r.PathCount != 2 ||
		!slices.Equal(r.Paths, []string{"app/lib/a.jar", "app/lib/b.jar"}) || r.OpenFindings != 2 || r.WorstSeverity != "CRITICAL" {
		t.Errorf("log4j-core row: %+v", r)
	}
	if r := all.Items[0]; r.OpenFindings != 0 || r.WorstSeverity != "" || r.PathCount != 1 { // no known vulnerability yet
		t.Errorf("log4j-api row: %+v", r)
	}
	if l := search("q=log4j", admin); l.rows() != strings.Join([]string{ops, api, core, js, jsBad}, " | ") ||
		l.Totals.Projects != 2 || l.Totals.Targets != 3 || l.Totals.TargetsSearched != 3 {
		t.Errorf("admin: %s %+v", l.rows(), l.Totals)
	}

	for q, want := range map[string]string{
		"q=log4j-core":                         core,
		"q=log4j&version=2.14.1":               api + " | " + core + " | " + jsBad + "?", // a bare version is "exactly this"
		"q=log4j&version=%3C2.17.1":            api + " | " + core + " | " + jsBad + "?",
		"q=log4j&version=%3E%3D2.15":           js + " | " + jsBad + "?",
		"q=log4j&version=%3E%3D2.0+%3C2.15":    api + " | " + core + " | " + jsBad + "?",
		"q=log4j&version=%3C3&ecosystem=maven": api + " | " + core,
		"q=log4j&ecosystem=npm":                js + " | " + jsBad,
		"q=log4j&project=web":                  strings.Join([]string{api, core, js, jsBad}, " | "),
		"q=log4j&project=ops":                  "", // not the member's project
		"q=log4j&project=nope":                 "",
		"q=log4j_":                             "", // escaped: a literal underscore
		"q=%25%25":                             "",
		"q=zz":                                 "",
	} {
		if l := search(q, ck); l.rows() != want || l.Items == nil {
			t.Errorf("%s: %q, want %q", q, l.rows(), want)
		}
	}
	// the row that could not be compared is counted apart, and the ecosystem choices do not shrink with the filter
	l := search("q=log4j&version=%3C2.17.1&ecosystem=npm", ck)
	if l.rows() != jsBad+"?" || l.Totals.Matched != 0 || l.Totals.VersionUnknown != 1 || l.Totals.Projects != 0 ||
		!slices.Equal(l.Ecosystems, []string{"maven", "npm"}) {
		t.Errorf("unknown only: %s %+v %v", l.rows(), l.Totals, l.Ecosystems)
	}
	// another project's targets are not even counted
	if l := search("q=log4j&project=ops", ck); l.Totals != (pkgTotals{}) {
		t.Errorf("project=ops as the member: %+v", l.Totals)
	}

	for _, q := range []string{"", "q=a", "q=+a+", "q=" + strings.Repeat("a", 201), "q=log4j&version=%3C", "q=log4j&version=%3E%3D%3C1",
		"q=log4j&version=1+||", "q=log4j&ecosystem=npm&version=%3C1.x"} {
		rec := do(t, s, "GET", "/api/v1/packages?"+q, nil, ck)
		wantCode(t, rec, 400, q)
		if strings.Contains(q, "version") && !strings.Contains(decode[struct{ Message string }](t, rec).Message, "<2.17.1") {
			t.Errorf("%s: the message shows no example: %s", q, rec.Body.String())
		}
		wantCode(t, do(t, s, "GET", "/api/v1/packages.csv?"+q, nil, ck), 400, "csv "+q)
	}
	wantCode(t, do(t, s, "GET", "/api/v1/packages?q=log4j", nil), 401, "no session")
	wantCode(t, do(t, s, "GET", "/api/v1/packages?q=log4j", nil, opsTok), 403, "an API token over REST")

	// more rows than the cap: the answer is cut and says so, the totals still count everything
	sqlExec(t, s, `insert into packages(scan_id, name, version, ecosystem) select $1, 'bulk-' || g, '1.0', 'npm' from generate_series(1, $2::int) g`,
		apiScan, pkgMaxRows+5)
	if l := search("q=bulk-", ck); len(l.Items) != pkgMaxRows || !l.Truncated || l.Totals.Matched != pkgMaxRows+5 || l.Totals.Targets != 1 {
		t.Errorf("cap: %d items truncated=%v %+v", len(l.Items), l.Truncated, l.Totals)
	}
}

func TestPackageCSV(t *testing.T) {
	s := testServer(t)
	ck, _, apiScan := pkgSeed(t, s)
	sqlExec(t, s, `insert into packages(scan_id, name, version, ecosystem) values($1, '=log4j()', '1.0', 'npm')`, apiScan)
	rec := do(t, s, "GET", "/api/v1/packages.csv?q=log4j&version=%3C2.17.1", nil, ck)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "packages.csv") || !strings.HasPrefix(rec.Body.String(), "\ufeff") {
		t.Fatalf("csv: %d %v", rec.Code, rec.Header())
	}
	lines := strings.Split(strings.TrimRight(strings.TrimPrefix(rec.Body.String(), "\ufeff"), "\r\n"), "\r\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], `"프로젝트","프로젝트 이름","대상 종류","대상","패키지","버전"`) {
		t.Fatalf("csv lines:\n%s", rec.Body.String())
	}
	core := `"web","web","image","shop-api","` + log4j + `core","2.14.1","maven","app/lib/a.jar` + "\n" + `app/lib/b.jar","2","2","CRITICAL","",`
	for _, want := range []string{`"'=log4j()"`, core, `"log4js-next","1.x","npm","app","1","0","","비교하지 못함"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("csv lacks %s:\n%s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "batch") {
		t.Errorf("csv has another project's rows:\n%s", rec.Body.String())
	}
}
