package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func init() {
	matrixRoutes = append(matrixRoutes, matrixCase{Method: "GET", Path: "/api/v1/projects/{key}/fixes"})
}

// fv is one vulnerability of a language package in a fixDoc.
type fv struct{ ID, Pkg, Ver, Fixed, Sev string }

// fixDoc builds a Trivy image report with one lang-pkgs result per Trivy type (jar, npm, pip, ...) in types.
func fixDoc(name string, types map[string][]fv) []byte {
	docSeq++
	results := []map[string]any{}
	for _, typ := range slices.Sorted(maps.Keys(types)) {
		vs := []map[string]any{}
		for _, v := range types[typ] {
			vs = append(vs, map[string]any{"VulnerabilityID": v.ID, "PkgName": v.Pkg, "InstalledVersion": v.Ver,
				"FixedVersion": v.Fixed, "Severity": v.Sev, "Title": "title of " + v.ID})
		}
		results = append(results, map[string]any{"Target": "app/" + typ + ".lock", "Class": "lang-pkgs", "Type": typ, "Vulnerabilities": vs})
	}
	b, _ := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": name, "ArtifactType": "container_image",
		"Created": fmt.Sprint(docSeq), "Results": results})
	return b
}

func TestFixPlan(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	mustUpload(t, s, "web", "target=api&kind=image", fixDoc("api", map[string][]fv{
		"jar": {
			{"CVE-2021-0001", "log4j-core", "2.14.1", "2.15.0, 2.12.2", "CRITICAL"},
			{"CVE-2021-0002", "log4j-core", "2.14.1", "2.17.1, 2.12.4, 2.3.2", "HIGH"},
			{"CVE-2021-0003", "log4j-core", "2.14.1", "", "MEDIUM"},
		},
		"npm": {
			{"CVE-2022-0001", "lodash", "4.17.20", ">=4.17.21", "HIGH"},
			{"CVE-2022-0002", "odd", "1.0.0", "next release", "HIGH"},    // does not parse as a version
			{"CVE-2022-0003", "requests", "2.0.0", "2.0.1", "LOW"},       // the npm package of that name
			{"CVE-2022-0004", "stale", "3.0.0", "2.9.0", "LOW"},          // the only "fix" is below the installed version
			{"CVE-2022-0005", "left-pad", "1.0.0", "", "CRITICAL"},       // nothing to upgrade to
			{"CVE-2022-0006", "left-pad", "1.0.0", "", "LOW"},            // nothing to upgrade to
			{"CVE-2022-0007", "accepted", "1.0.0", "1.0.1", "CRITICAL"},  // under an exception below: not open
			{"CVE-2022-0008", "zz-nofix", "1.0.0", "", "CRITICAL"},       // ties with left-pad on severity, fewer findings
			{"CVE-2022-0009", "lodash", "4.17.20", "4.17.21", "UNKNOWN"}, // the same version listed twice
			{"CVE-2022-0010", "aa-high", "1.0.0", "1.0.1", "HIGH"},       // ties with lodash on severity, fewer resolved
			{"CVE-2022-0011", "lodash", "4.17.20", "4.17.21", "MEDIUM"},
		},
		"pip":   {{"CVE-2023-0001", "requests", "2.0.0", "2.31.0", "MEDIUM"}},   // the PyPI package of that name
		"conan": {{"CVE-2024-0001", "zlib", "1.2.11", "1.3.1, 1.2.13", "HIGH"}}, // no comparator for this ecosystem
	}), ck)
	// the same JAR in a second image, and a misconfiguration the plan does not cover
	worker := mustUpload(t, s, "web", "target=worker&kind=image", fixDoc("worker", map[string][]fv{
		"jar": {{"CVE-2021-0001", "log4j-core", "2.14.1", "2.15.0, 2.12.2", "CRITICAL"}}}), ck)
	mustUpload(t, s, "web", "target=conf&kind=fs", trivyDoc("conf", nil, []string{"DS002"}), ck)
	sqlExec(t, s, `update findings set status = 'accepted' where rule_id = 'CVE-2022-0007'`)
	// another project's findings never show up
	_, opsTok := mkToken(t, s, "ops", "upload")
	ops := mustUpload(t, s, "ops", "target=api&kind=image", fixDoc("api", map[string][]fv{
		"jar": {{"CVE-2099-0001", "log4j-core", "2.14.1", "2.99.0", "CRITICAL"}}}), opsTok)

	get := func(q string) fixPlan {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/projects/web/fixes"+q, nil, ck)
		wantCode(t, rec, 200, "fixes"+q)
		return decode[fixPlan](t, rec)
	}
	p := get("")
	if tt := p.Totals; tt.OpenVulns != 16 || tt.Fixable != 12 || tt.NoFix != 4 || tt.InventoryTargets != 2 || p.Truncated || p.Limit != fixMaxFindings ||
		tt.OtherKinds["misconfig"] != 1 || tt.OtherKinds["secret"] != 0 || tt.OtherKinds["sast"] != 0 {
		t.Errorf("totals %+v truncated=%v", tt, p.Truncated)
	}
	line := func(gs []*fixGroup) string {
		var out []string
		for _, g := range gs {
			out = append(out, fmt.Sprintf("%s/%s %s>%s %d+%d", g.Package, g.Ecosystem, g.Installed, g.Recommended, g.Resolves.Open, g.NoFix))
		}
		return strings.Join(out, " | ")
	}
	// worst severity resolved, then most resolved, then name
	if got, want := line(p.Groups), "log4j-core/maven 2.14.1>2.17.1 3+1 | lodash/npm 4.17.20>4.17.21 3+0 | aa-high/npm 1.0.0>1.0.1 1+0 | "+
		"odd/npm 1.0.0> 1+0 | zlib/conan 1.2.11> 1+0 | requests/pip 2.0.0>2.31.0 1+0 | requests/npm 2.0.0>2.0.1 1+0 | stale/npm 3.0.0> 1+0"; got != want {
		t.Errorf("groups\n got %s\nwant %s", got, want)
	}
	if g := p.Groups[1]; g.Resolves.High != 1 || g.Resolves.Medium != 1 || g.Resolves.Unknown != 1 {
		t.Errorf("lodash counts %+v", g.Resolves)
	}
	if got, want := line(p.NoFixGroups), "left-pad/npm 1.0.0> 0+2 | zz-nofix/npm 1.0.0> 0+1"; got != want {
		t.Errorf("no-fix groups\n got %s\nwant %s", got, want)
	}
	log := p.Groups[0]
	if c := log.Resolves; c.Critical != 2 || c.High != 1 || c.Medium != 0 || len(log.Findings) != 4 || log.Findings[0].Severity != "CRITICAL" ||
		log.Findings[3].RuleID != "CVE-2021-0003" || log.Findings[3].FixedVersion != "" || log.Findings[0].Title == "" {
		t.Errorf("log4j group %+v", log)
	}
	if got := strings.Join(log.FixedVersions, "|"); got != "2.15.0|2.12.2|2.17.1|2.12.4|2.3.2" {
		t.Errorf("log4j fixed versions %q", got)
	}
	if len(log.Targets) != 2 || log.Targets[0].Name != "api" || log.Targets[0].Kind != "image" || log.Targets[1].Name != "worker" ||
		!slices.Equal(log.Targets[0].Paths, []string{"app/jar.lock"}) {
		t.Errorf("log4j targets %+v", log.Targets)
	}
	// versions that cannot be compared are listed as written, never one of them picked
	for _, i := range []int{3, 4, 7} {
		if g := p.Groups[i]; g.Recommended != "" || len(g.FixedVersions) == 0 {
			t.Errorf("%s: recommended %q of %v", g.Package, g.Recommended, g.FixedVersions)
		}
	}
	if g := p.Groups[4]; !slices.Equal(g.FixedVersions, []string{"1.3.1", "1.2.13"}) {
		t.Errorf("zlib fixed versions %v", g.FixedVersions)
	}

	one := get(fmt.Sprintf("?target_id=%d", worker.TargetID))
	if one.Totals.OpenVulns != 1 || one.Totals.OtherKinds["misconfig"] != 0 || one.Totals.InventoryTargets != 1 ||
		len(one.Groups) != 1 || len(one.Groups[0].Targets) != 1 || one.Groups[0].Resolves.Critical != 1 || one.Groups[0].Recommended != "2.15.0" {
		t.Errorf("one target: %+v %s", one.Totals, line(one.Groups))
	}
	if other := get(fmt.Sprintf("?target_id=%d", ops.TargetID)); other.Totals.OpenVulns != 0 || len(other.Groups) != 0 || other.Groups == nil || other.NoFixGroups == nil {
		t.Errorf("another project's target: %+v", other)
	}
	for _, q := range []string{"?target_id=x", "?target_id=0", "?target_id=-1"} {
		wantCode(t, do(t, s, "GET", "/api/v1/projects/web/fixes"+q, nil, ck), 400, q)
	}

	// the cap keeps the most severe findings and says so
	defer func(n int) { fixMaxFindings = n }(fixMaxFindings)
	fixMaxFindings = 3
	if c := get(""); !c.Truncated || c.Limit != 3 || c.Totals.OpenVulns != 16 || len(c.Groups) != 1 || len(c.NoFixGroups) != 2 ||
		c.Groups[0].Resolves.Critical != 1 || c.NoFixGroups[0].NoFix+c.NoFixGroups[1].NoFix != 2 {
		t.Errorf("capped: truncated=%v limit=%d %s || %s", c.Truncated, c.Limit, line(c.Groups), line(c.NoFixGroups))
	}
}

func TestFixPlanAccess(t *testing.T) {
	s := testServer(t)
	pid, ck := memberSession(t, s)
	mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: "CVE-2024-1000", Fixed: "1.2.12-r0"}}, nil), ck)
	viewer := mkUser(t, s, "reader", "")
	addMember(t, s, pid, "user", itoa(viewer.ID), "viewer")
	rec := do(t, s, "GET", "/api/v1/projects/web/fixes", nil, loginAs(t, s, viewer))
	wantCode(t, rec, 200, "viewer")
	// an OS package: the distribution of the report is its ecosystem
	if p := decode[fixPlan](t, rec); len(p.Groups) != 1 || p.Groups[0].Ecosystem != "alpine" || p.Groups[0].Recommended != "1.2.12-r0" {
		t.Errorf("viewer plan %s", rec.Body.String())
	}
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/fixes", nil, loginAs(t, s, mkUser(t, s, "nobody", ""))), 404, "not a member")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/fixes", nil), 401, "signed out")
	// a project without scans: empty lists, not null
	mkProject(t, s, "empty")
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	if p := decode[fixPlan](t, do(t, s, "GET", "/api/v1/projects/empty/fixes", nil, admin)); p.Groups == nil || p.NoFixGroups == nil ||
		p.Totals.OpenVulns != 0 || p.Totals.InventoryTargets != 0 {
		t.Errorf("empty project %+v", p)
	}
}
