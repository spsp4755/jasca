package main

import (
	"fmt"
	"strings"
	"testing"
)

type findingList struct {
	Items []struct {
		ID         int64  `json:"id"`
		ProjectKey string `json:"project_key"`
		RuleID     string `json:"rule_id"`
		PkgName    string `json:"pkg_name"`
	} `json:"items"`
	NextCursor *int64 `json:"next_cursor"`
	Total      int    `json:"total"`
}

func TestFindingsList(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	_, opsTok := mkToken(t, s, "ops", "upload")
	mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: "CVE-2024-1000", Fixed: "2.0"}, {ID: "CVE-2024-2000", Pkg: "open_ssl", Sev: "LOW"}}, nil), ck)
	mustUpload(t, s, "ops", "", trivyDoc("B", []tv{{ID: "CVE-2024-1000"}}, nil), opsTok)
	list := func(q string) findingList {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/findings?"+q, nil, ck)
		wantCode(t, rec, 200, q)
		return decode[findingList](t, rec)
	}
	if l := list(""); l.Total != 2 || len(l.Items) != 2 || l.Items[0].ProjectKey != "web" || l.Items[1].ProjectKey != "web" {
		t.Errorf("visible findings %+v", l)
	}
	for q, want := range map[string]int{
		"severity=HIGH": 1, "severity=HIGH,LOW": 2, "fixable=true": 1, "fixable=false": 1, "status=fixed": 0,
		"kind=vuln&origin=scan": 2, "project=web": 2, "project=ops": 0, "q=open_ssl": 1, "q=cve-2024-1": 1,
		"q=_":   1, // escaped: a literal underscore, not "any character"
		"q=%25": 0,
	} {
		if l := list(q); l.Total != want || len(l.Items) != want {
			t.Errorf("%s: total %d items %d, want %d", q, l.Total, len(l.Items), want)
		}
	}
	p1 := list("limit=1")
	if len(p1.Items) != 1 || p1.NextCursor == nil || p1.Total != 2 {
		t.Fatalf("page 1 %+v", p1)
	}
	p2 := list(fmt.Sprintf("limit=1&cursor=%d", *p1.NextCursor))
	if len(p2.Items) != 1 || p2.Items[0].ID >= p1.Items[0].ID {
		t.Errorf("page 2 %+v after %+v", p2, p1)
	}
	if p3 := list(fmt.Sprintf("limit=1&cursor=%d", p2.Items[0].ID)); len(p3.Items) != 0 || p3.NextCursor != nil {
		t.Errorf("page 3 %+v", p3)
	}
	if l := list("limit=500"); len(l.Items) != 2 {
		t.Errorf("limit over max %+v", l)
	}
	for _, q := range []string{"target_id=x", "cursor=x", "limit=x", "fixable=maybe", "q=" + strings.Repeat("a", 201)} {
		wantCode(t, do(t, s, "GET", "/api/v1/findings?"+q, nil, ck), 400, q)
	}
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	if l := decode[findingList](t, do(t, s, "GET", "/api/v1/findings", nil, admin)); l.Total != 3 {
		t.Errorf("admin sees %d", l.Total)
	}

	mine := list("").Items[0].ID
	rec := do(t, s, "GET", fmt.Sprintf("/api/v1/findings/%d", mine), nil, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"details":{`) {
		t.Errorf("finding get: %d %s", rec.Code, rec.Body.String())
	}
	opsID := qint64(t, s, `select f.id from findings f join projects p on p.id=f.project_id where p.key='ops'`)
	wantCode(t, do(t, s, "GET", fmt.Sprintf("/api/v1/findings/%d", opsID), nil, ck), 404, "other project's finding")
}

func TestFindingsCSVInjection(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: "CVE-2024-1000", Pkg: "=cmd()", Title: `say "hi"`}, {ID: "CVE-2024-2000", Pkg: "+x"}}, nil), ck)
	_, opsTok := mkToken(t, s, "ops", "upload")
	mustUpload(t, s, "ops", "", trivyDoc("B", []tv{{ID: "CVE-2024-3000"}}, nil), opsTok)
	rec := do(t, s, "GET", "/api/v1/findings.csv?severity=HIGH", nil, ck)
	body := strings.TrimPrefix(rec.Body.String(), "\ufeff")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", rec.Code, rec.Header())
	}
	for _, want := range []string{`"'=cmd()"`, `"'+x"`, `"say ""hi"""`} {
		if !strings.Contains(body, want) {
			t.Errorf("csv lacks %s:\n%s", want, body)
		}
	}
	lines := strings.Split(strings.TrimRight(body, "\r\n"), "\r\n")
	if len(lines) != 3 || strings.Contains(body, "CVE-2024-3000") {
		t.Errorf("csv rows (header + 2 visible):\n%s", body)
	}
	for _, l := range lines {
		for _, cell := range strings.Split(l, `","`) { // no cell here contains the separator
			if !strings.HasPrefix(l, `"`) || !strings.HasSuffix(l, `"`) || strings.HasPrefix(cell, "=") {
				t.Errorf("unquoted or unsafe cell %q in %q", cell, l)
			}
		}
	}
}

func TestVulnAffectedOnlyVisible(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	_, opsTok := mkToken(t, s, "ops", "upload")
	const x = "CVE-2024-1000"
	mustUpload(t, s, "web", "", trivyDoc("A", []tv{{ID: x, Title: "shared title", Fixed: "1.1"}}, nil), ck)
	mustUpload(t, s, "ops", "", trivyDoc("B", []tv{{ID: x}}, nil), opsTok)
	type vuln struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Refs     []string
		Affected []struct {
			ProjectKey   string `json:"project_key"`
			Target       string `json:"target"`
			FindingID    int64  `json:"finding_id"`
			Severity     string `json:"severity"`
			FixedVersion string `json:"fixed_version"`
		} `json:"affected"`
	}
	v := decode[vuln](t, do(t, s, "GET", "/api/v1/vulns/"+x, nil, ck))
	if v.ID != x || v.Title != "shared title" || len(v.Affected) != 1 || v.Affected[0].ProjectKey != "web" ||
		v.Affected[0].Target != "A" || v.Affected[0].FixedVersion != "1.1" || v.Affected[0].Severity != "HIGH" || v.Refs == nil {
		t.Errorf("member view %+v", v)
	}
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	if v := decode[vuln](t, do(t, s, "GET", "/api/v1/vulns/"+x, nil, admin)); len(v.Affected) != 2 {
		t.Errorf("admin view %+v", v)
	}
	outsider := loginAs(t, s, mkUser(t, s, "nobody", ""))
	rec := do(t, s, "GET", "/api/v1/vulns/"+x, nil, outsider)
	if v := decode[vuln](t, rec); rec.Code != 200 || v.Title != "shared title" || v.Affected == nil || len(v.Affected) != 0 {
		t.Errorf("outsider view %d %s", rec.Code, rec.Body.String())
	}
	wantCode(t, do(t, s, "GET", "/api/v1/vulns/CVE-1999-0000", nil, ck), 404, "unknown vuln")
}
