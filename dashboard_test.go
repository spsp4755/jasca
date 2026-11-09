package main

import (
	"context"
	"encoding/json"
	"testing"
)

func init() {
	matrixRoutes = append(matrixRoutes, matrixCase{Method: "GET", Path: "/api/v1/projects/{key}/report"})
}

func seedFinding(t *testing.T, s *server, pid int64, tgt, rule, sev, status, origin string, firstDaysAgo int) {
	t.Helper()
	var tid int64
	if err := s.db.QueryRow(context.Background(), `insert into targets(project_id, kind, name) values($1,'image',$2)
		on conflict (project_id, kind, name) do update set name=excluded.name returning id`, pid, tgt).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	sqlExec(t, s, `insert into findings(project_id,target_id,fingerprint,kind,tool,rule_id,severity,status,origin,first_seen_at)
		values($1,$2,$3,'vuln','trivy',$4,$5,$6,$7, now() - make_interval(days => $8))`, pid, tid, []byte(rule+tgt), rule, sev, status, origin, firstDaysAgo)
}

func TestDashboardScoped(t *testing.T) {
	s := testServer(t)
	a, b := mkProject(t, s, "proj-a"), mkProject(t, s, "proj-b")
	u := mkUser(t, s, "u", "")
	addMember(t, s, a, "user", itoa(u.ID), "viewer")
	seedFinding(t, s, a, "a/app", "CVE-1", "CRITICAL", "open", "scan", 5)
	seedFinding(t, s, a, "a/app", "CVE-2", "HIGH", "open", "recheck", 2)
	seedFinding(t, s, b, "b/app", "CVE-3", "CRITICAL", "open", "advisory", 1)
	sqlExec(t, s, `insert into exceptions(scope,project_id,vuln_id,resolution,reason,status,expires_at) values
		('project_vuln',$1,'CVE-1','accepted','x','approved', now()+interval '5 days'),
		('project_vuln',$2,'CVE-3','accepted','x','approved', now()+interval '5 days'),
		('global_vuln',null,'CVE-9','accepted','x','approved', now()+interval '5 days'),
		('project_vuln',$1,'CVE-2','accepted','x','approved', now()+interval '60 days')`, a, b)
	type dash struct {
		Totals         map[string]int
		Trend          []map[string]any
		OldestCritical []map[string]any `json:"oldest_critical"`
		Expiring       []map[string]any `json:"expiring_exceptions"`
		RecentScans    []any            `json:"recent_scans"`
		NewlyKnown     []map[string]any `json:"newly_known"`
	}
	get := func(u *user) dash {
		rec := do(t, s, "GET", "/api/v1/dashboard", nil, loginAs(t, s, u))
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		var d dash
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := get(u)
	if d.Totals["open"] != 2 || d.Totals["critical"] != 1 || len(d.OldestCritical) != 1 || len(d.Expiring) != 1 || len(d.NewlyKnown) != 1 {
		t.Errorf("scoped user: %+v", d)
	}
	if d.NewlyKnown[0]["rule_id"] != "CVE-2" || d.Expiring[0]["project_key"] != "proj-a" {
		t.Errorf("wrong items: %+v", d)
	}
	adm := get(mkUser(t, s, "adm", "admin"))
	if adm.Totals["open"] != 3 || len(adm.Expiring) != 3 || len(adm.NewlyKnown) != 2 {
		t.Errorf("admin: %+v", adm)
	}
	nobody := get(mkUser(t, s, "nobody", ""))
	if nobody.Totals["open"] != 0 || nobody.Trend == nil || len(nobody.Trend) != 30 || nobody.OldestCritical == nil || nobody.Expiring == nil ||
		nobody.RecentScans == nil || nobody.NewlyKnown == nil {
		t.Errorf("nobody: arrays must be [] and trend 30: %+v", nobody)
	}
}

func TestDashboardTrendSQL(t *testing.T) {
	s := testServer(t)
	a := mkProject(t, s, "proj-a")
	seedFinding(t, s, a, "a/app", "CVE-1", "CRITICAL", "open", "scan", 10)
	seedFinding(t, s, a, "a/app", "CVE-2", "HIGH", "fixed", "scan", 10)
	sqlExec(t, s, `update findings set fixed_at = now() - interval '4 days' where rule_id='CVE-2'`)
	rec := do(t, s, "GET", "/api/v1/dashboard", nil, loginAs(t, s, mkUser(t, s, "adm", "admin")))
	var d struct {
		Trend []struct {
			Date           string
			Critical, High int
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &d)
	if len(d.Trend) != 30 {
		t.Fatalf("points = %d", len(d.Trend))
	}
	if d.Trend[0].Critical != 0 || d.Trend[0].Date >= d.Trend[29].Date {
		t.Errorf("first point (29 days ago): %+v", d.Trend[0])
	}
	// 10 days ago the finding existed (index 29-10=19 is that day), 4 days ago HIGH was fixed (index 25)
	if p := d.Trend[20]; p.Critical != 1 || p.High != 1 {
		t.Errorf("day -9: %+v", p)
	}
	if p := d.Trend[29]; p.Critical != 1 || p.High != 0 {
		t.Errorf("today: %+v", p)
	}
}

func TestAuditVisibility(t *testing.T) {
	s := testServer(t)
	a, b := mkProject(t, s, "proj-a"), mkProject(t, s, "proj-b")
	owner, member, adm := mkUser(t, s, "owner", ""), mkUser(t, s, "member", ""), mkUser(t, s, "adm", "admin")
	addMember(t, s, a, "user", itoa(owner.ID), "owner")
	addMember(t, s, a, "user", itoa(member.ID), "member")
	for i := 0; i < 3; i++ {
		sqlExec(t, s, `insert into audit_log(action, project_id) values('x.a', $1)`, a)
	}
	sqlExec(t, s, `insert into audit_log(action, project_id) values('x.b', $1), ('x.none', null)`, b)
	count := func(u *user, q string) (int, int, string) {
		rec := do(t, s, "GET", "/api/v1/audit"+q, nil, loginAs(t, s, u))
		var p struct {
			Items      []map[string]any
			NextCursor *string `json:"next_cursor"`
		}
		json.Unmarshal(rec.Body.Bytes(), &p)
		nc := ""
		if p.NextCursor != nil {
			nc = *p.NextCursor
		}
		return rec.Code, len(p.Items), nc
	}
	if c, n, _ := count(adm, ""); c != 200 || n < 5 {
		t.Errorf("admin: %d %d", c, n)
	}
	if c, n, _ := count(owner, ""); c != 200 || n != 3 {
		t.Errorf("owner sees own project only: %d %d", c, n)
	}
	if c, _, _ := count(owner, "?project=proj-b"); c != 403 {
		t.Errorf("owner of A asking for B: %d", c)
	}
	if c, _, _ := count(member, ""); c != 403 {
		t.Errorf("non-owner: %d", c)
	}
	c, n, cur := count(owner, "?limit=2")
	if c != 200 || n != 2 || cur == "" {
		t.Fatalf("page 1: %d %d %q", c, n, cur)
	}
	if c, n, cur := count(owner, "?limit=2&cursor="+cur); c != 200 || n != 1 || cur != "" {
		t.Errorf("page 2: %d %d %q", c, n, cur)
	}
	if c, n, _ := count(adm, "?action=x.b"); c != 200 || n != 1 {
		t.Errorf("action filter: %d %d", c, n)
	}
}

func TestAdminCannotDemoteSelf(t *testing.T) {
	s := testServer(t)
	adm, other := mkUser(t, s, "adm", "admin"), mkUser(t, s, "other", "")
	ck := loginAs(t, s, adm)
	for _, body := range []map[string]any{{"system_role": ""}, {"system_role": "security"}, {"active": false}} {
		if rec := do(t, s, "PATCH", "/api/v1/admin/users/"+itoa(adm.ID), body, ck); rec.Code != 400 {
			t.Errorf("%v: %d", body, rec.Code)
		}
	}
	sqlExec(t, s, `update users set role_from_sso=true where id=$1`, other.ID)
	if rec := do(t, s, "PATCH", "/api/v1/admin/users/"+itoa(other.ID), map[string]any{"system_role": "security"}, ck); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var role string
	var fromSSO bool
	s.db.QueryRow(context.Background(), `select system_role, role_from_sso from users where id=$1`, other.ID).Scan(&role, &fromSSO)
	if role != "security" || fromSSO {
		t.Errorf("role=%q role_from_sso=%v", role, fromSSO)
	}
	if rec := do(t, s, "PATCH", "/api/v1/admin/users/"+itoa(other.ID), map[string]any{"system_role": "root"}, ck); rec.Code != 400 {
		t.Errorf("bad role: %d", rec.Code)
	}
	if rec := do(t, s, "PATCH", "/api/v1/admin/users/99999", map[string]any{"active": false}, ck); rec.Code != 404 {
		t.Errorf("unknown: %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/admin/users", nil, loginAs(t, s, other)); rec.Code != 403 {
		t.Errorf("non-admin: %d", rec.Code)
	}
}

func TestDeactivateKillsSessions(t *testing.T) {
	s := testServer(t)
	adm, v := mkUser(t, s, "adm", "admin"), mkUser(t, s, "victim", "")
	vck := loginAs(t, s, v)
	if rec := do(t, s, "GET", "/api/v1/me", nil, vck); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	ck := loginAs(t, s, adm)
	if rec := do(t, s, "PATCH", "/api/v1/admin/users/"+itoa(v.ID), map[string]any{"active": false}, ck); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := do(t, s, "GET", "/api/v1/me", nil, vck); rec.Code != 401 {
		t.Errorf("session survived: %d", rec.Code)
	}
	sqlExec(t, s, `update users set disabled_by_sync=true where id=$1`, v.ID)
	do(t, s, "PATCH", "/api/v1/admin/users/"+itoa(v.ID), map[string]any{"active": true}, ck)
	var dis bool
	s.db.QueryRow(context.Background(), `select disabled_by_sync from users where id=$1`, v.ID).Scan(&dis)
	if dis {
		t.Error("disabled_by_sync not cleared")
	}
	rec := do(t, s, "GET", "/api/v1/admin/users", nil, ck)
	var list []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 3 || list[0]["depts"] == nil || list[0]["groups"] == nil {
		t.Errorf("list: %s", rec.Body.String())
	}
}

func TestRetentionAndDefaultPolicy(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	rec := do(t, s, "GET", "/api/v1/admin/retention", nil, ck)
	if rec.Body.String() != "{\"raw_per_target\":20,\"raw_days\":90}\n" || rec.Code != 200 {
		t.Errorf("default: %s", rec.Body.String())
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/retention", map[string]int{"raw_per_target": 0, "raw_days": 5}, ck); rec.Code != 400 {
		t.Errorf("invalid: %d", rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/retention", map[string]int{"raw_per_target": 1, "raw_days": 8}, ck); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// an omitted field keeps its stored value
	if rec := do(t, s, "PUT", "/api/v1/admin/retention", map[string]int{"raw_days": 7}, ck); rec.Body.String() != "{\"raw_per_target\":1,\"raw_days\":7}\n" {
		t.Fatalf("partial put: %d %s", rec.Code, rec.Body.String())
	}
	p := mkProject(t, s, "proj-a")
	seedFinding(t, s, p, "a/app", "CVE-1", "LOW", "open", "scan", 0)
	var tid int64
	s.db.QueryRow(context.Background(), `select id from targets limit 1`).Scan(&tid)
	sqlExec(t, s, `insert into scans(project_id,target_id,source,format,status,raw,created_at) values
		($1,$2,'upload','trivy','done','\x01', now()-interval '30 days'),
		($1,$2,'upload','trivy','done','\x01', now()-interval '20 days'),
		($1,$2,'upload','trivy','done','\x01', now()-interval '1 day')`, p, tid)
	if err := s.trimAllRaw(context.Background()); err != nil {
		t.Fatal(err)
	}
	var kept int
	s.db.QueryRow(context.Background(), `select count(*) from scans where raw is not null`).Scan(&kept)
	if kept != 1 {
		t.Errorf("kept raw = %d, want 1", kept)
	}
	// default policy
	rec = do(t, s, "GET", "/api/v1/admin/default-policy", nil, ck)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/default-policy", map[string]any{"enabled": true, "min_severity": "NOPE", "max_count": 0}, ck); rec.Code != 400 {
		t.Errorf("bad sev: %d", rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/default-policy", map[string]any{"enabled": true, "min_severity": "HIGH", "max_count": 3, "new_only": true, "fixable_only": false}, ck); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	pol, _ := s.projectPolicy(context.Background(), p)
	if pol.MinSeverity != "HIGH" || pol.MaxCount != 3 || !pol.NewOnly {
		t.Errorf("projectPolicy did not pick the default: %+v", pol)
	}
	sec := loginAs(t, s, mkUser(t, s, "sec", "security"))
	if rec := do(t, s, "GET", "/api/v1/admin/default-policy", nil, sec); rec.Code != 200 {
		t.Errorf("security: %d", rec.Code)
	}
	if rec := do(t, s, "GET", "/api/v1/admin/retention", nil, sec); rec.Code != 403 {
		t.Errorf("retention for security: %d", rec.Code)
	}
}

func TestProjectReport(t *testing.T) {
	s := testServer(t)
	a := mkProject(t, s, "proj-a")
	v := mkUser(t, s, "v", "")
	addMember(t, s, a, "user", itoa(v.ID), "viewer")
	seedFinding(t, s, a, "a/app", "CVE-1", "CRITICAL", "open", "scan", 5)
	seedFinding(t, s, a, "a/app", "CVE-2", "LOW", "open", "scan", 5)
	seedFinding(t, s, a, "a/app", "CVE-3", "HIGH", "fixed", "scan", 5)
	sqlExec(t, s, `insert into ai_runs(kind, project_id, state, output) values('project_report', $1, 'done', 'hello')`, a)
	rec := do(t, s, "GET", "/api/v1/projects/proj-a/report", nil, loginAs(t, s, v))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var r struct {
		Summary struct {
			BySeverity map[string]int `json:"by_severity"`
			ByKind     map[string]int `json:"by_kind"`
		}
		Targets    []any
		Findings   []map[string]any
		Exceptions []any
		Policy     map[string]any
		AIReport   map[string]any `json:"ai_report"`
	}
	json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Summary.BySeverity["open"] != 2 || r.Summary.ByKind["vuln"] != 2 || len(r.Targets) != 1 || len(r.Findings) != 2 ||
		r.Findings[0]["rule_id"] != "CVE-1" || r.Exceptions == nil || r.Policy == nil || r.AIReport["output"] != "hello" {
		t.Errorf("report: %s", rec.Body.String())
	}
}
