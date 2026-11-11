package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func init() {
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "PATCH", Path: "/api/v1/findings/{finding}", Body: map[string]any{"assignee_id": nil}},
		matrixCase{Method: "GET", Path: "/api/v1/projects/{key}/assignees"},
		matrixCase{Method: "GET", Path: "/api/v1/findings?project={key}&due=overdue&sort=due", List: "items"})
}

type dueFinding struct {
	ID        int64         `json:"id"`
	RuleID    string        `json:"rule_id"`
	Status    string        `json:"status"`
	Assignee  *assigneeView `json:"assignee"`
	DueAt     *time.Time    `json:"due_at"`
	DueManual bool          `json:"due_manual"`
	SLADays   *int          `json:"sla_days"`
}

type duePage struct {
	Items      []dueFinding `json:"items"`
	NextCursor *string      `json:"next_cursor"`
	Total      int          `json:"total"`
}

// dueState reads the deadline columns of the finding of rule: days = whole days from open_since to due_at (-1: no
// deadline), age = whole days since open_since (-1: none).
func dueState(t *testing.T, s *server, rule string) (status string, days, age int, manual bool) {
	t.Helper()
	err := s.db.QueryRow(context.Background(), `select status, coalesce(round(extract(epoch from due_at - open_since) / 86400), -1)::int,
		coalesce(round(extract(epoch from now() - open_since) / 86400), -1)::int, due_manual from findings where rule_id = $1`, rule).
		Scan(&status, &days, &age, &manual)
	if err != nil {
		t.Fatalf("%s: %v", rule, err)
	}
	return
}

func wantDue(t *testing.T, s *server, rule, status string, days, age int, manual bool) {
	t.Helper()
	if st, d, a, m := dueState(t, s, rule); st != status || d != days || a != age || m != manual {
		t.Errorf("%s: status=%s days=%d age=%d manual=%v, want %s %d %d %v", rule, st, d, a, m, status, days, age, manual)
	}
}

// age moves the open_since of the finding of rule back, as if it had been open that long, and applies the rule.
func age(t *testing.T, s *server, rule string, days int) {
	t.Helper()
	sqlExec(t, s, `update findings set open_since = now() - make_interval(days => $2) where rule_id = $1`, rule, days)
	if _, err := applyDue(context.Background(), s.db, "true"); err != nil {
		t.Fatal(err)
	}
}

func fid(t *testing.T, s *server, rule string) int64 {
	t.Helper()
	return qint64(t, s, `select id from findings where rule_id = $1`, rule)
}

func patchFinding(t *testing.T, s *server, rule string, body any, ck *http.Cookie, want int) dueFinding {
	t.Helper()
	rec := do(t, s, "PATCH", "/api/v1/findings/"+itoa(fid(t, s, rule)), body, ck)
	wantCode(t, rec, want, fmt.Sprintf("patch %s %v", rule, body))
	if rec.Code != 200 {
		return dueFinding{}
	}
	return decode[dueFinding](t, rec)
}

// A new finding gets open_since + the days of its severity; a fixed one has no deadline; a re-opened one starts
// over; a severity change moves the deadline but not the clock.
func TestDueOnIngest(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	up := func(vs ...tv) {
		t.Helper()
		mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", vs, nil), ck)
	}
	all := []tv{{ID: "CVE-1", Sev: "CRITICAL"}, {ID: "CVE-2", Sev: "HIGH"}, {ID: "CVE-3", Sev: "MEDIUM"}, {ID: "CVE-4", Sev: "LOW"}, {ID: "CVE-5", Sev: "UNKNOWN"}}
	up(all...)
	for rule, days := range map[string]int{"CVE-1": 7, "CVE-2": 30, "CVE-3": 90, "CVE-4": 180, "CVE-5": -1} {
		wantDue(t, s, rule, "open", days, 0, false)
	}
	age(t, s, "CVE-1", 10)
	age(t, s, "CVE-2", 10)
	// seen again, CVE-2 now CRITICAL, CVE-1 gone: the clock of CVE-2 keeps running, its deadline is 7 days from the start
	all[1].Sev = "CRITICAL"
	up(all[1:]...)
	wantDue(t, s, "CVE-2", "open", 7, 10, false)
	wantDue(t, s, "CVE-1", "fixed", -1, 10, false)
	wantDue(t, s, "CVE-3", "open", 90, 0, false)
	// back in a scan: open since now
	up(all...)
	wantDue(t, s, "CVE-1", "open", 7, 0, false)
	wantDue(t, s, "CVE-2", "open", 7, 10, false)
	// the detail says where the deadline comes from
	rec := do(t, s, "GET", "/api/v1/findings/"+itoa(fid(t, s, "CVE-3")), nil, ck)
	if f := decode[dueFinding](t, rec); f.SLADays == nil || *f.SLADays != 90 || f.DueAt == nil || f.DueManual || f.Assignee != nil {
		t.Errorf("detail: %s", rec.Body.String())
	}
	if f := decode[dueFinding](t, do(t, s, "GET", "/api/v1/findings/"+itoa(fid(t, s, "CVE-5")), nil, ck)); f.SLADays != nil || f.DueAt != nil {
		t.Errorf("UNKNOWN has no deadline: %+v", f)
	}
}

// An approved exception takes the deadline away; when it ends (revoked or expired) the finding is open since then.
func TestDueAndExceptions(t *testing.T) {
	e := newExEnv(t)
	_, mck, _ := e.project(t, "web", "CVE-2024-1", "CVE-2024-2", "CVE-2024-3")
	age(t, e.s, "CVE-2024-1", 40)
	age(t, e.s, "CVE-2024-2", 40)
	wantDue(t, e.s, "CVE-2024-1", "open", 30, 40, false)
	// a manual deadline belongs to the open period it was set in
	patchFinding(t, e.s, "CVE-2024-2", map[string]any{"due_at": time.Now().AddDate(0, 0, 5).Format(time.DateOnly)}, mck, 200)
	if _, _, _, manual := dueState(t, e.s, "CVE-2024-2"); !manual {
		t.Fatal("manual deadline not stored")
	}
	ex1 := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)[0]
	ex2 := e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{fid(t, e.s, "CVE-2024-2")}}, 201)[0]
	e.decide(t, e.secA, ex1.ID, "approve", 200)
	e.decide(t, e.secA, ex2.ID, "approve", 200)
	wantDue(t, e.s, "CVE-2024-1", "accepted", -1, 40, false)
	wantDue(t, e.s, "CVE-2024-2", "accepted", -1, 40, false)
	wantDue(t, e.s, "CVE-2024-3", "open", 30, 0, false) // untouched
	wantCode(t, do(t, e.s, "POST", "/api/v1/exceptions/"+itoa(ex2.ID)+"/revoke", nil, e.secA), 200, "revoke")
	wantDue(t, e.s, "CVE-2024-2", "open", 30, 0, false)
	sqlExec(t, e.s, `update exceptions set expires_at = now() - interval '1 minute' where id = $1`, ex1.ID)
	e.s.expireExceptions(context.Background())
	wantDue(t, e.s, "CVE-2024-1", "open", 30, 0, false)
	// an accepted finding cannot be given a deadline; anyone may still be assigned to it
	ex3 := e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{fid(t, e.s, "CVE-2024-3")}}, 201)[0]
	e.decide(t, e.secA, ex3.ID, "approve", 200)
	patchFinding(t, e.s, "CVE-2024-3", map[string]any{"due_at": "2027-01-01"}, mck, 409)
	patchFinding(t, e.s, "CVE-2024-3", map[string]any{"due_at": nil}, mck, 200)
}

func TestSLASetting(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	sec := loginAs(t, s, mkUser(t, s, "sec", "security"))
	mustUpload(t, s, "web", "target=app&kind=fs", trivyDoc("app", []tv{{ID: "CVE-1", Sev: "CRITICAL"}, {ID: "CVE-2", Sev: "HIGH"},
		{ID: "CVE-3", Sev: "MEDIUM"}, {ID: "CVE-4", Sev: "MEDIUM"}}, nil), ck)
	patchFinding(t, s, "CVE-4", map[string]any{"due_at": time.Now().AddDate(0, 0, 3).Format(time.DateOnly)}, ck, 200)
	manual := qint64(t, s, `select extract(epoch from due_at)::bigint from findings where rule_id = 'CVE-4'`)

	type sla struct {
		Enabled bool            `json:"enabled"`
		Days    map[string]*int `json:"days"`
		Changed int             `json:"changed"`
	}
	rec := do(t, s, "GET", "/api/v1/admin/sla", nil, admin)
	if st := decode[sla](t, rec); rec.Code != 200 || !st.Enabled || len(st.Days) != 4 || *st.Days["CRITICAL"] != 7 || *st.Days["HIGH"] != 30 ||
		*st.Days["MEDIUM"] != 90 || *st.Days["LOW"] != 180 {
		t.Errorf("default setting: %d %s", rec.Code, rec.Body.String())
	}
	for _, ck := range []*http.Cookie{ck, sec} {
		wantCode(t, do(t, s, "GET", "/api/v1/admin/sla", nil, ck), 403, "non-admin get")
		wantCode(t, do(t, s, "PUT", "/api/v1/admin/sla", map[string]any{"enabled": false}, ck), 403, "non-admin put")
	}
	for _, bad := range []string{`{"enabled":true,"days":{"HIGH":0}}`, `{"enabled":true,"days":{"HIGH":3651}}`, `{"enabled":true,"days":{"UNKNOWN":5}}`,
		`{"enabled":true,"days":{"high":5}}`, `{"enabled":true,"days":{"HIGH":"5"}}`, `{"enabled":true,"days":[]}`, `{"enabled":true,"extra":1}`,
		`{"enabled":true}`, `{"enabled":false,"days":null}`} {
		wantCode(t, do(t, s, "PUT", "/api/v1/admin/sla", bad, admin), 400, bad)
	}
	wantDue(t, s, "CVE-2", "open", 30, 0, false) // nothing above was saved
	// new days: every open finding without a manual deadline follows; a severity left out or null has none
	rec = do(t, s, "PUT", "/api/v1/admin/sla", `{"enabled":true,"days":{"CRITICAL":1,"HIGH":14,"MEDIUM":null}}`, admin)
	if st := decode[sla](t, rec); rec.Code != 200 || st.Changed != 3 || *st.Days["HIGH"] != 14 {
		t.Errorf("put: %d %s", rec.Code, rec.Body.String())
	}
	wantDue(t, s, "CVE-1", "open", 1, 0, false)
	wantDue(t, s, "CVE-2", "open", 14, 0, false)
	wantDue(t, s, "CVE-3", "open", -1, 0, false)
	if got := qint64(t, s, `select extract(epoch from due_at)::bigint from findings where rule_id = 'CVE-4'`); got != manual {
		t.Errorf("the manual deadline moved: %d -> %d", manual, got)
	}
	if n := qInt(t, s, `select count(*) from audit_log where action = 'sla.update' and (details->>'recalculated')::int = 3 and details->'days'->>'HIGH' = '14'
		and details->>'enabled' = 'true'`); n != 1 {
		t.Errorf("sla.update audit rows: %d", n)
	}
	// saving the same again changes nothing; a new finding follows the new days
	if st := decode[sla](t, do(t, s, "PUT", "/api/v1/admin/sla", `{"enabled":true,"days":{"CRITICAL":1,"HIGH":14}}`, admin)); st.Changed != 0 {
		t.Errorf("unchanged setting recalculated %d", st.Changed)
	}
	mustUpload(t, s, "web", "target=app2&kind=fs", trivyDoc("app2", []tv{{ID: "CVE-9", Sev: "HIGH"}}, nil), ck)
	wantDue(t, s, "CVE-9", "open", 14, 0, false)
	// off: the automatic deadlines go, the manual one stays
	if st := decode[sla](t, do(t, s, "PUT", "/api/v1/admin/sla", `{"enabled":false,"days":{"CRITICAL":1,"HIGH":14}}`, admin)); st.Changed != 3 {
		t.Errorf("switching off changed %d", st.Changed)
	}
	wantDue(t, s, "CVE-1", "open", -1, 0, false)
	if st, days, _, m := dueState(t, s, "CVE-4"); st != "open" || days < 0 || !m {
		t.Errorf("manual deadline after switching off: %s %d %v", st, days, m)
	}
	if f := decode[dueFinding](t, do(t, s, "GET", "/api/v1/findings/"+itoa(fid(t, s, "CVE-2")), nil, ck)); f.SLADays != nil || f.DueAt != nil {
		t.Errorf("detail while off: %+v", f)
	}
}

// An install that is upgraded shows deadlines at once, counted from the upgrade: nothing is overdue on day one.
func TestDueUpgrade(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, ck := memberSession(t, s)
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1", Sev: "CRITICAL"}, {ID: "CVE-2"}, {ID: "CVE-3", Sev: "UNKNOWN"}}, nil), ck)
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1", Sev: "CRITICAL"}, {ID: "CVE-3", Sev: "UNKNOWN"}}, nil), ck)
	// the database as v1.0.1 left it, with findings a year old
	sqlExec(t, s, `alter table findings drop column assignee_id, drop column open_since, drop column due_at, drop column due_manual,
		drop column due_warned, drop column overdue_notified`)
	sqlExec(t, s, `delete from schema_migrations where name = '006_due_assignee.sql'`)
	sqlExec(t, s, `delete from settings where key = 'sla'`)
	sqlExec(t, s, `update findings set first_seen_at = now() - interval '400 days'`)
	up, err := newServer(ctx, s.cfg, s.db)
	if err != nil {
		t.Fatal(err)
	}
	wantDue(t, up, "CVE-1", "open", 7, 0, false)
	wantDue(t, up, "CVE-2", "fixed", -1, -1, false)
	wantDue(t, up, "CVE-3", "open", -1, 0, false)
	if n := qInt(t, up, `select count(*) from findings where due_at < now()`); n != 0 {
		t.Errorf("%d findings overdue right after the upgrade", n)
	}
	l := decode[duePage](t, do(t, up, "GET", "/api/v1/findings?sort=due&status=open", nil, ck))
	if len(l.Items) != 2 || l.Items[0].RuleID != "CVE-1" || l.Items[0].DueAt == nil || l.Items[1].DueAt != nil {
		t.Errorf("list after upgrade: %+v", l)
	}
	// starting again changes nothing
	sqlExec(t, up, `update findings set due_warned = true where rule_id = 'CVE-1'`)
	if _, err := newServer(ctx, s.cfg, s.db); err != nil {
		t.Fatal(err)
	}
	if n := qInt(t, up, `select count(*) from findings where due_warned`); n != 1 {
		t.Error("a restart reset a deadline that did not change")
	}
}

func TestFindingPatch(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, ck := memberSession(t, s) // dev, member of web
	dev := qint64(t, s, `select id from users where username = 'dev'`)
	viewer, outsider, sec := mkUser(t, s, "view", ""), mkUser(t, s, "out", ""), mkUser(t, s, "sec", "security")
	addMember(t, s, pid, "user", itoa(viewer.ID), "viewer")
	grouped := mkUser(t, s, "grp", "")
	sqlExec(t, s, `insert into user_groups(user_id, path) values($1, '/platform/web')`, grouped.ID)
	addMember(t, s, pid, "group", "/platform", "viewer")
	gone := mkUser(t, s, "gone", "")
	addMember(t, s, pid, "user", itoa(gone.ID), "member")
	sqlExec(t, s, `update users set active = false where id = $1`, gone.ID)
	_, tok := mkToken(t, s, "web", "read", "upload")
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1"}, {ID: "CVE-2"}}, nil), ck)
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1"}}, nil), ck) // CVE-2 is fixed
	path := "/api/v1/findings/" + itoa(fid(t, s, "CVE-1"))

	// who may
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"assignee_id": dev}, loginAs(t, s, viewer)), 403, "viewer")
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"assignee_id": dev}, loginAs(t, s, outsider)), 404, "outsider")
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"assignee_id": dev}, tok), 403, "api token")
	wantCode(t, do(t, s, "PATCH", path, map[string]any{"assignee_id": dev}), 401, "anonymous")
	if n := qInt(t, s, `select count(*) from findings where assignee_id is not null`); n != 0 {
		t.Fatal("a refused request assigned the finding")
	}
	// what may be sent
	for _, bad := range []string{`{}`, `{"assignee_id":"1"}`, `{"assignee_id":0}`, `{"assignee_id":1.5}`, `{"due_at":"tomorrow"}`, `{"due_at":20270101}`,
		`{"due_at":"2027-13-01"}`, `{"due_at":"1999-01-01"}`, `{"due_at":"2099-01-01"}`, `{"status":"fixed"}`,
		fmt.Sprintf(`{"assignee_id":%d}`, outsider.ID), fmt.Sprintf(`{"assignee_id":%d}`, gone.ID), `{"assignee_id":999999}`} {
		wantCode(t, do(t, s, "PATCH", path, bad, ck), 400, bad)
	}
	// a member assigns themselves, someone who sees the project through a group, and a security user
	if f := patchFinding(t, s, "CVE-1", map[string]any{"assignee_id": dev}, ck, 200); f.Assignee == nil || f.Assignee.ID != dev ||
		f.Assignee.Username != "dev" || !f.Assignee.Active || f.DueManual {
		t.Errorf("self-assign: %+v", f)
	}
	for _, u := range []*user{grouped, viewer, sec} {
		if f := patchFinding(t, s, "CVE-1", map[string]any{"assignee_id": u.ID}, ck, 200); f.Assignee == nil || f.Assignee.ID != u.ID {
			t.Errorf("assign %s: %+v", u.Username, f)
		}
	}
	// a security user who is not a member may triage too
	if f := patchFinding(t, s, "CVE-1", map[string]any{"assignee_id": nil}, loginAs(t, s, sec), 200); f.Assignee != nil {
		t.Errorf("unassign by security: %+v", f)
	}
	// a date is the end of that day in the display zone; the past is allowed; null goes back to the rule
	day := time.Now().In(s.cfg.Loc).AddDate(0, 0, 3)
	f := patchFinding(t, s, "CVE-1", map[string]any{"due_at": day.Format(time.DateOnly), "assignee_id": dev}, ck, 200)
	if want := time.Date(day.Year(), day.Month(), day.Day(), 23, 59, 59, 0, s.cfg.Loc); f.DueAt == nil || !f.DueAt.Equal(want) || !f.DueManual || f.Assignee == nil {
		t.Errorf("manual deadline: %+v, want %s", f, want)
	}
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1", Sev: "CRITICAL"}}, nil), ck)
	if g := decode[dueFinding](t, do(t, s, "GET", path, nil, ck)); !g.DueManual || !g.DueAt.Equal(*f.DueAt) {
		t.Errorf("an ingest moved the manual deadline: %+v", g)
	}
	sqlExec(t, s, `update findings set due_warned = true, overdue_notified = true where rule_id = 'CVE-1'`)
	patchFinding(t, s, "CVE-1", map[string]any{"due_at": day.Format(time.DateOnly)}, ck, 200)
	if n := qInt(t, s, `select count(*) from findings where rule_id = 'CVE-1' and due_warned and overdue_notified`); n != 1 {
		t.Error("the same date again must not be announced again")
	}
	past := time.Now().In(s.cfg.Loc).AddDate(0, 0, -3).Format(time.DateOnly)
	if f := patchFinding(t, s, "CVE-1", map[string]any{"due_at": past}, ck, 200); f.DueAt == nil || !f.DueAt.Before(time.Now()) {
		t.Errorf("past deadline: %+v", f)
	}
	if n := qInt(t, s, `select count(*) from findings where rule_id = 'CVE-1' and (due_warned or overdue_notified)`); n != 0 {
		t.Error("a changed deadline must be announced again")
	}
	if f := patchFinding(t, s, "CVE-1", map[string]any{"due_at": nil}, ck, 200); f.DueManual || f.DueAt == nil || f.Assignee == nil {
		t.Errorf("back to the rule: %+v", f)
	}
	wantDue(t, s, "CVE-1", "open", 7, 0, false)
	// a fixed finding has no deadline to set, but can be assigned
	patchFinding(t, s, "CVE-2", map[string]any{"due_at": past}, ck, 409)
	patchFinding(t, s, "CVE-2", map[string]any{"assignee_id": dev}, ck, 200)

	for action, want := range map[string]int{"finding.assign": 7, "finding.due": 4} {
		if n := qInt(t, s, `select count(*) from audit_log where action = $1 and project_id = $2 and details ? 'finding_id'`, action, pid); n != want {
			t.Errorf("%s audit rows: %d, want %d", action, n, want)
		}
	}
	var target string
	var details map[string]any
	s.db.QueryRow(ctx, `select target, details from audit_log where action = 'finding.assign' order by id limit 1`).Scan(&target, &details)
	if target != "CVE-1 · zlib" || details["assignee"] != "dev" {
		t.Errorf("audit row: %q %v", target, details)
	}

	// the list and the CSV carry both
	l := decode[duePage](t, do(t, s, "GET", "/api/v1/findings?status=open,fixed", nil, ck))
	if len(l.Items) != 2 || l.Items[0].Assignee == nil || l.Items[0].DueAt == nil || l.Items[1].DueAt != nil {
		t.Errorf("list: %+v", l)
	}
	csv := do(t, s, "GET", "/api/v1/findings.csv?status=open", nil, ck).Body.String()
	if lines := strings.Split(strings.TrimSpace(csv), "\r\n"); len(lines) != 2 || !strings.HasSuffix(lines[0], `"담당자","조치 기한"`) ||
		!strings.Contains(lines[1], `,"dev","20`) {
		t.Errorf("csv:\n%s", csv)
	}

	// a deactivated assignee stays, marked; a deleted one leaves the finding unassigned
	sqlExec(t, s, `update users set active = false where id = $1`, dev)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	if g := decode[dueFinding](t, do(t, s, "GET", path, nil, admin)); g.Assignee == nil || g.Assignee.Active {
		t.Errorf("deactivated assignee: %+v", g.Assignee)
	}
	if csv := do(t, s, "GET", "/api/v1/findings.csv", nil, admin).Body.String(); !strings.Contains(csv, `"dev (비활성)"`) {
		t.Errorf("csv with a deactivated assignee:\n%s", csv)
	}
	sqlExec(t, s, `delete from users where id = $1`, dev)
	if g := decode[dueFinding](t, do(t, s, "GET", path, nil, admin)); g.Assignee != nil || g.Status != "open" {
		t.Errorf("after the assignee was deleted: %+v", g)
	}
}

func TestFindingAssignBulk(t *testing.T) {
	s := testServer(t)
	me := mkUser(t, s, "me", "")
	a, b, c := mkProject(t, s, "proj-a"), mkProject(t, s, "proj-b"), mkProject(t, s, "proj-c")
	addMember(t, s, a, "user", itoa(me.ID), "owner")
	addMember(t, s, b, "user", itoa(me.ID), "member")
	addMember(t, s, c, "user", itoa(me.ID), "viewer")
	onlyA := mkUser(t, s, "only-a", "")
	addMember(t, s, a, "user", itoa(onlyA.ID), "viewer")
	hidden := mkProject(t, s, "hidden")
	for i, pid := range []int64{a, a, b, c, hidden} {
		seedFinding(t, s, pid, "t", fmt.Sprintf("CVE-%d", i+1), "HIGH", "open", "scan", 0)
	}
	ids := func(rules ...string) []int64 {
		var out []int64
		for _, r := range rules {
			out = append(out, fid(t, s, r))
		}
		return out
	}
	ck := loginAs(t, s, me)
	assign := func(ids []int64, to any, want int) {
		t.Helper()
		wantCode(t, do(t, s, "POST", "/api/v1/findings/assign", map[string]any{"ids": ids, "assignee_id": to}, ck), want, fmt.Sprint(ids, to))
	}
	assigned := func() int { return qInt(t, s, `select count(*) from findings where assignee_id is not null`) }
	assign(ids("CVE-1", "CVE-2", "CVE-3", "CVE-5"), me.ID, 404) // one of a project the caller cannot see
	assign(append(ids("CVE-1"), 999999), me.ID, 404)            // one that does not exist
	assign(ids("CVE-1", "CVE-4"), me.ID, 403)                   // one of a project the caller only views
	assign(ids("CVE-1", "CVE-3"), onlyA.ID, 400)                // the assignee cannot see proj-b
	assign(ids("CVE-1"), 999999, 400)
	assign(nil, me.ID, 400)
	assign(make([]int64, 0), me.ID, 400)
	wantCode(t, do(t, s, "POST", "/api/v1/findings/assign", map[string]any{"ids": ids("CVE-1")}, ck), 400, "assignee_id left out")
	many := make([]int64, 501)
	for i := range many {
		many[i] = int64(i + 1)
	}
	assign(many, me.ID, 400)
	if assigned() != 0 {
		t.Fatal("a refused bulk assignment changed findings")
	}
	// the cross-project case the matrix cannot express: an owner of A sends B's finding
	wantCode(t, do(t, s, "POST", "/api/v1/findings/assign", map[string]any{"ids": ids("CVE-5"), "assignee_id": onlyA.ID}, loginAs(t, s, onlyA)), 404, "foreign finding")
	wantCode(t, do(t, s, "POST", "/api/v1/findings/assign", map[string]any{"ids": ids("CVE-1"), "assignee_id": onlyA.ID}, loginAs(t, s, onlyA)), 403, "viewer")

	rec := do(t, s, "POST", "/api/v1/findings/assign", map[string]any{"ids": append(ids("CVE-1", "CVE-2", "CVE-3"), ids("CVE-1")...), "assignee_id": me.ID}, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"updated":3`) || assigned() != 3 {
		t.Fatalf("bulk assign: %d %s", rec.Code, rec.Body.String())
	}
	if n := qInt(t, s, `select count(*) from audit_log where action = 'finding.assign' and details->>'assignee' = 'me'
		and (project_id = $1 and (details->>'count')::int = 2 or project_id = $2 and (details->>'count')::int = 1)`, a, b); n != 2 {
		t.Errorf("one audit row per project, got %d", n)
	}
	assign(ids("CVE-1", "CVE-3"), onlyA.ID, 400)
	assign(ids("CVE-1"), onlyA.ID, 200)
	assign(ids("CVE-2", "CVE-3"), nil, 200)
	if assigned() != 1 {
		t.Errorf("after unassigning two: %d assigned", assigned())
	}
}

func TestAssigneePicker(t *testing.T) {
	s := testServer(t)
	pid, ck := memberSession(t, s)
	sqlExec(t, s, `update users set name = '김개발' where username = 'dev'`)
	grouped, outsider, off := mkUser(t, s, "grp", ""), mkUser(t, s, "out", ""), mkUser(t, s, "off", "")
	sqlExec(t, s, `insert into user_depts(user_id, path) values($1, '/개발본부/플랫폼팀')`, grouped.ID)
	addMember(t, s, pid, "group", "/개발본부", "viewer")
	addMember(t, s, pid, "user", itoa(off.ID), "owner")
	sqlExec(t, s, `update users set active = false where id = $1`, off.ID)
	mkUser(t, s, "sec", "security")
	names := func(q string) string {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/projects/web/assignees?q="+q, nil, ck)
		wantCode(t, rec, 200, q)
		var out []string
		for _, a := range decode[[]assigneeView](t, rec) {
			out = append(out, a.Username)
		}
		return strings.Join(out, " ")
	}
	if got := names(""); got != "admin dev grp sec" { // the bootstrap admin and security see every project
		t.Errorf("assignees: %q", got)
	}
	for q, want := range map[string]string{"gr": "grp", "%EA%B9%80": "dev", "example.internal": "dev grp sec", "out": "", "off": "", "%25": ""} {
		if got := names(q); got != want {
			t.Errorf("q=%s: %q, want %q", q, got, want)
		}
	}
	rec := do(t, s, "GET", "/api/v1/projects/web/assignees", nil, ck)
	if l := decode[[]assigneeView](t, rec); l[1].Name != "김개발" || !l[1].Active || strings.Contains(rec.Body.String(), "email") {
		t.Errorf("row: %s", rec.Body.String())
	}
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/assignees?q="+strings.Repeat("a", 101), nil, ck), 400, "long q")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/assignees", nil, loginAs(t, s, outsider)), 404, "outsider")
}

func TestFindingDueFiltersAndSort(t *testing.T) {
	s := testServer(t)
	pid, ck := memberSession(t, s)
	dev := qint64(t, s, `select id from users where username = 'dev'`)
	other := mkUser(t, s, "other", "")
	addMember(t, s, pid, "user", itoa(other.ID), "member")
	hidden := mkProject(t, s, "hidden")
	// days until the deadline: negative = overdue, nil = none. C and D share theirs to the microsecond.
	base := time.Now().Truncate(time.Minute)
	for _, f := range []struct {
		rule string
		left any
	}{{"CVE-A", -5}, {"CVE-B", -1}, {"CVE-C", 2}, {"CVE-D", 2}, {"CVE-E", 6}, {"CVE-F", 20}, {"CVE-G", nil}, {"CVE-H", nil}} {
		seedFinding(t, s, pid, "t", f.rule, "HIGH", "open", "scan", 0)
		sqlExec(t, s, `update findings set due_manual = true, due_at = $3::timestamptz + make_interval(days => $2) where rule_id = $1`, f.rule, f.left, base)
	}
	seedFinding(t, s, pid, "t", "CVE-FIXED", "HIGH", "fixed", "scan", 0)
	seedFinding(t, s, hidden, "t", "CVE-HIDDEN", "CRITICAL", "open", "scan", 0)
	sqlExec(t, s, `update findings set due_at = now() - interval '9 days', assignee_id = $1 where rule_id = 'CVE-HIDDEN'`, dev)
	sqlExec(t, s, `update findings set assignee_id = $1 where rule_id in ('CVE-A', 'CVE-C', 'CVE-FIXED')`, dev)
	sqlExec(t, s, `update findings set assignee_id = $1 where rule_id = 'CVE-B'`, other.ID)
	list := func(q string) duePage {
		t.Helper()
		rec := do(t, s, "GET", "/api/v1/findings?"+q, nil, ck)
		wantCode(t, rec, 200, q)
		return decode[duePage](t, rec)
	}
	rules := func(p duePage) string {
		var out []string
		for _, f := range p.Items {
			out = append(out, strings.TrimPrefix(f.RuleID, "CVE-"))
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}
	for q, want := range map[string]string{
		"assignee=me&status=open": "A C", "assignee=me": "A C FIXED", "assignee=none&status=open": "D E F G H",
		"assignee=" + itoa(other.ID): "B", "due=overdue": "A B", "due=soon": "C D E", "due=overdue&assignee=me": "A",
		"due=soon&status=fixed": "", "assignee=999999": "",
	} {
		if p := list(q); rules(p) != want || p.Total != len(p.Items) {
			t.Errorf("%s: %q (total %d), want %q", q, rules(p), p.Total, want)
		}
	}
	for _, q := range []string{"assignee=you", "due=late", "sort=age", "sort=due&cursor=x", "sort=due&cursor=1.2", "sort=due&cursor=-.x", "sort=due&cursor=2026-13-45T00:00:00Z.3"} {
		wantCode(t, do(t, s, "GET", "/api/v1/findings?"+q, nil, ck), 400, q)
	}
	_, tok := mkToken(t, s, "web", "read")
	wantCode(t, do(t, s, "GET", "/api/v1/projects/web/scans", nil, tok), 200, "token works")
	// the earliest deadline first, no deadline last, and the cursor walks all of it at every page size
	want := "A B D C E F FIXED H G" // ties and the ones without a deadline: newest id first
	for _, limit := range []int{1, 2, 3, 4, 100} {
		var walked []string
		cur := ""
		for pages := 0; ; pages++ {
			p := list(fmt.Sprintf("sort=due&status=&limit=%d%s", limit, cur))
			for _, f := range p.Items {
				walked = append(walked, strings.TrimPrefix(f.RuleID, "CVE-"))
			}
			if p.Total != 9 || pages > 12 {
				t.Fatalf("limit %d: total %d after %d pages", limit, p.Total, pages)
			}
			if p.NextCursor == nil {
				break
			}
			cur = "&cursor=" + strings.ReplaceAll(*p.NextCursor, "+", "%2B")
		}
		if got := strings.Join(walked, " "); got != want {
			t.Errorf("sort=due limit %d: %q, want %q", limit, got, want)
		}
	}
	// the default order is untouched, and the CSV follows sort too
	if p := list("status=open&limit=3"); p.Items[0].RuleID != "CVE-H" {
		t.Errorf("default order starts with %s", p.Items[0].RuleID)
	}
	csv := strings.Split(do(t, s, "GET", "/api/v1/findings.csv?sort=due&due=overdue", nil, ck).Body.String(), "\r\n")
	if len(csv) != 4 || !strings.Contains(csv[1], "CVE-A") || !strings.Contains(csv[2], "CVE-B") {
		t.Errorf("csv sorted by deadline: %q", csv)
	}
	wantCode(t, do(t, s, "GET", "/api/v1/findings.csv?sort=x", nil, ck), 400, "csv sort")
}

// The numbers people see: dashboard, project, report and MCP count the same overdue findings, visible ones only.
func TestOverdueCounts(t *testing.T) {
	s := testServer(t)
	pid, tok := mkToken(t, s, "web", "read", "upload")
	dev := mkUser(t, s, "dev", "")
	addMember(t, s, pid, "user", itoa(dev.ID), "member")
	ck := loginAs(t, s, dev)
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", []tv{{ID: "CVE-1", Sev: "CRITICAL"}, {ID: "CVE-2"}, {ID: "CVE-3"},
		{ID: "CVE-4", Sev: "LOW"}}, nil), tok)
	hidden := mkProject(t, s, "hidden")
	seedFinding(t, s, hidden, "t", "CVE-HIDDEN", "CRITICAL", "open", "scan", 0)
	sqlExec(t, s, `update findings set assignee_id = $1 where rule_id = 'CVE-HIDDEN'`, dev.ID)
	age(t, s, "CVE-HIDDEN", 9)
	age(t, s, "CVE-1", 8)  // overdue by a day
	age(t, s, "CVE-2", 31) // overdue
	age(t, s, "CVE-3", 29) // due tomorrow
	patchFinding(t, s, "CVE-1", map[string]any{"assignee_id": dev.ID}, ck, 200)
	patchFinding(t, s, "CVE-3", map[string]any{"assignee_id": dev.ID}, ck, 200)

	type dash struct {
		Overdue sevCounts `json:"overdue"`
		Mine    struct{ Open, Overdue int }
	}
	d := decode[dash](t, do(t, s, "GET", "/api/v1/dashboard", nil, ck))
	if d.Overdue != (sevCounts{Critical: 1, High: 1, Open: 2}) || d.Mine.Open != 2 || d.Mine.Overdue != 1 {
		t.Errorf("member dashboard: %+v", d)
	}
	if d := decode[dash](t, do(t, s, "GET", "/api/v1/dashboard", nil, loginAs(t, s, mkUser(t, s, "root", "admin")))); d.Overdue.Open != 3 || d.Mine.Open != 0 {
		t.Errorf("admin dashboard: %+v", d)
	}
	type proj struct {
		Key     string `json:"key"`
		Overdue int    `json:"overdue"`
	}
	if p := decode[proj](t, do(t, s, "GET", "/api/v1/projects/web", nil, ck)); p.Overdue != 2 {
		t.Errorf("project overdue: %+v", p)
	}
	if l := decode[[]proj](t, do(t, s, "GET", "/api/v1/projects", nil, ck)); len(l) != 1 || l[0].Overdue != 2 {
		t.Errorf("project list: %+v", l)
	}
	rep := do(t, s, "GET", "/api/v1/projects/web/report", nil, ck)
	if !strings.Contains(rep.Body.String(), `"overdue":{"critical":1,"high":1,"medium":0,"low":0,"unknown":0,"open":2}`) {
		t.Errorf("report: %s", rep.Body.String())
	}
	// MCP: the same two, each with its deadline and assignee
	type row struct {
		RuleID   string     `json:"rule_id"`
		Assignee string     `json:"assignee"`
		DueAt    *time.Time `json:"due_at"`
		Overdue  bool       `json:"overdue"`
	}
	type page struct {
		Total    int
		Findings []row
	}
	p := callTool[page](t, s, tok, "list_findings", map[string]any{"overdue": true})
	if p.Total != 2 || p.Findings[0].RuleID != "CVE-1" || p.Findings[0].Assignee != "dev" || !p.Findings[0].Overdue || p.Findings[0].DueAt == nil ||
		p.Findings[1].Assignee != "" {
		t.Errorf("mcp overdue: %+v", p)
	}
	if p := callTool[page](t, s, tok, "list_findings", map[string]any{"overdue": false}); p.Total != 4 {
		t.Errorf("mcp overdue=false: %+v", p)
	}
	one := callTool[row](t, s, tok, "get_finding", map[string]any{"id": fid(t, s, "CVE-3")})
	if one.Assignee != "dev" || one.Overdue || one.DueAt == nil {
		t.Errorf("mcp get_finding: %+v", one)
	}
	if four := callTool[map[string]any](t, s, tok, "get_finding", map[string]any{"id": fid(t, s, "CVE-4")}); four["assignee"] != nil || four["overdue"] != nil || four["due_at"] == nil {
		t.Errorf("mcp finding without an assignee: %v", four)
	}
}

// Findings an advisory or a recheck creates get deadlines like scanned ones.
func TestDueAdvisoryAndRecheck(t *testing.T) {
	e := newExEnv(t)
	ctx := context.Background()
	_, mck, _ := e.project(t, "web")
	mustUpload(t, e.s, "web", "target=app&kind=fs", pkgDoc("app", "npm", [2]string{"left-pad", "1.3.0"}), mck)
	wantCode(t, do(t, e.s, "POST", "/api/v1/advisories", advBody("INT-2026-001", "npm", "left-pad", "<1.3.1"), e.secA), 201, "advisory")
	wantDue(t, e.s, "INT-2026-001", "open", 30, 0, false)
	age(t, e.s, "INT-2026-001", 12)
	off := advBody("INT-2026-001", "npm", "left-pad", "<1.3.1")
	off["active"] = false
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", off, e.secA), 200, "advisory off")
	wantDue(t, e.s, "INT-2026-001", "fixed", -1, 12, false)
	off["active"], off["severity"] = true, "CRITICAL"
	wantCode(t, do(t, e.s, "PUT", "/api/v1/advisories/INT-2026-001", off, e.secA), 200, "advisory on")
	wantDue(t, e.s, "INT-2026-001", "open", 7, 0, false)

	pid := mkProject(t, e.s, "re")
	tid := seedInventory(t, e.s, pid, "fs", "t1", "trivy/fs-mixed.json", false)
	useFakeTrivy(t, e.s, sbomStyle(t, readFixture(t, "trivy/fs-mixed.json")))
	if _, err := e.s.startRecheck(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	if ran, err := e.s.runNextJob(ctx); !ran || err != nil {
		t.Fatal(ran, err)
	}
	if n := qInt(t, e.s, `select count(*) from findings where target_id = $1 and origin = 'recheck'`, tid); n == 0 {
		t.Fatal("the recheck added nothing")
	}
	if n := qInt(t, e.s, `select count(*) from findings where target_id = $1 and status = 'open' and severity <> 'UNKNOWN'
		and (due_at is null or open_since is null)`, tid); n != 0 {
		t.Errorf("%d recheck findings without a deadline", n)
	}
}

func TestDueNotices(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, ck := memberSession(t, s)
	ops := mkProject(t, s, "ops")
	quiet := mkProject(t, s, "quiet") // subscribed to nothing
	sqlExec(t, s, `update users set name = '김개발' where username = 'dev'`)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	ch := mkChannel(t, s, "mattermost", "mm", `{"webhook_url":"http://mm.example.internal/h"}`, true)
	for _, key := range []string{"web", "ops"} {
		wantCode(t, do(t, s, "PUT", "/api/v1/projects/"+key+"/notify", []map[string]any{{"channel_id": ch, "events": []string{"due_soon", "overdue"}}}, admin), 204, "subscribe")
	}
	vs := []tv{{ID: "CVE-C1", Sev: "CRITICAL", Pkg: "openssl"}, {ID: "CVE-H1"}, {ID: "CVE-H2"}, {ID: "CVE-M1", Sev: "MEDIUM"}}
	for i := range 6 {
		vs = append(vs, tv{ID: fmt.Sprintf("CVE-L%d", i), Sev: "LOW"})
	}
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", vs, nil), ck)
	seedFinding(t, s, ops, "t", "CVE-OPS", "HIGH", "open", "scan", 0)
	seedFinding(t, s, quiet, "t", "CVE-QUIET", "HIGH", "open", "scan", 0)
	seedFinding(t, s, ops, "t", "CVE-OPS-FIXED", "HIGH", "fixed", "scan", 0)
	sqlExec(t, s, `update findings set due_at = now() - interval '1 day' where rule_id = 'CVE-OPS-FIXED'`) // not open: never announced
	s.notifyDue(ctx)
	if n := countDeliveries(t, s, "true"); n != 0 {
		t.Fatalf("%d notices although every deadline is far away", n)
	}
	age(t, s, "CVE-C1", 8)   // overdue
	age(t, s, "CVE-H1", 28)  // 2 days left
	age(t, s, "CVE-H2", 20)  // 10 days left
	age(t, s, "CVE-M1", 100) // overdue
	sqlExec(t, s, `update findings set open_since = now() - interval '181 days' where rule_id like 'CVE-L%'`)
	age(t, s, "CVE-OPS", 31)
	age(t, s, "CVE-QUIET", 31)
	patchFinding(t, s, "CVE-C1", map[string]any{"assignee_id": qint64(t, s, `select id from users where username = 'dev'`)}, ck, 200)

	s.notifyDue(ctx)
	type top struct {
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Pkg      string `json:"pkg"`
		Target   string `json:"target"`
		DueAt    string `json:"due_at"`
		Assignee string `json:"assignee"`
	}
	type data struct {
		Count, Critical, High, Medium, Low int
		Top                                []top
	}
	sent := func() map[string]data {
		t.Helper()
		rows, _ := s.db.Query(ctx, `select event, payload from deliveries order by id`)
		out := map[string]data{}
		var ev string
		var raw []byte
		for rows.Next() {
			if err := rows.Scan(&ev, &raw); err != nil {
				t.Fatal(err)
			}
			var p struct {
				Key  string `json:"project_key"`
				Data data   `json:"data"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			if _, dup := out[p.Key+" "+ev]; dup {
				t.Errorf("two %s messages for %s in one run", ev, p.Key)
			}
			out[p.Key+" "+ev] = p.Data
		}
		sqlExec(t, s, `delete from deliveries`)
		return out
	}
	got := sent()
	if len(got) != 3 {
		t.Fatalf("messages: %+v", got)
	}
	if d := got["web overdue"]; d.Count != 8 || d.Critical != 1 || d.Medium != 1 || d.Low != 6 || d.High != 0 || len(d.Top) != 5 ||
		d.Top[0] != (top{"CRITICAL", "CVE-C1", "openssl", "app", d.Top[0].DueAt, "김개발"}) || d.Top[1].RuleID != "CVE-M1" || d.Top[4].Severity != "LOW" || d.Top[1].Assignee != "" {
		t.Errorf("web overdue: %+v", d)
	}
	if d := got["web due_soon"]; d.Count != 1 || d.High != 1 || len(d.Top) != 1 || d.Top[0].RuleID != "CVE-H1" {
		t.Errorf("web due_soon: %+v", d)
	}
	if d := got["ops overdue"]; d.Count != 1 || d.Top[0].RuleID != "CVE-OPS" {
		t.Errorf("ops overdue: %+v", d)
	}
	// each deadline once
	s.notifyDue(ctx)
	if got := sent(); len(got) != 0 {
		t.Errorf("announced twice: %+v", got)
	}
	// the warned one passes its deadline: overdue now; a new deadline is announced again; a fixed one never
	sqlExec(t, s, `update findings set open_since = open_since - interval '3 days', due_at = due_at - interval '3 days' where rule_id = 'CVE-H1'`)
	patchFinding(t, s, "CVE-M1", map[string]any{"due_at": time.Now().In(s.cfg.Loc).AddDate(0, 0, 1).Format(time.DateOnly)}, ck, 200)
	mustUpload(t, s, "web", "target=app&kind=fs&scanners=vuln", trivyDoc("app", vs[1:], nil), ck) // CVE-C1 is fixed
	s.notifyDue(ctx)
	got = sent()
	if d := got["web overdue"]; len(got) != 2 || d.Count != 1 || d.Top[0].RuleID != "CVE-H1" || got["web due_soon"].Top[0].RuleID != "CVE-M1" {
		t.Errorf("after the changes: %+v", got)
	}
	// the message a person reads, through the real queue
	sqlExec(t, s, `update findings set overdue_notified = false where rule_id = 'CVE-OPS'`)
	s.notifyDue(ctx)
	var raw []byte
	if err := s.db.QueryRow(ctx, `select payload from deliveries where event = 'overdue'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if text := s.renderMsg(ctx, "overdue", raw).text(); !strings.HasPrefix(text, "[ops] 조치 기한 지남 1건\n") || !strings.Contains(text, "- HIGH CVE-OPS · 대상 t · 기한 20") ||
		!strings.HasSuffix(text, "· 담당 미지정") {
		t.Errorf("message:\n%s", text)
	}
}
