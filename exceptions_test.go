package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type exView struct {
	ID          int64      `json:"id"`
	Scope       string     `json:"scope"`
	ProjectID   *int64     `json:"project_id"`
	ProjectKey  string     `json:"project_key"`
	FindingID   *int64     `json:"finding_id"`
	VulnID      *string    `json:"vuln_id"`
	Resolution  string     `json:"resolution"`
	Status      string     `json:"status"`
	RequestedBy *int64     `json:"requested_by"`
	DecidedBy   *int64     `json:"decided_by"`
	DecidedAt   *time.Time `json:"decided_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	// name of the requester, for the approver's list
	RequestedByName string `json:"requested_by_name"`
}

func init() {
	body := map[string]any{"scope": "project_vuln", "project_key": "{key}", "vuln_id": "CVE-2024-0001",
		"resolution": "accepted", "reason": "matrix reason", "expires_at": "{exp}"}
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "GET", Path: "/api/v1/exceptions?project={key}", List: "[]"},
		matrixCase{Method: "POST", Path: "/api/v1/exceptions", Body: body},
		matrixCase{Method: "POST", Path: "/api/v1/exceptions/{exception}/revoke"})
	matrixFixtures = append(matrixFixtures, func(t *testing.T, s *server, projB *project) map[string]string {
		return map[string]string{"{exp}": futureISO(30 * 24 * time.Hour)}
	})
	matrixExempt["GET /api/v1/advisories/{id}"] = "internal advisories are one shared catalog"
}

func futureISO(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

type exEnv struct {
	s          *server
	secA, secB *http.Cookie // two security users
	secBID     int64
	secAID     int64
}

func newExEnv(t *testing.T) *exEnv {
	s := testServer(t)
	a, b := mkUser(t, s, "seca", "security"), mkUser(t, s, "secb", "security")
	return &exEnv{s: s, secA: loginAs(t, s, a), secB: loginAs(t, s, b), secAID: a.ID, secBID: b.ID}
}

// project makes a project with a member user, uploads a scan with the given CVEs and returns (project id, member cookie, target id).
func (e *exEnv) project(t *testing.T, key string, cves ...string) (int64, *http.Cookie, int64) {
	t.Helper()
	u := mkUser(t, e.s, "m-"+key, "")
	pid := mkProject(t, e.s, key)
	addMember(t, e.s, pid, "user", itoa(u.ID), "member")
	ck := loginAs(t, e.s, u)
	e.upload(t, key, ck, cves...)
	return pid, ck, qint64(t, e.s, `select id from targets where project_id=$1`, pid)
}

func (e *exEnv) upload(t *testing.T, key string, ck *http.Cookie, cves ...string) uploadResp {
	vs := []tv{}
	for _, c := range cves {
		vs = append(vs, tv{ID: c})
	}
	return mustUpload(t, e.s, key, "target=app&kind=fs", trivyDoc("app", vs, nil), ck)
}

func (e *exEnv) request(t *testing.T, ck *http.Cookie, body map[string]any, want int) []exView {
	t.Helper()
	if body["expires_at"] == nil {
		body["expires_at"] = futureISO(30 * 24 * time.Hour)
	}
	if body["reason"] == nil {
		body["reason"] = "정당한 사유"
	}
	if body["resolution"] == nil {
		body["resolution"] = "accepted"
	}
	rec := do(t, e.s, "POST", "/api/v1/exceptions", body, ck)
	wantCode(t, rec, want, "request")
	if rec.Code != 201 {
		return nil
	}
	return decode[[]exView](t, rec)
}

func (e *exEnv) decide(t *testing.T, ck *http.Cookie, id int64, verb string, want int) {
	t.Helper()
	wantCode(t, do(t, e.s, "POST", "/api/v1/exceptions/"+itoa(id)+"/"+verb, map[string]string{"note": "ok"}, ck), want, verb)
}

func fstatus(t *testing.T, s *server, pid int64, cve string) string {
	t.Helper()
	var st string
	if err := s.db.QueryRow(context.Background(), `select status from findings where project_id=$1 and rule_id=$2`, pid, cve).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestExceptionSelfApproveForbidden(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1")
	// a security user asks for a global exception and may not approve it; the other one may
	ex := e.request(t, e.secA, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-1"}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 403)
	e.decide(t, e.secA, ex.ID, "reject", 403)
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "open" {
		t.Fatalf("status = %s", st)
	}
	// a plain member cannot decide at all
	e.decide(t, mck, ex.ID, "approve", 403)
	e.decide(t, e.secB, ex.ID, "approve", 200)
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "accepted" {
		t.Fatalf("status = %s", st)
	}
	e.decide(t, e.secB, ex.ID, "approve", 409) // already decided
	if n := auditCount(t, e.s, "exception.approve"); n != 1 {
		t.Errorf("approve audits = %d", n)
	}
	// admin who requested may not approve either
	adm := loginAs(t, e.s, mkUser(t, e.s, "adm", "admin"))
	ex2 := e.request(t, adm, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-2"}, 201)[0]
	e.decide(t, adm, ex2.ID, "approve", 403)
}

func TestExceptionScopeProjectOnly(t *testing.T) {
	e := newExEnv(t)
	a, ack, _ := e.project(t, "proj-a", "CVE-2024-1", "CVE-2024-2")
	b, _, _ := e.project(t, "proj-b", "CVE-2024-1")
	ex := e.request(t, ack, map[string]any{"scope": "project_vuln", "project_key": "proj-a", "vuln_id": "CVE-2024-1", "resolution": "false_positive"}, 201)[0]
	if ex.Status != "pending" || ex.ProjectKey != "proj-a" {
		t.Fatalf("%+v", ex)
	}
	e.decide(t, e.secA, ex.ID, "approve", 200)
	if st := fstatus(t, e.s, a, "CVE-2024-1"); st != "false_positive" {
		t.Errorf("A = %s", st)
	}
	if st := fstatus(t, e.s, b, "CVE-2024-1"); st != "open" {
		t.Errorf("B = %s", st)
	}
	if st := fstatus(t, e.s, a, "CVE-2024-2"); st != "open" {
		t.Errorf("A other CVE = %s", st)
	}
	if n := qInt(t, e.s, `select count(*) from findings where exception_id=$1`, ex.ID); n != 1 {
		t.Errorf("linked findings = %d", n)
	}
	// one finding scope touches only that finding
	fid := qint64(t, e.s, `select id from findings where project_id=$1 and rule_id='CVE-2024-2'`, a)
	ex2 := e.request(t, ack, map[string]any{"scope": "finding", "finding_ids": []int64{fid}}, 201)[0]
	e.decide(t, e.secA, ex2.ID, "approve", 200)
	if st := fstatus(t, e.s, a, "CVE-2024-2"); st != "accepted" {
		t.Errorf("finding scope = %s", st)
	}
}

func TestGlobalVulnNeedsSecurity(t *testing.T) {
	e := newExEnv(t)
	e.project(t, "web", "CVE-2024-1")
	_, mck, _ := e.project(t, "web2")
	e.request(t, mck, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-1"}, 403)
	e.request(t, e.secA, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-1"}, 201)
	// global exceptions are listed to everybody who is logged in
	rec := do(t, e.s, "GET", "/api/v1/exceptions", nil, mck)
	if l := decode[[]exView](t, rec); len(l) != 1 || l[0].ProjectID != nil || l[0].RequestedByName == "" {
		t.Errorf("list = %+v", l)
	}
}

func TestExceptionCreateValidationAndRoles(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1")
	viewer := mkUser(t, e.s, "viewer", "")
	addMember(t, e.s, pid, "user", itoa(viewer.ID), "viewer")
	vck := loginAs(t, e.s, viewer)
	out := loginAs(t, e.s, mkUser(t, e.s, "outsider", ""))
	pv := map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}
	cp := func(m map[string]any, k string, v any) map[string]any {
		n := map[string]any{}
		for kk, vv := range m {
			n[kk] = vv
		}
		n[k] = v
		return n
	}
	e.request(t, vck, pv, 403)
	e.request(t, out, pv, 404)
	e.request(t, mck, cp(pv, "project_key", "nope"), 404)
	e.request(t, mck, cp(pv, "expires_at", futureISO(-time.Hour)), 400)
	e.request(t, mck, cp(pv, "expires_at", futureISO(366*24*time.Hour)), 400)
	e.request(t, mck, cp(pv, "expires_at", "soon"), 400)
	e.request(t, mck, cp(pv, "reason", "  "), 400)
	e.request(t, mck, cp(pv, "resolution", "fixed"), 400)
	e.request(t, mck, cp(pv, "scope", "weird"), 400)
	e.request(t, mck, cp(pv, "vuln_id", ""), 400)
	e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{}}, 400)
	e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{999999}}, 404)
	e.request(t, mck, cp(pv, "expires_at", futureISO(364*24*time.Hour)), 201)
	if n := qInt(t, e.s, `select count(*) from exceptions`); n != 1 {
		t.Errorf("rows = %d", n)
	}
	if n := auditCount(t, e.s, "exception.request"); n != 1 {
		t.Errorf("request audits = %d", n)
	}
}

func TestExceptionRevoke(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1")
	other := mkUser(t, e.s, "other", "")
	addMember(t, e.s, pid, "user", itoa(other.ID), "member")
	ock := loginAs(t, e.s, other)
	ex := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)[0]
	revoke := func(ck *http.Cookie, want int) {
		t.Helper()
		wantCode(t, do(t, e.s, "POST", "/api/v1/exceptions/"+itoa(ex.ID)+"/revoke", nil, ck), want, "revoke")
	}
	revoke(ock, 403) // member but not the requester
	revoke(mck, 200) // the requester while pending
	revoke(mck, 409)
	ex = e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 200)
	revoke(mck, 403) // approved: security only
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "accepted" {
		t.Fatal(st)
	}
	revoke(e.secB, 200)
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "open" {
		t.Errorf("after revoke = %s", st)
	}
	if n := qInt(t, e.s, `select count(*) from findings where exception_id is not null`); n != 0 {
		t.Errorf("exception_id left on %d findings", n)
	}
}

func TestExceptionExpiryReopens(t *testing.T) {
	e := newExEnv(t)
	pid, mck, tid := e.project(t, "web", "CVE-2024-1", "CVE-2024-2")
	var mu sync.Mutex
	var events []string
	saved := notifyEmit
	notifyEmit = func(s *server, ctx context.Context, projectID int64, ev string, p map[string]any) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}
	t.Cleanup(func() { notifyEmit = saved })
	ex := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)[0]
	ex2 := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-2"}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 200)
	e.decide(t, e.secA, ex2.ID, "approve", 200)
	// a fixed finding must stay fixed
	sqlExec(t, e.s, `update exceptions set expires_at = now() + interval '3 days' where id=$1`, ex.ID)
	e.s.expireExceptions(context.Background())
	e.s.expireExceptions(context.Background()) // the warning fires once
	if n := qInt(t, e.s, `select count(*) from exceptions where expiry_warned`); n != 1 {
		t.Fatalf("warned = %d", n)
	}
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "accepted" {
		t.Fatal(st)
	}
	sqlExec(t, e.s, `update exceptions set expires_at = now() - interval '1 minute' where id in ($1, $2)`, ex.ID, ex2.ID)
	sqlExec(t, e.s, `update findings set status='fixed', fixed_at=now() where project_id=$1 and rule_id='CVE-2024-2'`, pid)
	e.s.expireExceptions(context.Background())
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "open" {
		t.Errorf("expired -> %s", st)
	}
	if st := fstatus(t, e.s, pid, "CVE-2024-2"); st != "fixed" {
		t.Errorf("fixed finding -> %s", st)
	}
	if n := qInt(t, e.s, `select count(*) from exceptions where status='expired'`); n != 2 {
		t.Errorf("expired = %d", n)
	}
	_ = tid
	mu.Lock()
	defer mu.Unlock()
	want := map[string]int{"exception_requested": 2, "exception_approved": 2, "exception_expiring": 1, "exception_expired": 2}
	got := map[string]int{}
	for _, ev := range events {
		got[ev]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("event %s x%d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

func TestNewFindingInheritsActiveException(t *testing.T) {
	e := newExEnv(t)
	pid, mck, tid := e.project(t, "web", "CVE-2024-1")
	ex := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-9"}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 200)
	g := e.request(t, e.secA, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-8"}, 201)[0]
	e.decide(t, e.secB, g.ID, "approve", 200)
	e.upload(t, "web", mck, "CVE-2024-1", "CVE-2024-9", "CVE-2024-8")
	if st := fstatus(t, e.s, pid, "CVE-2024-9"); st != "accepted" {
		t.Errorf("project exception, new finding = %s", st)
	}
	if st := fstatus(t, e.s, pid, "CVE-2024-8"); st != "accepted" {
		t.Errorf("global exception, new finding = %s", st)
	}
	if st := fstatus(t, e.s, pid, "CVE-2024-1"); st != "open" {
		t.Errorf("unrelated = %s", st)
	}
	if n := qInt(t, e.s, `select count(*) from findings where target_id=$1 and exception_id is not null`, tid); n != 2 {
		t.Errorf("linked = %d", n)
	}
	// an expired exception no longer applies to new findings
	sqlExec(t, e.s, `update exceptions set expires_at = now() - interval '1 second' where id=$1`, ex.ID)
	e.s.expireExceptions(context.Background())
	e.upload(t, "web", mck, "CVE-2024-1", "CVE-2024-9", "CVE-2024-8", "CVE-2024-7")
	if st := fstatus(t, e.s, pid, "CVE-2024-9"); st != "open" {
		t.Errorf("after expiry = %s", st)
	}
}

func TestExceptionCrossProject(t *testing.T) {
	e := newExEnv(t)
	_, ack, _ := e.project(t, "proj-a", "CVE-2024-1")
	b, _, _ := e.project(t, "proj-b", "CVE-2024-1")
	bf := qint64(t, e.s, `select id from findings where project_id=$1`, b)
	e.request(t, ack, map[string]any{"scope": "finding", "finding_ids": []int64{bf}}, 404)
	if n := qInt(t, e.s, `select count(*) from exceptions`); n != 0 {
		t.Errorf("rows = %d", n)
	}
	// A's list never shows B's exceptions
	e.request(t, e.secA, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-1"}, 201)
	sqlExec(t, e.s, `insert into exceptions(scope, project_id, vuln_id, resolution, reason, expires_at)
		values('project_vuln', $1, 'CVE-2024-1', 'accepted', 'b', now() + interval '1 day')`, b)
	l := decode[[]exView](t, do(t, e.s, "GET", "/api/v1/exceptions", nil, ack))
	if len(l) != 1 || l[0].ProjectID != nil {
		t.Errorf("A sees %+v", l)
	}
	if l := decode[[]exView](t, do(t, e.s, "GET", "/api/v1/exceptions", nil, e.secA)); len(l) != 2 {
		t.Errorf("security sees %d", len(l))
	}
}

// a global exception has no project: its events go to each project that has the vulnerability
func TestGlobalExceptionEventsPerProject(t *testing.T) {
	e := newExEnv(t)
	a, _, _ := e.project(t, "proj-a", "CVE-2024-5")
	b, _, _ := e.project(t, "proj-b", "CVE-2024-5", "CVE-2024-6")
	e.project(t, "proj-c", "CVE-2024-6")
	emits := captureEmits(t)
	g := e.request(t, e.secA, map[string]any{"scope": "global_vuln", "vuln_id": "CVE-2024-5"}, 201)[0]
	e.decide(t, e.secB, g.ID, "approve", 200)
	var got []string
	for _, m := range *emits {
		f := strings.Fields(m)
		got = append(got, f[0]+" "+f[1])
	}
	want := []string{itoa(a) + " exception_requested", itoa(b) + " exception_requested", itoa(a) + " exception_approved", itoa(b) + " exception_approved"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("emits %v, want %v", got, want)
	}
}

// The approval inbox can say what a finding exception covers; duplicate requests are not stored twice.
func TestExceptionListNamesFindingAndNoDuplicates(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1")
	fid := qint64(t, e.s, `select id from findings where project_id=$1 and rule_id='CVE-2024-1'`, pid)
	got := e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{fid, fid}}, 201)
	if len(got) != 1 {
		t.Fatalf("duplicate ids made %d exceptions", len(got))
	}
	e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{fid}}, 409)
	e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)
	e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 409)
	var list []map[string]any
	rec := do(t, e.s, "GET", "/api/v1/exceptions", nil, e.secA)
	if json.Unmarshal(rec.Body.Bytes(), &list); len(list) != 2 {
		t.Fatalf("list: %s", rec.Body.String())
	}
	f := list[1]
	if f["finding_rule"] != "CVE-2024-1" || f["finding_pkg"] != "zlib" || f["finding_severity"] != "HIGH" {
		t.Fatalf("finding brief: %v", f)
	}
}

// The API enforces what the request dialog enforces: an open finding, a real reason, an expiry from tomorrow to a year.
func TestExceptionCreateEnforcesDialogRules(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1", "CVE-2024-2")
	fid := qint64(t, e.s, `select id from findings where project_id=$1 and rule_id='CVE-2024-1'`, pid)
	pv := func(k string, v any) map[string]any {
		return map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-2", k: v}
	}
	msg := func(body map[string]any, want int) string {
		t.Helper()
		body["resolution"] = "accepted"
		if body["reason"] == nil {
			body["reason"] = "정당한 사유"
		}
		if body["expires_at"] == nil {
			body["expires_at"] = futureISO(30 * 24 * time.Hour)
		}
		rec := do(t, e.s, "POST", "/api/v1/exceptions", body, mck)
		wantCode(t, rec, want, "request")
		var e struct{ Message string }
		json.Unmarshal(rec.Body.Bytes(), &e) // a 201 answers a list
		return e.Message
	}
	if m := msg(pv("reason", "네 글자"), 400); !strings.Contains(m, "5") {
		t.Errorf("short reason: %s", m)
	}
	if m := msg(pv("reason", strings.Repeat("가", 2001)), 400); !strings.Contains(m, "2000") {
		t.Errorf("long reason: %s", m)
	}
	// the dialog sends the end of a local day from tomorrow on: never less than 24h ahead (less a second), in any zone
	for _, d := range []time.Duration{time.Minute, 12 * time.Hour, 22 * time.Hour} {
		if m := msg(pv("expires_at", futureISO(d)), 400); !strings.Contains(m, "내일") {
			t.Errorf("expiry in %v: %s", d, m)
		}
	}
	// ... and never more than a year plus the hour a day gains when summer time ends
	msg(pv("expires_at", futureISO(365*24*time.Hour+3*time.Hour)), 400)
	if n := qInt(t, e.s, `select count(*) from exceptions`); n != 0 {
		t.Fatalf("%d invalid requests were stored", n)
	}
	// what the dialog can send passes: tomorrow 23:59:59 seen from 23:59:59 today, and day 364 on a 25-hour day
	msg(pv("expires_at", futureISO(24*time.Hour-time.Second)), 201)
	sqlExec(t, e.s, `delete from exceptions`)
	msg(pv("expires_at", futureISO(365*24*time.Hour+time.Hour-time.Second)), 201)
	msg(pv("reason", "다섯 글자"), 409) // same target still pending: the reason passed
	// a finding that is not open
	sqlExec(t, e.s, `update findings set status='fixed', fixed_at=now() where id=$1`, fid)
	if m := msg(map[string]any{"scope": "finding", "finding_ids": []int64{fid}}, 409); !strings.Contains(m, "열린 결과") {
		t.Errorf("fixed finding: %s", m)
	}
	sqlExec(t, e.s, `update findings set status='open', fixed_at=null where id=$1`, fid)
	msg(map[string]any{"scope": "finding", "finding_ids": []int64{fid}}, 201)
}

// An exception past its time reads as expired at once, before the hourly job stores that; the job still notifies.
func TestExpiredShownBeforeTheJobRuns(t *testing.T) {
	e := newExEnv(t)
	_, mck, _ := e.project(t, "web", "CVE-2024-1", "CVE-2024-2")
	ap := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-1"}, 201)[0]
	pe := e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-2"}, 201)[0]
	e.decide(t, e.secA, ap.ID, "approve", 200)
	sqlExec(t, e.s, `update exceptions set expires_at = now() - interval '1 second'`)
	list := func(q string) map[int64]string {
		out := map[int64]string{}
		for _, x := range decode[[]exView](t, do(t, e.s, "GET", "/api/v1/exceptions"+q, nil, e.secA)) {
			out[x.ID] = x.Status
		}
		return out
	}
	if l := list(""); l[ap.ID] != "expired" || l[pe.ID] != "expired" {
		t.Errorf("list: %v", l)
	}
	if l := list("?status=approved,pending"); len(l) != 0 {
		t.Errorf("status filter still finds them: %v", l)
	}
	if l := list("?status=expired"); len(l) != 2 {
		t.Errorf("status=expired: %v", l)
	}
	wantCode(t, do(t, e.s, "POST", "/api/v1/exceptions/"+itoa(ap.ID)+"/revoke", nil, e.secA), 409, "revoke after expiry")
	// the expired request no longer stands in the way of a new one
	e.request(t, mck, map[string]any{"scope": "project_vuln", "project_key": "web", "vuln_id": "CVE-2024-2"}, 201)
	emits := captureEmits(t)
	e.s.expireExceptions(context.Background())
	if len(*emits) != 2 || !strings.Contains((*emits)[0], "exception_expired") {
		t.Errorf("the job must still send exception_expired: %v", *emits)
	}
}

// What the audit log and the notifications need: the finding, its target and the people, by name.
func TestExceptionCarriesNamesForAuditAndNotify(t *testing.T) {
	e := newExEnv(t)
	pid, mck, _ := e.project(t, "web", "CVE-2024-1")
	fid := qint64(t, e.s, `select id from findings where project_id=$1`, pid)
	emits := captureEmits(t)
	ex := e.request(t, mck, map[string]any{"scope": "finding", "finding_ids": []int64{fid}}, 201)[0]
	e.decide(t, e.secA, ex.ID, "approve", 200)
	var row map[string]any
	json.Unmarshal(do(t, e.s, "GET", "/api/v1/exceptions", nil, e.secA).Body.Bytes(), &[]*map[string]any{&row})
	if row["finding_target"] != "app" || row["decided_by_name"] != "seca" || row["requested_by_name"] != "m-web" {
		t.Errorf("list row: %v", row)
	}
	var target string
	e.s.db.QueryRow(context.Background(), `select target from audit_log where action='exception.approve'`).Scan(&target)
	if target != "CVE-2024-1 · zlib" {
		t.Errorf("audit target = %q", target)
	}
	last := (*emits)[len(*emits)-1]
	for _, want := range []string{`"requested_by":"m-web"`, `"decided_by":"seca"`, `"finding_rule":"CVE-2024-1"`, `"finding_pkg":"zlib"`, `"finding_severity":"HIGH"`, `"target":"app"`, `"note":"ok"`} {
		if !strings.Contains(last, want) {
			t.Errorf("approved payload misses %s: %s", want, last)
		}
	}
}

// The finding's detail names the request waiting for a decision that would cover it, so the drawer can say so
// instead of offering a second request that would only be refused.
func TestFindingNamesItsPendingException(t *testing.T) {
	e := newExEnv(t)
	_, ck, _ := e.project(t, "web", "CVE-2024-1000", "CVE-2024-2000")
	fid := func(cve string) int64 { return qint64(t, e.s, `select id from findings where rule_id=$1`, cve) }
	pending := func(cve string) *int64 {
		t.Helper()
		return decode[struct {
			PendingExceptionID *int64 `json:"pending_exception_id"`
		}](t, do(t, e.s, "GET", "/api/v1/findings/"+itoa(fid(cve)), nil, ck)).PendingExceptionID
	}
	if got := pending("CVE-2024-1000"); got != nil {
		t.Fatalf("no request yet: %d", *got)
	}
	ex := e.request(t, ck, map[string]any{"scope": "finding", "project_key": "web", "finding_ids": []int64{fid("CVE-2024-1000")}}, 201)
	if got := pending("CVE-2024-1000"); got == nil || *got != ex[0].ID {
		t.Errorf("pending request %d: got %v", ex[0].ID, got)
	}
	if got := pending("CVE-2024-2000"); got != nil {
		t.Errorf("another finding: %d", *got)
	}
	e.decide(t, e.secA, ex[0].ID, "approve", 200)
	if got := pending("CVE-2024-1000"); got != nil {
		t.Errorf("after the decision: %d", *got)
	}
}
