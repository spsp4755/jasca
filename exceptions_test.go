package main

import (
	"context"
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
}

func init() {
	body := map[string]any{"scope": "project_vuln", "project_key": "{key}", "vuln_id": "CVE-2024-0001",
		"resolution": "accepted", "reason": "x", "expires_at": "{exp}"}
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
	if l := decode[[]exView](t, rec); len(l) != 1 || l[0].ProjectID != nil {
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
