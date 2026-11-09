package main

import (
	"context"
	"testing"
)

func TestPolicyFailsClosed(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, ck := memberSession(t, s)
	sqlExec(t, s, `insert into policies(project_id, min_severity) values($1, 'BOGUS')`, pid)
	res := mustUpload(t, s, "web", "", trivyDoc("A", nil, nil), ck) // nothing to count, but the rule can't be read
	if res.Policy.Passed || res.Policy.Error == "" || len(res.Policy.Reasons) == 0 {
		t.Errorf("bad policy row: %+v", res.Policy)
	}
	if n := qInt(t, s, `select count(*) from scans where id=$1 and policy->>'passed' = 'false' and policy->>'error' <> ''`, res.ScanID); n != 1 {
		t.Error("stored policy is not a failure")
	}
	sqlExec(t, s, `delete from policies`)
	if p := s.evaluatePolicy(ctx, pid, res.ScanID+1000); p.Passed || p.Error == "" {
		t.Errorf("unknown scan: %+v", p)
	}
	if p := s.evaluatePolicy(ctx, pid+1000, res.ScanID); p.Passed || p.Error == "" {
		t.Errorf("scan of another project: %+v", p)
	}
	if p := s.evaluatePolicy(ctx, pid, res.ScanID); !p.Passed || p.Error != "" || p.Reasons == nil {
		t.Errorf("good policy: %+v", p)
	}
}

func TestPolicyRules(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, ck := memberSession(t, s)
	crit := tv{ID: "CVE-2024-1000", Sev: "CRITICAL"}
	high := tv{ID: "CVE-2024-2000", Sev: "HIGH", Fixed: "2.0"}
	s1 := mustUpload(t, s, "web", "", trivyDoc("A", []tv{crit, high}, nil), ck)
	if s1.Policy.Passed || len(s1.Policy.Reasons) != 1 {
		t.Errorf("default policy with one CRITICAL: %+v", s1.Policy)
	}
	// another target's CRITICAL never counts against A's scan
	mustUpload(t, s, "web", "", trivyDoc("B", []tv{crit, {ID: "CVE-2024-5000", Sev: "CRITICAL"}}, nil), ck)
	set := func(q string) {
		t.Helper()
		sqlExec(t, s, `insert into policies(project_id) values($1) on conflict do nothing`, pid)
		sqlExec(t, s, `update policies set `+q+` where project_id=$1`, pid)
	}
	check := func(scan int64, want bool, what string) {
		t.Helper()
		if p := s.evaluatePolicy(ctx, pid, scan); p.Passed != want || p.Error != "" {
			t.Errorf("%s: %+v, want passed=%v", what, p, want)
		}
	}
	set(`max_count = 1`)
	check(s1.ScanID, true, "one CRITICAL allowed")
	set(`max_count = 1, min_severity = 'HIGH'`)
	check(s1.ScanID, false, "CRITICAL and HIGH counted at HIGH")
	set(`fixable_only = true`)
	check(s1.ScanID, true, "only the HIGH has a fix")
	set(`max_count = 0`)
	check(s1.ScanID, false, "fixable HIGH over 0")
	set(`fixable_only = false, min_severity = 'CRITICAL', new_only = true`)
	check(s1.ScanID, false, "CRITICAL new in s1")
	s2 := mustUpload(t, s, "web", "", trivyDoc("A", []tv{crit, high}, nil), ck)
	check(s2.ScanID, true, "CRITICAL already seen before s2")
	set(`new_only = false`)
	check(s2.ScanID, false, "CRITICAL still open")

	critID := qint64(t, s, `select id from findings where target_id=$1 and rule_id=$2`, s1.TargetID, crit.ID)
	exID := qint64(t, s, `insert into exceptions(scope, project_id, finding_id, resolution, reason, status, expires_at)
		values('finding', $1, $2, 'accepted', 'r', 'pending', now() + interval '1 day') returning id`, pid, critID)
	check(s2.ScanID, false, "pending exception")
	sqlExec(t, s, `update exceptions set status='approved' where id=$1`, exID)
	check(s2.ScanID, true, "approved finding exception")
	sqlExec(t, s, `update exceptions set expires_at = now() - interval '1 minute' where id=$1`, exID)
	check(s2.ScanID, false, "expired exception")
	sqlExec(t, s, `insert into exceptions(scope, project_id, vuln_id, resolution, reason, status, expires_at)
		values('project_vuln', $1, $2, 'accepted', 'r', 'approved', now() + interval '1 day')`, pid, crit.ID)
	check(s2.ScanID, true, "approved project_vuln exception")
	sqlExec(t, s, `delete from exceptions`)
	sqlExec(t, s, `insert into exceptions(scope, vuln_id, resolution, reason, status, expires_at)
		values('global_vuln', $1, 'false_positive', 'r', 'approved', now() + interval '1 day')`, crit.ID)
	check(s2.ScanID, true, "approved global_vuln exception")
	sqlExec(t, s, `delete from exceptions`)
	set(`enabled = false`)
	check(s2.ScanID, true, "disabled")
	sqlExec(t, s, `delete from policies`)
	if err := s.putSetting(ctx, "default_policy", map[string]any{"min_severity": "CRITICAL", "max_count": 5}); err != nil {
		t.Fatal(err)
	}
	check(s2.ScanID, true, "default_policy setting")
}
