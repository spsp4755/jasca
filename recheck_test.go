package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spsp4755/jasca/internal/formats"
	"github.com/spsp4755/jasca/internal/trivy"
)

// seedInventory ingests a fixture as a scan of target name; keepFindings=false stores only its packages.
func seedInventory(t *testing.T, s *server, pid int64, kind, name, fixture string, keepFindings bool) int64 {
	t.Helper()
	rep := parseReport(t, "trivy", readFixture(t, fixture))
	if !keepFindings {
		rep.Findings = nil
	}
	res, err := s.ingest(context.Background(), ingestInput{ProjectID: pid, TargetKind: kind, TargetName: name, Source: "upload", Report: rep})
	if err != nil {
		t.Fatal(err)
	}
	return res.TargetID
}

// sbomStyle turns a filesystem report into what trivy sbom prints: language results are named after the
// language and carry no file path.
func sbomStyle(t *testing.T, b []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["Results"].([]any) {
		if m := r.(map[string]any); m["Class"] == "lang-pkgs" {
			m["Target"] = "Node.js"
		}
	}
	out, _ := json.Marshal(doc)
	return out
}

type runView struct {
	ID          int64  `json:"id"`
	Reason      string `json:"reason"`
	State       string `json:"state"`
	Total       int    `json:"total"`
	Done        int    `json:"done"`
	NewFindings int    `json:"new_findings"`
}

func captureEmits(t *testing.T) *[]string {
	var got []string
	old := notifyEmit
	notifyEmit = func(s *server, ctx context.Context, projectID int64, event string, payload map[string]any) {
		b, _ := json.Marshal(payload)
		got = append(got, itoa(projectID)+" "+event+" "+string(b))
	}
	t.Cleanup(func() { notifyEmit = old })
	return &got
}

func TestRecheckAddsOnlyAndResumes(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid := mkProject(t, s, "web")
	t1 := seedInventory(t, s, pid, "fs", "t1", "trivy/fs-mixed.json", true) // already has the findings
	t2 := seedInventory(t, s, pid, "fs", "t2", "trivy/fs-mixed.json", false)
	t3 := seedInventory(t, s, pid, "fs", "t3", "trivy/fs-mixed.json", false)
	emits := captureEmits(t) // after seeding: the uploads' own new_critical/policy_failed events are not the recheck's
	sqlExec(t, s, `update findings set status='fixed', fixed_at=now() where target_id=$1 and rule_id='CVE-2021-23337'`, t1)
	sqlExec(t, s, `update findings set status='accepted' where target_id=$1 and rule_id='CVE-2026-4800'`, t1)
	sqlExec(t, s, `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity) values($1, $2, 'gone', 'vuln', 'trivy', 'CVE-1999-0001', 'LOW')`, pid, t1)
	var seeded time.Time
	s.db.QueryRow(ctx, `select now()`).Scan(&seeded)

	logPath := useFakeTrivy(t, s, sbomStyle(t, readFixture(t, "trivy/fs-mixed.json")))
	wait := filepath.Join(t.TempDir(), "go-on")
	t.Setenv("FAKETRIVY_WAIT_CALL", "2")
	t.Setenv("FAKETRIVY_WAIT_FILE", wait)
	runID, err := s.startRecheck(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	stop := startJobs(t, s)
	waitFor(t, "item 2 to start", func() bool { return len(readLog(logPath)) == 2 })
	stop() // the process dies while item 2 runs
	if st := qInt(t, s, `select count(*) from recheck_items where run_id=$1 and state='done'`, runID); st != 1 {
		t.Fatalf("done items after kill: %d", st)
	}
	if n := qInt(t, s, `select count(*) from jobs where kind='recheck' and state='running'`); n != 1 {
		t.Fatal("killed job should stay running until the restart")
	}
	os.WriteFile(wait, nil, 0o644)
	startJobs(t, s) // restart: running -> queued, then resumes
	waitFor(t, "run to finish", func() bool {
		return qInt(t, s, `select count(*) from recheck_runs where id=$1 and state='done'`, runID) == 1
	})
	calls := readLog(logPath)
	count := func(tid int64) int {
		n := 0
		for _, c := range calls {
			if strings.Contains(c, "recheck-"+itoa(tid)+"-") {
				n++
			}
		}
		return n
	}
	if len(calls) != 4 || count(t1) != 1 || count(t2) != 2 || count(t3) != 1 || !strings.HasPrefix(calls[0], "sbom|") {
		t.Fatalf("trivy calls: %v", calls)
	}
	// adds only: t1 keeps its statuses, nothing is resolved or touched
	if st, _, _ := findingState(t, s, t1, "CVE-2021-23337"); st != "fixed" {
		t.Fatalf("fixed finding changed: %s", st)
	}
	if st, _, _ := findingState(t, s, t1, "CVE-2026-4800"); st != "accepted" {
		t.Fatalf("accepted finding changed: %s", st)
	}
	if st, _, _ := findingState(t, s, t1, "CVE-1999-0001"); st != "open" {
		t.Fatalf("finding absent from recheck was resolved: %s", st)
	}
	if n := qInt(t, s, `select count(*) from findings where target_id=$1 and last_seen_at >= $2`, t1, seeded); n != 0 {
		t.Fatal("existing findings were touched")
	}
	var v runView
	s.db.QueryRow(ctx, `select total, done, new_findings from recheck_runs where id=$1`, runID).Scan(&v.Total, &v.Done, &v.NewFindings)
	recheckNew := qInt(t, s, `select count(*) from findings where origin='recheck'`)
	if v.Total != 3 || v.Done != 3 || v.NewFindings != 8 || recheckNew != 8 {
		t.Fatalf("run %+v, recheck findings %d", v, recheckNew)
	}
	if n := qInt(t, s, `select count(*) from findings where origin='recheck' and target_id=$1`, t1); n != 0 {
		t.Fatal("t1 got recheck findings")
	}
	if n := qInt(t, s, `select count(*) from scans where source='recheck'`); n != 2 {
		t.Fatalf("recheck scans: %d", n)
	}
	if len(*emits) != 1 || !strings.HasPrefix((*emits)[0], itoa(pid)+" new_known ") || !strings.Contains((*emits)[0], `"count":8`) {
		t.Fatalf("emits: %v", *emits)
	}
	// the recheck fingerprints are the scan ones: a real scan of t2 adds nothing new
	res, err := s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "t2", Source: "upload",
		Report: parseReport(t, "trivy", readFixture(t, "trivy/fs-mixed.json"))})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range res.New {
		var kind string
		s.db.QueryRow(ctx, `select kind from findings where id=$1`, id).Scan(&kind)
		if kind == "vuln" {
			t.Fatalf("scan after recheck created vuln finding %d again", id)
		}
	}
	if p := qInt(t, s, `select count(*) from findings where target_id=$1 and kind='vuln' and pkg_path='package-lock.json'`, t2); p != 4 {
		t.Fatalf("pkg_path not mapped back: %d", p)
	}
}

func TestRecheckYieldsToScan(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid := mkProject(t, s, "web")
	seedInventory(t, s, pid, "fs", "t1", "trivy/fs-mixed.json", false)
	seedInventory(t, s, pid, "fs", "t2", "trivy/fs-mixed.json", false)
	logPath := useFakeTrivy(t, s, sbomStyle(t, readFixture(t, "trivy/fs-mixed.json")))
	wait := filepath.Join(t.TempDir(), "go-on")
	t.Setenv("FAKETRIVY_WAIT_CALL", "1")
	t.Setenv("FAKETRIVY_WAIT_FILE", wait)
	s.registerJob("ai", func(ctx context.Context, j *job) error {
		f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
		defer f.Close()
		_, err := f.WriteString("ai\n")
		return err
	})
	runID, err := s.startRecheck(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	startJobs(t, s)
	waitFor(t, "item 1 to start", func() bool { return len(readLog(logPath)) == 1 })
	if _, err := s.enqueue(ctx, nil, "ai", nil, map[string]any{}, 5); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(wait, nil, 0o644)
	waitFor(t, "run to finish", func() bool {
		return qInt(t, s, `select count(*) from recheck_runs where id=$1 and state='done'`, runID) == 1
	})
	calls := readLog(logPath)
	if len(calls) != 3 || calls[1] != "ai" || !strings.HasPrefix(calls[2], "sbom|") {
		t.Fatalf("order: %v", calls)
	}
	if n := qInt(t, s, `select attempts from jobs where kind='recheck'`); n != 2 {
		t.Fatalf("recheck attempts %d (should have yielded once)", n)
	}
}

func TestRecheckRoutes(t *testing.T) {
	s := testServer(t)
	pid := mkProject(t, s, "web")
	adm := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	seedInventory(t, s, pid, "fs", "in", "trivy/fs-mixed.json", false)
	ex := seedInventory(t, s, pid, "image", "harbor", "trivy/image-alpine.json", false)
	sqlExec(t, s, `update targets set recheck_excluded=true where id=$1`, ex)
	s.ingest(context.Background(), ingestInput{ProjectID: pid, TargetKind: "repo", TargetName: "nopkgs", Source: "upload",
		Report: &formats.Report{Format: "sarif"}})

	rec := do(t, s, "POST", "/api/v1/admin/recheck", nil, adm)
	wantCode(t, rec, 201, "start")
	if r := decode[runView](t, rec); r.Reason != "manual" || r.State != "running" || r.Total != 1 {
		t.Fatalf("run: %+v", r)
	}
	wantCode(t, do(t, s, "POST", "/api/v1/admin/recheck", nil, adm), 409, "second while running")
	sqlExec(t, s, `update recheck_runs set state='done'`)
	wantCode(t, do(t, s, "POST", "/api/v1/admin/recheck", nil, adm), 201, "after done")
	runs := decode[[]runView](t, do(t, s, "GET", "/api/v1/admin/recheck", nil, adm))
	if len(runs) != 2 || runs[0].ID < runs[1].ID || runs[0].State != "running" {
		t.Fatalf("runs: %+v", runs)
	}
	if auditCount(t, s, "recheck.start") != 2 {
		t.Fatal("not audited")
	}
	wantCode(t, do(t, s, "GET", "/api/v1/admin/recheck", nil, loginAs(t, s, mkUser(t, s, "u", ""))), 403, "user")
}

func TestOSForRecheck(t *testing.T) {
	for _, c := range []struct {
		summary map[string]any
		purl    string
		want    *trivy.OSInfo
	}{
		{map[string]any{"os": map[string]any{"family": "alpine", "name": "3.12.12"}}, "", &trivy.OSInfo{Family: "alpine", Name: "3.12.12"}},
		{nil, "pkg:apk/alpine/zlib@1.2.12-r0?arch=x86_64&distro=3.12.12", &trivy.OSInfo{Family: "alpine", Name: "3.12.12"}},
		{nil, "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u3?arch=amd64&distro=debian-11.6", &trivy.OSInfo{Family: "debian", Name: "11.6"}},
		{nil, "pkg:npm/lodash@4.17.20", nil},
	} {
		got := osForRecheck(c.summary, []trivy.Package{{PURL: c.purl}})
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%v %s: got %+v", c.summary, c.purl, got)
		}
	}
}

// TestRecheckRealTrivy proves OS packages are matched again: the CycloneDX carries the operating-system component.
func TestRecheckRealTrivy(t *testing.T) {
	if os.Getenv("JASCA_TEST_TRIVY") != "1" {
		t.Skip("set JASCA_TEST_TRIVY=1, JASCA_TRIVY_BIN and JASCA_TRIVY_CACHE")
	}
	s := testServer(t)
	ctx := context.Background()
	s.cfg.TrivyBin = os.Getenv("JASCA_TRIVY_BIN")
	if err := os.Symlink(os.Getenv("JASCA_TRIVY_CACHE"), filepath.Join(s.cfg.DataDir, "trivy")); err != nil {
		t.Fatal(err)
	}
	pid := mkProject(t, s, "web")
	img := seedInventory(t, s, pid, "image", "alpine", "trivy/image-alpine.json", false)
	src := seedInventory(t, s, pid, "fs", "web-src", "trivy/fs-mixed.json", false)
	if _, err := s.startRecheck(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	if ran, err := s.runNextJob(ctx); !ran || err != nil {
		t.Fatal(ran, err)
	}
	var state, errMsg string
	s.db.QueryRow(ctx, `select state, error from recheck_runs`).Scan(&state, &errMsg)
	if state != "done" || errMsg != "" {
		t.Fatalf("run %s %q", state, errMsg)
	}
	want := map[int64]formats.Finding{}
	for tid, fx := range map[int64]string{img: "trivy/image-alpine.json", src: "trivy/fs-mixed.json"} {
		for _, f := range parseReport(t, "trivy", readFixture(t, fx)).Findings {
			if f.Kind == "vuln" && (f.RuleID == "CVE-2022-37434" || f.RuleID == "CVE-2021-23337") {
				want[tid] = f
			}
		}
	}
	for tid, f := range want {
		var path, origin string
		err := s.db.QueryRow(ctx, `select pkg_path, origin from findings where target_id=$1 and fingerprint=$2`, tid, f.Fingerprint).Scan(&path, &origin)
		if err != nil || origin != "recheck" {
			t.Fatalf("target %d: %s on %s not found again by recheck (%v)", tid, f.RuleID, f.PkgName, err)
		}
		t.Logf("recheck found %s %s path=%q", f.RuleID, f.PkgName, path)
	}
	t.Logf("recheck findings: %d", qInt(t, s, `select count(*) from findings where origin='recheck'`))
}
