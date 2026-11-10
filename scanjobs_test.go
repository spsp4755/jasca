package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "POST", Path: "/api/v1/projects/{key}/scan-jobs"},
		matrixCase{Method: "POST", Path: "/api/v1/scans/{scan}/cancel"})
}

// fakeTrivyBin builds testdata/faketrivy once per test run.
var fakeTrivyBin = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "jasca-faketrivy-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "trivy")
	out, err := exec.Command("go", "build", "-o", bin, "./testdata/faketrivy").CombinedOutput()
	if err != nil {
		return "", &os.PathError{Op: "go build faketrivy", Path: string(out), Err: err}
	}
	return bin, nil
})

// useFakeTrivy points s at the fake trivy, which prints out as its report. It returns the call log path.
func useFakeTrivy(t *testing.T, s *server, out []byte) string {
	t.Helper()
	bin, err := fakeTrivyBin()
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.TrivyBin = bin
	dir := t.TempDir()
	op := filepath.Join(dir, "out.json")
	if err := os.WriteFile(op, out, 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	t.Setenv("FAKETRIVY_OUT", op)
	t.Setenv("FAKETRIVY_LOG", logPath)
	return logPath
}

func readLog(path string) []string {
	b, _ := os.ReadFile(path)
	return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), " ", "|")) // one entry per line
}

// waitFor polls cond for up to 15s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 750 {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// startJobs runs the job loop until the returned stop func is called (also on cleanup).
func startJobs(t *testing.T, s *server) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.jobLoop(ctx); close(done) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return stop
}

func multipartReq(t *testing.T, fields map[string]string, file []byte) ([]byte, http.Header) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if file != nil {
		fw, _ := mw.CreateFormFile("file", "upload.bin")
		fw.Write(file)
	}
	mw.Close()
	return b.Bytes(), http.Header{"Content-Type": {mw.FormDataContentType()}, "Sec-Fetch-Site": {"same-origin"}}
}

func postScanJob(t *testing.T, s *server, ck *http.Cookie, key string, fields map[string]string, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, h := multipartReq(t, fields, file)
	return do(t, s, "POST", "/api/v1/projects/"+key+"/scan-jobs", body, ck, h)
}

func mustScanJob(t *testing.T, s *server, ck *http.Cookie, target, kind string, file []byte) int64 {
	t.Helper()
	rec := postScanJob(t, s, ck, "web", map[string]string{"target": target, "kind": kind}, file)
	if rec.Code != 201 {
		t.Fatalf("scan job: %d %s", rec.Code, rec.Body.String())
	}
	return decode[struct {
		ScanID int64 `json:"scan_id"`
	}](t, rec).ScanID
}

func scanStatus(t *testing.T, s *server, id int64) (status, errMsg string) {
	t.Helper()
	if err := s.db.QueryRow(context.Background(), `select status, error from scans where id=$1`, id).Scan(&status, &errMsg); err != nil {
		t.Fatal(err)
	}
	return
}

func jobState(t *testing.T, s *server, scanID int64) string {
	t.Helper()
	var st string
	if err := s.db.QueryRow(context.Background(), `select state from jobs where scan_id=$1`, scanID).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func gone(path string) bool { _, err := os.Stat(path); return os.IsNotExist(err) }

func TestScanJobWithFakeTrivy(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, ck := memberSession(t, s)
	// the report has only an os-pkgs result, so only the scanners setting can mark secret:trivy complete
	logPath := useFakeTrivy(t, s, trivyDoc("x", []tv{{ID: "CVE-2024-1111"}}, nil))
	argsPath := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKETRIVY_ARGS", argsPath)
	if err := s.putSetting(ctx, "trivy", map[string]any{"scanners": []string{"vuln", "secret"}}); err != nil {
		t.Fatal(err)
	}
	// an open secret finding the new complete secret scan no longer has must be fixed
	tid := qint64(t, s, `insert into targets(project_id, kind, name) values($1, 'fs', 'web-src') returning id`, pid)
	sqlExec(t, s, `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity) values($1, $2, 'old', 'secret', 'trivy', 'old-key', 'HIGH')`, pid, tid)

	id := mustScanJob(t, s, ck, "web-src", "fs", mkZip(t, arEnt{name: "package-lock.json", body: "{}"}, arEnt{name: "src/a.js", body: "x"}))
	if st, _ := scanStatus(t, s, id); st != "queued" {
		t.Fatalf("status %s", st)
	}
	var prio int
	var createdBy int64
	if err := s.db.QueryRow(ctx, `select priority, created_by from jobs where scan_id=$1 and kind='server_scan' and state='queued'`, id).Scan(&prio, &createdBy); err != nil || prio != 10 {
		t.Fatalf("job: %v prio=%d", err, prio)
	}
	work := filepath.Join(s.cfg.DataDir, "work", itoa(id))
	if gone(filepath.Join(work, "upload")) {
		t.Fatal("upload not stored under work/<scan>")
	}
	if ran, err := s.runNextJob(ctx); !ran || err != nil {
		t.Fatalf("run: %v %v", ran, err)
	}
	if st, e := scanStatus(t, s, id); st != "done" {
		t.Fatalf("scan %s %q", st, e)
	}
	if jobState(t, s, id) != "done" || !gone(work) {
		t.Fatal("job not done or work dir left behind")
	}
	if n := qInt(t, s, `select count(*) from scan_findings sf join scans sc on sc.id=sf.scan_id where sc.id=$1 and sc.source='server' and sc.target_id=$2`, id, tid); n == 0 {
		t.Fatal("no findings linked")
	}
	if st, _, _ := findingState(t, s, tid, "old-key"); st != "fixed" {
		t.Fatalf("old secret: %s (scanners not passed to ingest)", st)
	}
	calls := readLog(logPath)
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "fs|"+work+"/src|files=") || !strings.Contains(calls[0], "package-lock.json,src/a.js") {
		t.Fatalf("trivy calls: %v", calls)
	}
	if auditCount(t, s, "scan.job") != 1 {
		t.Fatal("not audited")
	}

	// image: the upload goes to trivy image --input as is
	id = mustScanJob(t, s, ck, "app", "image", mkTarGz(t, false, arEnt{name: "manifest.json", body: "[]"}))
	if ran, err := s.runNextJob(ctx); !ran || err != nil {
		t.Fatal(ran, err)
	}
	if st, e := scanStatus(t, s, id); st != "done" {
		t.Fatalf("image scan %s %q", st, e)
	}
	work = filepath.Join(s.cfg.DataDir, "work", itoa(id))
	if calls := readLog(logPath); len(calls) != 2 || calls[1] != "image|"+work+"/upload" {
		t.Fatalf("trivy calls: %v", calls)
	}
	// no Java DB installed: Java archives are skipped, or real Trivy fails the whole scan at the first JAR
	if args, _ := os.ReadFile(argsPath); !strings.Contains(string(args), "--skip-files=**/*.jar") {
		t.Fatalf("no java db, args:\n%s", args)
	}
	fakeTrivyDB(t, s)
	os.MkdirAll(filepath.Join(s.trivyCacheDir(), "java-db"), 0o755)
	os.WriteFile(filepath.Join(s.trivyCacheDir(), "java-db", "metadata.json"), []byte(`{"Version":1,"UpdatedAt":"2026-11-01T00:00:00Z"}`), 0o644)
	mustScanJob(t, s, ck, "app", "image", mkTarGz(t, false, arEnt{name: "manifest.json", body: "[1]"}))
	if ran, err := s.runNextJob(ctx); !ran || err != nil {
		t.Fatal(ran, err)
	}
	if args, _ := os.ReadFile(argsPath); strings.Contains(string(args), "--skip-files") {
		t.Fatalf("java db installed, args:\n%s", args)
	}
	var kind string
	s.db.QueryRow(ctx, `select t.kind from scans s join targets t on t.id=s.target_id where s.id=$1`, id).Scan(&kind)
	if kind != "image" {
		t.Fatalf("target kind %s", kind)
	}
}

func TestScanJobUploadRules(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	s.cfg.MaxScanUploadMB = 1
	zip := mkZip(t, arEnt{name: "a", body: "x"})
	for name, c := range map[string]struct {
		fields map[string]string
		file   []byte
		code   int
	}{
		"too big":    {map[string]string{"target": "t", "kind": "fs"}, make([]byte, 2<<20), 413},
		"bad kind":   {map[string]string{"target": "t", "kind": "repo"}, zip, 400},
		"no target":  {map[string]string{"kind": "fs"}, zip, 400},
		"no file":    {map[string]string{"target": "t", "kind": "fs"}, nil, 400},
		"empty file": {map[string]string{"target": "t", "kind": "fs"}, []byte{}, 400},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postScanJob(t, s, ck, "web", c.fields, c.file)
			wantCode(t, rec, c.code, name)
		})
	}
	if n := qInt(t, s, `select count(*) from scans`) + qInt(t, s, `select count(*) from jobs`); n != 0 {
		t.Fatalf("rows left behind: %d", n)
	}
	es, _ := os.ReadDir(filepath.Join(s.cfg.DataDir, "work"))
	if len(es) != 0 {
		t.Fatalf("work dir not clean: %v", es)
	}
	// a viewer cannot start a scan
	v := mkUser(t, s, "viewer", "")
	addMember(t, s, qint64(t, s, `select id from projects where key='web'`), "user", itoa(v.ID), "viewer")
	wantCode(t, postScanJob(t, s, loginAs(t, s, v), "web", map[string]string{"target": "t", "kind": "fs"}, zip), 403, "viewer")
}

func TestExtractCleansUp(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, ck := memberSession(t, s)
	logPath := useFakeTrivy(t, s, readFixture(t, "trivy/fs-mixed.json"))
	id := mustScanJob(t, s, ck, "evil", "fs", mkZip(t, arEnt{name: "../../escape.txt", body: "x"}))
	s.runNextJob(ctx)
	st, msg := scanStatus(t, s, id)
	if st != "failed" || !strings.Contains(msg, "압축") {
		t.Fatalf("hostile archive: %s %q", st, msg)
	}
	if !gone(filepath.Join(s.cfg.DataDir, "work", itoa(id))) || jobState(t, s, id) != "failed" {
		t.Fatal("work dir left or job not failed")
	}
	if len(readLog(logPath)) != 0 {
		t.Fatal("trivy ran on a rejected archive")
	}
	// a trivy failure also fails the scan with a Korean message and cleans up
	t.Setenv("FAKETRIVY_FAIL", "1")
	id = mustScanJob(t, s, ck, "ok", "fs", mkZip(t, arEnt{name: "a.txt", body: "x"}))
	s.runNextJob(ctx)
	if st, msg := scanStatus(t, s, id); st != "failed" || !strings.Contains(msg, "Trivy") {
		t.Fatalf("trivy failure: %s %q", st, msg)
	}
	if !gone(filepath.Join(s.cfg.DataDir, "work", itoa(id))) {
		t.Fatal("work dir left after trivy failure")
	}
}

func TestScanCancel(t *testing.T) {
	s := testServer(t)
	pid, ck := memberSession(t, s)
	other := mkUser(t, s, "dev2", "")
	addMember(t, s, pid, "user", itoa(other.ID), "member")
	logPath := useFakeTrivy(t, s, readFixture(t, "trivy/fs-mixed.json"))
	t.Setenv("FAKETRIVY_WAIT_CALL", "1")
	t.Setenv("FAKETRIVY_WAIT_FILE", filepath.Join(t.TempDir(), "never"))

	id := mustScanJob(t, s, ck, "slow", "fs", mkZip(t, arEnt{name: "a.txt", body: "x"}))
	stop := startJobs(t, s)
	waitFor(t, "trivy to start", func() bool { return len(readLog(logPath)) == 1 })
	if st, _ := scanStatus(t, s, id); st != "running" {
		t.Fatalf("status %s", st)
	}
	path := "/api/v1/scans/" + itoa(id) + "/cancel"
	wantCode(t, do(t, s, "POST", path, nil, loginAs(t, s, other)), 403, "another member")
	wantCode(t, do(t, s, "POST", path, nil, ck), 204, "requester")
	waitFor(t, "job canceled", func() bool { return jobState(t, s, id) == "canceled" })
	if st, _ := scanStatus(t, s, id); st != "canceled" {
		t.Fatalf("scan %s", st)
	}
	waitFor(t, "work dir removed", func() bool { return gone(filepath.Join(s.cfg.DataDir, "work", itoa(id))) })
	wantCode(t, do(t, s, "POST", path, nil, ck), 409, "already canceled")
	stop()

	// a queued scan: the job never runs; an admin may cancel anyone's scan
	id = mustScanJob(t, s, ck, "queued", "fs", mkZip(t, arEnt{name: "a.txt", body: "x"}))
	wantCode(t, do(t, s, "POST", "/api/v1/scans/"+itoa(id)+"/cancel", nil, loginAs(t, s, mkUser(t, s, "adm", "admin"))), 204, "admin")
	if jobState(t, s, id) != "canceled" {
		t.Fatal("queued job not canceled")
	}
	if !gone(s.workDir(id)) {
		t.Fatal("a canceled queued scan left its upload on disk")
	}
	if ran, _ := s.runNextJob(context.Background()); ran {
		t.Fatal("canceled job was picked")
	}
	if auditCount(t, s, "scan.cancel") != 2 {
		t.Fatal("cancel not audited")
	}
}

// mkBundle builds a trivy-db bundle; truncate cuts it in half.
func mkBundle(t *testing.T, version int, truncate bool) []byte {
	return mkBundleOf(t, "trivy.db", version, truncate)
}

// mkBundleOf builds a bundle around dbFile: "trivy.db" (db.tar.gz) or "trivy-java.db" (javadb.tar.gz).
func mkBundleOf(t *testing.T, dbFile string, version int, truncate bool) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	meta := []byte(`{"Version":` + itoa(int64(version)) + `,"NextUpdate":"2026-11-10T00:00:00Z","UpdatedAt":"2026-11-09T00:00:00Z"}`)
	for name, body := range map[string][]byte{dbFile: bytes.Repeat([]byte{7}, 2<<20), "metadata.json": meta} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	tw.Close()
	zw.Close()
	if truncate {
		return b.Bytes()[:b.Len()/2]
	}
	return b.Bytes()
}

func TestTrivyDBUploadKeepsOldOnFailure(t *testing.T) {
	s := testServer(t)
	useFakeTrivy(t, s, []byte(`{}`))
	adm := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	postDB := func(b []byte, ck *http.Cookie) *httptest.ResponseRecorder {
		body, h := multipartReq(t, nil, b)
		return do(t, s, "POST", "/api/v1/admin/trivy/db", body, ck, h)
	}
	type status struct {
		DBVersion    int      `json:"db_version"`
		UpdatedAt    *string  `json:"updated_at"`
		Scanners     []string `json:"scanners"`
		TrivyVersion string   `json:"trivy_version"`
		RecheckRunID int64    `json:"recheck_run_id"`
	}
	st := decode[status](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm))
	if st.DBVersion != 0 || st.UpdatedAt != nil || st.TrivyVersion != "0.76.1-fake" || len(st.Scanners) == 0 {
		t.Fatalf("empty status: %+v", st)
	}
	rec := postDB(mkBundle(t, 2, false), adm)
	wantCode(t, rec, 200, "good bundle")
	if r := decode[status](t, rec); r.DBVersion != 2 || r.RecheckRunID == 0 {
		t.Fatalf("upload result: %+v", r)
	}
	dbFile := filepath.Join(s.cfg.DataDir, "trivy", "db", "trivy.db")
	before, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "trivy", "db", "metadata.json"))

	for name, b := range map[string][]byte{"truncated": mkBundle(t, 3, true), "not gzip": []byte("PK\x03\x04 nope")} {
		rec := postDB(b, adm)
		if rec.Code != 400 || errCode(t, rec) != "bad_bundle" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	after, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "trivy", "db", "metadata.json"))
	if fi, err := os.Stat(dbFile); err != nil || fi.Size() != 2<<20 || !bytes.Equal(before, after) {
		t.Fatalf("old db not kept: %v", err)
	}
	if st := decode[status](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm)); st.DBVersion != 2 {
		t.Fatalf("status after failure: %+v", st)
	}
	if n := qInt(t, s, `select count(*) from recheck_runs where reason='trivydb'`); n != 1 {
		t.Fatalf("recheck runs: %d", n)
	}
	// too big, either unpacked (InstallBundle's limit) or on the wire: 413, old DB kept
	s.cfg.MaxExtractMB = 1
	if rec := postDB(mkBundle(t, 3, false), adm); rec.Code != 413 {
		t.Fatalf("unpacked too big: %d %s", rec.Code, rec.Body.String())
	}
	s.cfg.MaxExtractMB, s.cfg.MaxScanUploadMB = 4096, 1
	noise := make([]byte, 2<<20)
	rand.Read(noise)
	if rec := postDB(noise, adm); rec.Code != 413 {
		t.Fatalf("upload too big: %d %s", rec.Code, rec.Body.String())
	}
	s.cfg.MaxScanUploadMB = 2048
	if st := decode[status](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm)); st.DBVersion != 2 {
		t.Fatalf("status after 413: %+v", st)
	}
	if es, _ := os.ReadDir(filepath.Join(s.cfg.DataDir, "work")); len(es) != 0 {
		t.Fatalf("spooled bundle left behind: %v", es)
	}
	wantCode(t, postDB(mkBundle(t, 2, false), loginAs(t, s, mkUser(t, s, "sec", "security"))), 403, "security")

	// scanners setting
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", map[string]any{"scanners": []string{"vuln", "misconfig"}}, adm), 200, "put scanners")
	if st := decode[status](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm)); strings.Join(st.Scanners, ",") != "vuln,misconfig" {
		t.Fatalf("scanners: %v", st.Scanners)
	}
	for _, bad := range [][]string{{}, {"vuln", "license"}, {"vuln", "vuln"}} {
		wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", map[string]any{"scanners": bad}, adm), 400, "bad scanners")
	}
	if auditCount(t, s, "trivy.db_upload") != 1 || auditCount(t, s, "trivy.db_upload_failed") != 4 {
		t.Fatal("uploads not audited")
	}
	if auditCount(t, s, "trivy.settings") != 1 {
		t.Fatal("settings not audited")
	}
}

// Uploads of deleted projects and files a crash left behind are removed; queued scans keep their upload.
// A Java DB goes in on its own, before or after the main DB, and the answer says which one was installed. It starts
// no recheck: the recheck evaluates stored package lists, which a Java DB does not change.
func TestJavaDBUpload(t *testing.T) {
	s := testServer(t)
	useFakeTrivy(t, s, []byte(`{}`))
	adm := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	type status struct {
		Kind      string  `json:"kind"`
		DBVersion int     `json:"db_version"`
		UpdatedAt *string `json:"updated_at"`
		JavaDB    *struct {
			UpdatedAt string `json:"updated_at"`
		} `json:"java_db"`
		RecheckRunID int64 `json:"recheck_run_id"`
	}
	postDB := func(b []byte) status {
		body, h := multipartReq(t, nil, b)
		rec := do(t, s, "POST", "/api/v1/admin/trivy/db", body, adm, h)
		wantCode(t, rec, 200, "bundle")
		return decode[status](t, rec)
	}
	st := postDB(mkBundleOf(t, "trivy-java.db", 1, false))
	if st.Kind != "java-db" || st.JavaDB == nil || st.JavaDB.UpdatedAt != "2026-11-09T00:00:00Z" || st.DBVersion != 0 || st.UpdatedAt != nil || st.RecheckRunID != 0 {
		t.Fatalf("java db before the main db: %+v", st)
	}
	if st := decode[status](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm)); st.JavaDB == nil || st.DBVersion != 0 {
		t.Fatalf("status with only a java db: %+v", st)
	}
	if st = postDB(mkBundle(t, 2, false)); st.Kind != "db" || st.DBVersion != 2 || st.JavaDB == nil || st.RecheckRunID == 0 {
		t.Fatalf("main db after the java db: %+v", st)
	}
	if st = postDB(mkBundleOf(t, "trivy-java.db", 1, false)); st.Kind != "java-db" || st.DBVersion != 2 || st.RecheckRunID != 0 {
		t.Fatalf("java db replaced: %+v", st)
	}
	if n := qInt(t, s, `select count(*) from recheck_runs`); n != 1 {
		t.Fatalf("recheck runs: %d, want 1 (only the main DB starts one)", n)
	}
	if auditCount(t, s, "trivy.db_upload") != 3 || qInt(t, s, `select count(*) from audit_log where action='trivy.db_upload' and target='java-db'`) != 2 {
		t.Fatal("uploads not audited with their kind")
	}
}

func fullTrivyOptions() map[string]any {
	return map[string]any{"scanners": []string{"vuln", "misconfig"}, "ignore_unfixed": true, "severities": []string{"CRITICAL", "HIGH"},
		"pkg_types": []string{"library"}, "include_dev_deps": true, "detection_priority": "comprehensive",
		"skip_dirs": []string{"-rf", "node_modules"}, "skip_files": []string{"**/*.min.js"}, "timeout_min": 30}
}

func TestTrivySettings(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	useFakeTrivy(t, s, []byte(`{}`))
	adm := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	get := func() trivySettings {
		return decode[trivySettings](t, do(t, s, "GET", "/api/v1/admin/trivy", nil, adm))
	}
	// a value stored before the options existed has only scanners: everything else is the default
	if err := s.putSetting(ctx, "trivy", map[string]any{"scanners": []string{"vuln"}}); err != nil {
		t.Fatal(err)
	}
	def := trivySettings{Scanners: []string{"vuln"}, Severities: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
		PkgTypes: []string{"os", "library"}, DetectionPriority: "precise", SkipDirs: []string{}, SkipFiles: []string{}}
	rec := do(t, s, "GET", "/api/v1/admin/trivy", nil, adm)
	if got := decode[trivySettings](t, rec); !reflect.DeepEqual(got, def) {
		t.Fatalf("old stored value: %+v", got)
	}
	if b := rec.Body.String(); !strings.Contains(b, `"skip_dirs":[]`) || !strings.Contains(b, `"default_timeout_min":15`) {
		t.Fatalf("status body: %s", b)
	}
	// severities and pkg_types come back in Trivy's order whatever order they were sent in
	in := fullTrivyOptions()
	in["severities"] = []string{"HIGH", "CRITICAL"}
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", in, adm), 200, "put all options")
	full := trivySettings{Scanners: []string{"vuln", "misconfig"}, IgnoreUnfixed: true, Severities: []string{"CRITICAL", "HIGH"},
		PkgTypes: []string{"library"}, IncludeDevDeps: true, DetectionPriority: "comprehensive",
		SkipDirs: []string{"-rf", "node_modules"}, SkipFiles: []string{"**/*.min.js"}, TimeoutMin: 30}
	if got := get(); !reflect.DeepEqual(got, full) {
		t.Fatalf("after put: %+v", got)
	}
	// a field the request leaves out keeps its stored value, as the other settings do
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", map[string]any{"ignore_unfixed": false, "timeout_min": 0}, adm), 200, "partial put")
	full.IgnoreUnfixed, full.TimeoutMin = false, 0
	if got := get(); !reflect.DeepEqual(got, full) {
		t.Fatalf("after partial put: %+v", got)
	}
	long := strings.Repeat("가", 200)
	fifty := slices.Repeat([]string{"x"}, 50)
	for i := range fifty {
		fifty[i] = "dir" + itoa(int64(i))
	}
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", map[string]any{"skip_dirs": fifty, "skip_files": []string{long}, "timeout_min": 240,
		"severities": []string{}, "pkg_types": []string{}}, adm), 200, "limits")
	if got := get(); len(got.SkipDirs) != 50 || got.SkipFiles[0] != long || got.TimeoutMin != 240 || len(got.Severities) != 5 || len(got.PkgTypes) != 2 {
		t.Fatalf("limits: %+v", got)
	}
	before := get()
	for name, bad := range map[string]map[string]any{
		"unknown severity":     {"severities": []string{"HIGH", "BOGUS"}},
		"lower-case severity":  {"severities": []string{"high"}},
		"severity twice":       {"severities": []string{"HIGH", "HIGH"}},
		"unknown pkg type":     {"pkg_types": []string{"os", "jar"}},
		"pkg type twice":       {"pkg_types": []string{"os", "os"}},
		"unknown priority":     {"detection_priority": "fast"},
		"51 dirs":              {"skip_dirs": append(slices.Clone(fifty), "one-more")},
		"51 files":             {"skip_files": append(slices.Clone(fifty), "one-more")},
		"empty pattern":        {"skip_files": []string{""}},
		"201 chars":            {"skip_dirs": []string{long + "가"}},
		"newline in a pattern": {"skip_dirs": []string{"a\nb"}},
		"NUL in a pattern":     {"skip_files": []string{"a\x00b"}},
		"tab in a pattern":     {"skip_files": []string{"a\tb"}},
		"DEL in a pattern":     {"skip_files": []string{"a\x7fb"}},
		"negative timeout":     {"timeout_min": -1},
		"timeout over 240":     {"timeout_min": 241},
		"no scanner":           {"scanners": []string{}},
		"unknown scanner":      {"scanners": []string{"vuln", "license"}},
		"unknown field":        {"skip_dir": []string{"x"}},
	} {
		if rec := do(t, s, "PUT", "/api/v1/admin/trivy", bad, adm); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if got := get(); !reflect.DeepEqual(got, before) {
		t.Fatalf("a refused PUT changed the setting: %+v", got)
	}
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", fullTrivyOptions(), loginAs(t, s, mkUser(t, s, "sec", "security"))), 403, "security")
	var details string
	if err := s.db.QueryRow(ctx, `select details::text from audit_log where action='trivy.settings' order by id limit 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scanners", "ignore_unfixed", "severities", "pkg_types", "include_dev_deps", "detection_priority", "skip_dirs", "skip_files", "timeout_min"} {
		if !strings.Contains(details, `"`+k+`"`) {
			t.Errorf("audit details lack %s: %s", k, details)
		}
	}
	if auditCount(t, s, "trivy.settings") != 3 {
		t.Fatalf("settings audits: %d", auditCount(t, s, "trivy.settings"))
	}
}

// The admin's options reach every server-side Trivy run: file scans, a CycloneDX upload and the recheck. A filter
// that the recheck did not get would let it add back what the scan left out.
func TestTrivyOptionsReachEveryRun(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	_, ck := memberSession(t, s)
	fakeTrivyDB(t, s)
	useFakeTrivy(t, s, sbomStyle(t, readFixture(t, "trivy/fs-mixed.json")))
	argsPath := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKETRIVY_ARGS", argsPath)
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/trivy", fullTrivyOptions(), loginAs(t, s, mkUser(t, s, "adm", "admin"))), 200, "put options")
	everywhere := []string{"--ignore-unfixed", "--severity=CRITICAL,HIGH", "--pkg-types=library", "--detection-priority=comprehensive", "--timeout=31m0s"}
	files := []string{"--skip-dirs=-rf", "--skip-dirs=node_modules", "--skip-files=**/*.min.js", "--skip-files=**/*.jar"}
	check := func(what, kind string, want, not []string) {
		t.Helper()
		b, _ := os.ReadFile(argsPath)
		a := strings.Split(string(b), "\n")
		if a[0] != kind {
			t.Fatalf("%s: ran %q, want %s", what, a[0], kind)
		}
		for _, w := range want {
			if !slices.Contains(a, w) {
				t.Errorf("%s: no %s in %v", what, w, a)
			}
		}
		for _, e := range a {
			for _, n := range not {
				if e == n || strings.HasPrefix(e, n+"=") { // n is a flag name, or one exact --flag=value
					t.Errorf("%s: has %s", what, e)
				}
			}
		}
		os.Remove(argsPath)
	}
	run := func() {
		t.Helper()
		if ran, err := s.runNextJob(ctx); !ran || err != nil {
			t.Fatalf("run: %v %v", ran, err)
		}
	}
	mustScanJob(t, s, ck, "web-src", "fs", mkZip(t, arEnt{name: "package-lock.json", body: "{}"}))
	run()
	check("fs scan", "fs", append(slices.Concat(everywhere, files), "--include-dev-deps", "--scanners"), nil)
	mustScanJob(t, s, ck, "app", "image", mkTarGz(t, false, arEnt{name: "manifest.json", body: "[]"}))
	run()
	check("image scan", "image", slices.Concat(everywhere, files), []string{"--include-dev-deps"})
	sbomOnly := []string{"--skip-dirs", "--skip-files", "--include-dev-deps", "--skip-check-update"} // trivy sbom rejects these
	mustUpload(t, s, "web", "", readFixture(t, "cyclonedx/image.json"), ck)
	check("CycloneDX upload", "sbom", everywhere, sbomOnly)
	if _, err := s.startRecheck(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	run()
	check("recheck", "sbom", everywhere, sbomOnly)

	// only scanners stored (before the options existed): no option flag, the time limit from the config (15 minutes)
	if err := s.putSetting(ctx, "trivy", map[string]any{"scanners": []string{"vuln", "secret"}}); err != nil {
		t.Fatal(err)
	}
	mustScanJob(t, s, ck, "web-src", "fs", mkZip(t, arEnt{name: "package-lock.json", body: "{ }"}))
	run()
	check("defaults", "fs", []string{"--timeout=16m0s", "--skip-files=**/*.jar"}, []string{"--ignore-unfixed", "--severity", "--pkg-types", "--detection-priority", "--skip-dirs", "--skip-files=**/*.min.js", "--include-dev-deps"})
}

func TestWorkDirCleanup(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	keep := mustScanJob(t, s, ck, "keep", "fs", mkZip(t, arEnt{name: "a.txt", body: "x"}))
	root := filepath.Join(s.cfg.DataDir, "work")
	junk := []string{filepath.Join(root, "incoming-123"), filepath.Join(root, "trivydb-1.tar.gz"), filepath.Join(root, "recheck-1-2.json"),
		filepath.Join(root, "99999"), filepath.Join(s.trivyCacheDir(), ".incoming-ab")}
	for _, j := range junk {
		os.MkdirAll(filepath.Dir(j), 0o755)
		if err := os.WriteFile(j, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s.sweepWork(context.Background())
	for _, j := range junk {
		if !gone(j) {
			t.Errorf("%s not swept", j)
		}
	}
	if gone(s.workDir(keep)) {
		t.Fatal("a queued scan's upload was swept")
	}
	// deleting the project removes its queued scans' uploads
	owner := loginAs(t, s, mkUser(t, s, "own", "admin"))
	wantCode(t, do(t, s, "DELETE", "/api/v1/projects/web", nil, owner), 204, "delete project")
	if !gone(s.workDir(keep)) {
		t.Fatal("a deleted project's upload stayed on disk")
	}
}

// A server scan that took the process down three times (OOM kill) is failed instead of re-queued forever.
func TestCrashingScanIsNotRequeuedForever(t *testing.T) {
	s := testServer(t)
	_, ck := memberSession(t, s)
	useFakeTrivy(t, s, readFixture(t, "trivy/fs-mixed.json"))
	t.Setenv("FAKETRIVY_WAIT_CALL", "1") // a re-run would hang here instead of failing on its own
	t.Setenv("FAKETRIVY_WAIT_FILE", filepath.Join(t.TempDir(), "never"))
	id := mustScanJob(t, s, ck, "big", "image", []byte("x"))
	sqlExec(t, s, `update jobs set state='running', attempts=3 where scan_id=$1`, id)
	sqlExec(t, s, `update scans set status='running' where id=$1`, id)
	stop := startJobs(t, s)
	waitFor(t, "job failed", func() bool { return jobState(t, s, id) == "failed" })
	stop()
	if st, msg := scanStatus(t, s, id); st != "failed" || msg == "" {
		t.Fatalf("scan %s %q", st, msg)
	}
}
